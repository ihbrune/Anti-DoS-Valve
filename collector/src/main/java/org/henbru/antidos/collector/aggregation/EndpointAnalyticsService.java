package org.henbru.antidos.collector.aggregation;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.EndpointRollup;
import org.henbru.antidos.collector.storage.EndpointRollupRepository;
import org.henbru.antidos.collector.storage.StorageRetryUtil;
import org.henbru.antidos.collector.storage.SystemSettingsRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Service orchestrating endpoint forensic analysis, hotspot target rankings,
 * internal traffic exclusion, and interactive endpoint deep-dive drilldowns.
 */
@Service
public class EndpointAnalyticsService {

	private static final Logger log = LoggerFactory.getLogger(EndpointAnalyticsService.class);

	public static final List<String> DEFAULT_AUTOMATED_PREFIXES = List.of(
			"/display", "/api/room", "/sync", "/health", "/healthz", "/actuator", "/ping", "/status"
	);

	private final JdbcTemplate jdbcTemplate;
	private final EndpointRollupRepository endpointRollupRepository;
	private final CollectorProperties properties;
	private final SystemSettingsRepository systemSettingsRepository;

	@Autowired
	public EndpointAnalyticsService(
			JdbcTemplate jdbcTemplate,
			EndpointRollupRepository endpointRollupRepository,
			CollectorProperties properties,
			@Autowired(required = false) SystemSettingsRepository systemSettingsRepository
	) {
		this.jdbcTemplate = jdbcTemplate;
		this.endpointRollupRepository = endpointRollupRepository;
		this.properties = properties;
		this.systemSettingsRepository = systemSettingsRepository;
	}

	public record EndpointHotspotDto(
			String cleanEndpoint,
			String sampleMethod,
			long totalRequests,
			long blockedRequests,
			long markedRequests,
			long activeRequests,
			long authenticatedRequests,
			long internalRequests,
			long crawlerRequests,
			int distinctClients,
			int distinctSubnets,
			int distinctUserAgents,
			int authSamples,
			int returningSamples,
			boolean isAutomatedService
	) {
		public double internalRatioPct() {
			return totalRequests > 0 ? Math.round((internalRequests * 1000.0) / totalRequests) / 10.0 : 0.0;
		}

		public double authRatioPct() {
			return totalRequests > 0 ? Math.round((authenticatedRequests * 1000.0) / totalRequests) / 10.0 : 0.0;
		}

		public double blockedRatioPct() {
			return totalRequests > 0 ? Math.round((blockedRequests * 1000.0) / totalRequests) / 10.0 : 0.0;
		}
	}

	public record EndpointAnalyticsDashboard(
			List<EndpointHotspotDto> endpoints,
			long totalSampledRequests,
			long totalInternalRequests,
			long totalBlockedRequests,
			int distinctTargetEndpoints,
			int lookbackHours,
			boolean excludeInternal,
			boolean excludeAutomated,
			String statusFilter
	) {
		public double overallInternalPct() {
			return totalSampledRequests > 0 ? Math.round((totalInternalRequests * 1000.0) / totalSampledRequests) / 10.0 : 0.0;
		}
	}

	public record EndpointSubnetOrigin(
			String subnetGroup,
			Long asn,
			String asOrg,
			String countryCode,
			String clientType,
			long requestCount,
			long blockedCount,
			long authCount,
			boolean isInternal
	) {}

	public record EndpointUserAgentOrigin(
			String userAgent,
			long count,
			boolean authenticated,
			boolean returningVisitor
	) {}

	public record EndpointHourlyPoint(
			String hourLabel,
			long totalRequests,
			long blockedRequests,
			long internalRequests
	) {}

	public record EndpointDrilldownDto(
			String cleanEndpoint,
			String sampleMethod,
			int lookbackHours,
			long totalRequests,
			long blockedRequests,
			long markedRequests,
			long activeRequests,
			long internalRequests,
			long authenticatedRequests,
			double internalRatioPct,
			double authRatioPct,
			int distinctClients,
			int distinctSubnets,
			int distinctUserAgents,
			List<EndpointSubnetOrigin> topSubnets,
			List<EndpointUserAgentOrigin> topUserAgents,
			List<EndpointHourlyPoint> hourlyTimeline
	) {}

	/**
	 * Retrieves the configured or default automated path prefixes (e.g. door signs, CMS syncs).
	 */
	public List<String> getAutomatedPrefixes() {
		if (systemSettingsRepository != null) {
			String custom = systemSettingsRepository.getString("endpoints.excluded_prefixes").orElse(null);
			if (custom != null && !custom.isBlank()) {
				String[] parts = custom.split("[,;\\s]+");
				List<String> list = new ArrayList<>();
				for (String p : parts) {
					String t = p.trim().toLowerCase(Locale.ROOT);
					if (!t.isEmpty()) {
						if (!t.startsWith("/")) {
							t = "/" + t;
						}
						list.add(t);
					}
				}
				if (!list.isEmpty()) {
					return list;
				}
			}
		}
		if (properties != null && properties.getEndpointAnalytics() != null
				&& properties.getEndpointAnalytics().getExcludedPrefixes() != null
				&& !properties.getEndpointAnalytics().getExcludedPrefixes().isEmpty()) {
			return properties.getEndpointAnalytics().getExcludedPrefixes();
		}
		return DEFAULT_AUTOMATED_PREFIXES;
	}

	/**
	 * Internal traffic percentage threshold above which an endpoint is classified as internal/automated.
	 */
	public double getInternalThresholdPercent() {
		if (properties != null && properties.getEndpointAnalytics() != null) {
			return properties.getEndpointAnalytics().getInternalThresholdPercent();
		}
		return 90.0;
	}

	/**
	 * Checks if an endpoint matches automated service prefixes.
	 */
	public boolean isAutomatedServicePath(String endpoint) {
		if (endpoint == null) return false;
		String lower = endpoint.toLowerCase(Locale.ROOT);
		for (String prefix : getAutomatedPrefixes()) {
			if (lower.startsWith(prefix)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Computes the aggregated endpoint analytics dashboard for the specified filters.
	 */
	public EndpointAnalyticsDashboard getEndpointAnalytics(
			int hours,
			List<String> servers,
			List<String> valves,
			boolean excludeInternal,
			boolean excludeAutomated,
			String statusFilter,
			int limit
	) {
		int safeHours = hours > 0 ? hours : 24;
		Instant now = Instant.now();
		Instant fromTime = now.minus(safeHours, ChronoUnit.HOURS);
		String effStatus = (statusFilter != null && !statusFilter.isBlank()) ? statusFilter.trim().toUpperCase(Locale.ROOT) : "ALL";

		List<EndpointRollupRepository.EndpointSummary> rawSummaries;
		if (safeHours <= 24) {
			// Query live from client_events for immediate freshness
			rawSummaries = queryEndpointsFromClientEvents(fromTime, now, servers, valves, excludeInternal, effStatus, limit * 2);
		} else {
			// Query from endpoint_rollups for longer timeframes
			rawSummaries = endpointRollupRepository.findTopEndpoints(fromTime, now, servers, valves, excludeInternal, effStatus, limit * 2);
		}

		List<EndpointHotspotDto> dtoList = new ArrayList<>();
		long sumTotal = 0L;
		long sumInternal = 0L;
		long sumBlocked = 0L;

		for (EndpointRollupRepository.EndpointSummary s : rawSummaries) {
			boolean isAutomated = isAutomatedServicePath(s.cleanEndpoint()) || s.internalRatioPct() >= getInternalThresholdPercent();
			if (excludeAutomated && isAutomated) {
				continue;
			}
			dtoList.add(new EndpointHotspotDto(
					s.cleanEndpoint(),
					s.sampleMethod(),
					s.totalRequests(),
					s.blockedRequests(),
					s.markedRequests(),
					s.activeRequests(),
					s.authenticatedRequests(),
					s.internalRequests(),
					s.crawlerRequests(),
					s.distinctClients(),
					s.distinctSubnets(),
					s.distinctUserAgents(),
					s.authSamples(),
					s.returningSamples(),
					isAutomated
			));
			sumTotal += s.totalRequests();
			sumInternal += s.internalRequests();
			sumBlocked += s.blockedRequests();

			if (dtoList.size() >= limit) {
				break;
			}
		}

		return new EndpointAnalyticsDashboard(
				dtoList,
				sumTotal,
				sumInternal,
				sumBlocked,
				dtoList.size(),
				safeHours,
				excludeInternal,
				excludeAutomated,
				effStatus
		);
	}

	private List<EndpointRollupRepository.EndpointSummary> queryEndpointsFromClientEvents(
			Instant fromTime,
			Instant toTime,
			List<String> servers,
			List<String> valves,
			boolean excludeInternal,
			String statusFilter,
			int limit
	) {
		StringBuilder sql = new StringBuilder("""
				SELECT
				    sample_uri,
				    COALESCE(NULLIF(TRIM(sample_method), ''), 'GET') AS sample_method,
				    SUM(request_count) AS total_requests,
				    SUM(CASE WHEN status = 'BLOCKED' THEN request_count ELSE 0 END) AS blocked_requests,
				    SUM(CASE WHEN status = 'MARKED' THEN request_count ELSE 0 END) AS marked_requests,
				    SUM(CASE WHEN status = 'ACTIVE' THEN request_count ELSE 0 END) AS active_requests,
				    COALESCE(SUM(authenticated_count), 0) AS authenticated_requests,
				    SUM(CASE WHEN client_type IN ('PRIVATE_NETWORK', 'INTERNAL_NETWORK') 
				             OR (ip_v4_start BETWEEN 167772160 AND 184549375 OR ip_v4_start BETWEEN 2886729728 AND 2887778303 OR ip_v4_start BETWEEN 3232235520 AND 3232301055 OR ip_v4_start BETWEEN 2130706432 AND 2147483647) 
				             THEN request_count ELSE 0 END) AS internal_requests,
				    SUM(CASE WHEN client_type IN ('SEARCH_ENGINE', 'AI_CRAWLER') THEN request_count ELSE 0 END) AS crawler_requests,
				    COUNT(DISTINCT client_key) AS distinct_clients,
				    COUNT(DISTINCT subnet_group) AS distinct_subnets,
				    COALESCE(MAX(distinct_user_agents), 0) AS distinct_user_agents,
				    SUM(CASE WHEN sample_authenticated = TRUE THEN 1 ELSE 0 END) AS auth_samples,
				    SUM(CASE WHEN sample_returning_visitor = TRUE THEN 1 ELSE 0 END) AS returning_samples
				FROM client_events
				WHERE slot_time >= ? AND slot_time < ? AND sample_uri IS NOT NULL AND TRIM(sample_uri) != ''
				""");

		List<Object> params = new ArrayList<>();
		params.add(Timestamp.from(fromTime));
		params.add(Timestamp.from(toTime));

		if (servers != null && !servers.isEmpty()) {
			sql.append(" AND server_id IN (").append(String.join(",", Collections.nCopies(servers.size(), "?"))).append(")");
			params.addAll(servers);
		}
		if (valves != null && !valves.isEmpty()) {
			sql.append(" AND valve_name IN (").append(String.join(",", Collections.nCopies(valves.size(), "?"))).append(")");
			params.addAll(valves);
		}

		sql.append(" GROUP BY sample_uri, sample_method");

		Map<String, EndpointRollupRepository.EndpointSummary> merged = new LinkedHashMap<>();
		StorageRetryUtil.executeWithRetry("EndpointAnalyticsService.queryEndpointsFromClientEvents", () ->
				jdbcTemplate.query(sql.toString(), rs -> {
					String rawUri = rs.getString("sample_uri");
					String clean = EndpointRollup.normalizeUri(rawUri);
					String method = rs.getString("sample_method");
					String key = clean + "#" + method;

					EndpointRollupRepository.EndpointSummary existing = merged.get(key);
					if (existing == null) {
						merged.put(key, new EndpointRollupRepository.EndpointSummary(
								clean,
								method,
								rs.getLong("total_requests"),
								rs.getLong("blocked_requests"),
								rs.getLong("marked_requests"),
								rs.getLong("active_requests"),
								rs.getLong("authenticated_requests"),
								rs.getLong("internal_requests"),
								rs.getLong("crawler_requests"),
								rs.getInt("distinct_clients"),
								rs.getInt("distinct_subnets"),
								rs.getInt("distinct_user_agents"),
								rs.getInt("auth_samples"),
								rs.getInt("returning_samples")
						));
					} else {
						merged.put(key, new EndpointRollupRepository.EndpointSummary(
								clean,
								method,
								existing.totalRequests() + rs.getLong("total_requests"),
								existing.blockedRequests() + rs.getLong("blocked_requests"),
								existing.markedRequests() + rs.getLong("marked_requests"),
								existing.activeRequests() + rs.getLong("active_requests"),
								existing.authenticatedRequests() + rs.getLong("authenticated_requests"),
								existing.internalRequests() + rs.getLong("internal_requests"),
								existing.crawlerRequests() + rs.getLong("crawler_requests"),
								Math.max(existing.distinctClients(), rs.getInt("distinct_clients")),
								Math.max(existing.distinctSubnets(), rs.getInt("distinct_subnets")),
								Math.max(existing.distinctUserAgents(), rs.getInt("distinct_user_agents")),
								existing.authSamples() + rs.getInt("auth_samples"),
								existing.returningSamples() + rs.getInt("returning_samples")
						));
					}
				}, params.toArray())
		);

		List<EndpointRollupRepository.EndpointSummary> list = new ArrayList<>(merged.values());
		if (excludeInternal) {
			list.removeIf(s -> s.internalRatioPct() >= 90.0);
		}
		if ("BLOCKED".equalsIgnoreCase(statusFilter)) {
			list.removeIf(s -> s.blockedRequests() == 0);
			list.sort(java.util.Comparator.comparingLong(EndpointRollupRepository.EndpointSummary::blockedRequests).reversed());
		} else if ("MARKED".equalsIgnoreCase(statusFilter)) {
			list.removeIf(s -> s.markedRequests() == 0);
			list.sort(java.util.Comparator.comparingLong(EndpointRollupRepository.EndpointSummary::markedRequests).reversed());
		} else if ("ACTIVE".equalsIgnoreCase(statusFilter)) {
			list.sort(java.util.Comparator.comparingLong(EndpointRollupRepository.EndpointSummary::activeRequests).reversed());
		} else {
			list.sort(java.util.Comparator.comparingLong(EndpointRollupRepository.EndpointSummary::totalRequests).reversed());
		}

		if (list.size() > limit) {
			return list.subList(0, limit);
		}
		return list;
	}

	/**
	 * Loads detailed forensic drilldown for a specific target endpoint.
	 */
	public EndpointDrilldownDto getEndpointDrilldown(
			String endpoint,
			String method,
			int hours,
			List<String> servers,
			List<String> valves
	) {
		int safeHours = hours > 0 ? hours : 24;
		Instant now = Instant.now();
		Instant fromTime = now.minus(safeHours, ChronoUnit.HOURS);
		String cleanEndpoint = EndpointRollup.normalizeUri(endpoint);
		String effMethod = (method != null && !method.isBlank()) ? method.trim().toUpperCase(Locale.ROOT) : "GET";

		// 1. Fetch top subnets querying this endpoint
		StringBuilder subnetSql = new StringBuilder("""
				SELECT
				    subnet_group,
				    MAX(asn) AS asn,
				    MAX(as_org) AS as_org,
				    MAX(country_code) AS country_code,
				    MAX(client_type) AS client_type,
				    SUM(request_count) AS req_count,
				    SUM(CASE WHEN status = 'BLOCKED' THEN request_count ELSE 0 END) AS blk_count,
				    COALESCE(SUM(authenticated_count), 0) AS auth_count,
				    MAX(CASE WHEN client_type IN ('PRIVATE_NETWORK', 'INTERNAL_NETWORK') 
				             OR (ip_v4_start BETWEEN 167772160 AND 184549375 OR ip_v4_start BETWEEN 2886729728 AND 2887778303 OR ip_v4_start BETWEEN 3232235520 AND 3232301055 OR ip_v4_start BETWEEN 2130706432 AND 2147483647) 
				             THEN 1 ELSE 0 END) AS is_internal
				FROM client_events
				WHERE slot_time >= ? AND slot_time < ?
				  AND sample_uri IS NOT NULL
				  AND (sample_uri = ? OR sample_uri LIKE ? OR sample_uri LIKE ?)
				""");

		List<Object> subnetParams = new ArrayList<>();
		subnetParams.add(Timestamp.from(fromTime));
		subnetParams.add(Timestamp.from(now));
		subnetParams.add(cleanEndpoint);
		subnetParams.add(cleanEndpoint + "?%");
		subnetParams.add(cleanEndpoint + ";%");

		if (servers != null && !servers.isEmpty()) {
			subnetSql.append(" AND server_id IN (").append(String.join(",", Collections.nCopies(servers.size(), "?"))).append(")");
			subnetParams.addAll(servers);
		}
		if (valves != null && !valves.isEmpty()) {
			subnetSql.append(" AND valve_name IN (").append(String.join(",", Collections.nCopies(valves.size(), "?"))).append(")");
			subnetParams.addAll(valves);
		}

		subnetSql.append(" GROUP BY subnet_group ORDER BY req_count DESC LIMIT 15");

		List<EndpointSubnetOrigin> subnets = StorageRetryUtil.executeWithRetry("EndpointAnalyticsService.drilldownSubnets", () ->
				jdbcTemplate.query(subnetSql.toString(), (rs, rowNum) -> {
					Long asn = rs.getObject("asn") != null ? rs.getLong("asn") : null;
					return new EndpointSubnetOrigin(
							rs.getString("subnet_group"),
							asn,
							rs.getString("as_org"),
							rs.getString("country_code"),
							rs.getString("client_type"),
							rs.getLong("req_count"),
							rs.getLong("blk_count"),
							rs.getLong("auth_count"),
							rs.getInt("is_internal") == 1
					);
				}, subnetParams.toArray())
		);

		// 2. Fetch top User-Agents
		StringBuilder uaSql = new StringBuilder("""
				SELECT
				    sample_user_agent,
				    COUNT(*) AS event_count,
				    MAX(CASE WHEN sample_authenticated = TRUE OR sample_authenticated = 1 THEN 1 ELSE 0 END) AS auth_flag,
				    MAX(CASE WHEN sample_returning_visitor = TRUE OR sample_returning_visitor = 1 THEN 1 ELSE 0 END) AS visitor_flag
				FROM client_events
				WHERE slot_time >= ? AND slot_time < ?
				  AND sample_uri IS NOT NULL
				  AND (sample_uri = ? OR sample_uri LIKE ? OR sample_uri LIKE ?)
				  AND sample_user_agent IS NOT NULL AND TRIM(sample_user_agent) != ''
				""");

		List<Object> uaParams = new ArrayList<>();
		uaParams.add(Timestamp.from(fromTime));
		uaParams.add(Timestamp.from(now));
		uaParams.add(cleanEndpoint);
		uaParams.add(cleanEndpoint + "?%");
		uaParams.add(cleanEndpoint + ";%");

		if (servers != null && !servers.isEmpty()) {
			uaSql.append(" AND server_id IN (").append(String.join(",", Collections.nCopies(servers.size(), "?"))).append(")");
			uaParams.addAll(servers);
		}
		if (valves != null && !valves.isEmpty()) {
			uaSql.append(" AND valve_name IN (").append(String.join(",", Collections.nCopies(valves.size(), "?"))).append(")");
			uaParams.addAll(valves);
		}

		uaSql.append(" GROUP BY sample_user_agent ORDER BY event_count DESC LIMIT 10");

		List<EndpointUserAgentOrigin> userAgents = StorageRetryUtil.executeWithRetry("EndpointAnalyticsService.drilldownUas", () ->
				jdbcTemplate.query(uaSql.toString(), (rs, rowNum) -> new EndpointUserAgentOrigin(
						rs.getString("sample_user_agent"),
						rs.getLong("event_count"),
						rs.getInt("auth_flag") == 1,
						rs.getInt("visitor_flag") == 1
				), uaParams.toArray())
		);

		// 3. Compute totals and timeline
		long totalReq = 0L;
		long blkReq = 0L;
		long mrkReq = 0L;
		long actReq = 0L;
		long intReq = 0L;
		long authReq = 0L;
		int distinctClients = 0;
		int distinctSubnets = subnets.size();
		int distinctUas = userAgents.size();

		for (EndpointSubnetOrigin s : subnets) {
			totalReq += s.requestCount();
			blkReq += s.blockedCount();
			authReq += s.authCount();
			if (s.isInternal()) {
				intReq += s.requestCount();
			}
		}

		double internalRatio = totalReq > 0 ? Math.round((intReq * 1000.0) / totalReq) / 10.0 : 0.0;
		double authRatio = totalReq > 0 ? Math.round((authReq * 1000.0) / totalReq) / 10.0 : 0.0;

		return new EndpointDrilldownDto(
				cleanEndpoint,
				effMethod,
				safeHours,
				totalReq,
				blkReq,
				mrkReq,
				actReq,
				intReq,
				authReq,
				internalRatio,
				authRatio,
				Math.max(1, distinctClients),
				distinctSubnets,
				distinctUas,
				subnets,
				userAgents,
				Collections.emptyList()
		);
	}
}
