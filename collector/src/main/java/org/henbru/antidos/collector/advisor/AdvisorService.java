package org.henbru.antidos.collector.advisor;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Service evaluating fleet telemetry and incident data against expert operational rules
 * to detect rate-limiting false positives, search engine collateral damage, unwhitelisted
 * internal subnets, and opportunities for edge defense offloading.
 */
@Service
public class AdvisorService {

	private static final Logger log = LoggerFactory.getLogger(AdvisorService.class);

	private final JdbcTemplate jdbcTemplate;
	private final MonitoredValveRepository monitoredValveRepository;

	@Autowired
	public AdvisorService(
			JdbcTemplate jdbcTemplate,
			@Autowired(required = false) MonitoredValveRepository monitoredValveRepository) {
		this.jdbcTemplate = jdbcTemplate;
		this.monitoredValveRepository = monitoredValveRepository;
	}

	public AdvisorReport generateReport(int hours, List<String> servers, List<String> valves) {
		int safeHours = hours > 0 ? hours : 24;
		Instant cutoff = Instant.now().minus(safeHours, ChronoUnit.HOURS);
		Timestamp cutoffTs = Timestamp.from(cutoff);

		List<AdvisorFinding> findings = new ArrayList<>();
		Set<String> recommendedSubnets = new LinkedHashSet<>();

		try {
			// 1. Evaluate Authenticated User Collateral Blocks (Critical False Positives)
			evaluateBlockedAuthenticatedUsers(cutoffTs, servers, valves, findings);

			// 2. Evaluate Search Engine Collateral Blocks (Googlebot, Bingbot, Applebot)
			evaluateSearchEngineCollateral(cutoffTs, servers, valves, findings, recommendedSubnets);

			// 3. Evaluate Internal / Private Infrastructure Blocks (RFC 1918)
			evaluateInternalInfrastructure(cutoffTs, servers, valves, findings, recommendedSubnets);

			// 4. Evaluate High-Returning Residential / NAT Clusters (Potential False Positives)
			evaluateResidentialNatRisks(cutoffTs, servers, valves, findings);

			// 5. Evaluate Massive Datacenter Scraping Waves (Offloading Candidates)
			evaluateDatacenterScraping(cutoffTs, servers, valves, findings);

			// 6. Evaluate Horizontal Stealth Carpet Attacks (Unblocked Distributed Waves)
			evaluateStealthCarpetAttacks(cutoffTs, servers, valves, findings);

			// 7. Evaluate Chameleon User-Agent Rotating Scrapers / Bots
			evaluateChameleonScrapers(cutoffTs, servers, valves, findings);

			// 8. Evaluate Missing Forensic Active Sampling Configuration
			evaluateMissingActiveSampling(servers, valves, findings);
		} catch (Exception e) {
			log.error("Error evaluating advisor diagnostics: {}", e.getMessage(), e);
		}

		// Sort findings by severity: CRITICAL first, then WARNING, then INFO, then by blockedRequests DESC, then totalRequests DESC
		findings.sort((a, b) -> {
			int sevComp = a.severity().compareTo(b.severity());
			if (sevComp != 0) {
				return sevComp;
			}
			int blkComp = Long.compare(b.blockedRequests(), a.blockedRequests());
			if (blkComp != 0) {
				return blkComp;
			}
			return Long.compare(b.totalRequests(), a.totalRequests());
		});

		int criticalCount = 0;
		int warningCount = 0;
		int infoCount = 0;
		for (AdvisorFinding f : findings) {
			switch (f.severity()) {
				case CRITICAL -> criticalCount++;
				case WARNING -> warningCount++;
				case INFO -> infoCount++;
			}
		}

		String consolidatedRegex = buildConsolidatedRegex(recommendedSubnets);
		String consolidatedSnippet = buildConsolidatedServerXmlSnippet(consolidatedRegex);

		return new AdvisorReport(
				Instant.now(),
				safeHours,
				findings,
				criticalCount,
				warningCount,
				infoCount,
				recommendedSubnets,
				consolidatedRegex,
				consolidatedSnippet
		);
	}

	private void evaluateBlockedAuthenticatedUsers(
			Timestamp cutoff,
			List<String> servers,
			List<String> valves,
			List<AdvisorFinding> findings) {

		StringBuilder sql = new StringBuilder("""
				SELECT 
				    r.server_id,
				    r.valve_name,
				    r.subnet_group,
				    COALESCE(r.as_org, 'Authenticated Clients') AS entity_name,
				    COALESCE(r.country_code, 'XX') AS country_code,
				    r.client_type,
				    SUM(r.total_requests) AS total_req,
				    SUM(r.blocked_requests) AS blocked_req,
				    SUM(r.authenticated_requests) AS auth_req,
				    MAX(r.max_requests_per_client) AS peak_req
				FROM client_subnet_rollups r
				WHERE r.authenticated_requests > 0
				  AND r.blocked_requests > 0
				  AND r.bucket_start >= ?
				""");

		List<Object> params = new ArrayList<>();
		params.add(cutoff);
		appendFilterClauses(sql, params, servers, valves);
		sql.append(" GROUP BY r.server_id, r.valve_name, r.subnet_group, r.as_org, r.country_code, r.client_type ORDER BY blocked_req DESC LIMIT 10");

		jdbcTemplate.query(sql.toString(), rs -> {
			String serverId = rs.getString("server_id");
			String valveName = rs.getString("valve_name");
			String subnetGroup = rs.getString("subnet_group");
			String entityName = rs.getString("entity_name");
			String country = rs.getString("country_code");
			ClientType clientType = ClientType.valueOf(rs.getString("client_type"));
			long totalReq = rs.getLong("total_req");
			long blockedReq = rs.getLong("blocked_req");
			long authReq = rs.getLong("auth_req");
			int peakReq = rs.getInt("peak_req");

			double blockPct = totalReq > 0 ? (double) blockedReq / totalReq * 100.0 : 100.0;
			blockPct = Math.round(blockPct * 10.0) / 10.0;

			ValveConfigInfo valveInfo = resolveValveConfig(serverId, valveName);

			String explanation = String.format(
					"Subnet %s (%s, %s) experienced %d blocked requests (%.1f%% of %d total requests) on valve '%s' on node '%s', " +
					"despite carrying valid authentication credentials (%d authenticated requests recorded). " +
					"Blocking verified authenticated users represents a critical false-positive that disrupts legitimate operations or customers.",
					subnetGroup, entityName, country, blockedReq, blockPct, totalReq, valveName, serverId, authReq);

			String recommendation = String.format(
					"To protect authenticated users from aggressive rate limiting:\n" +
					"1) Verify that 'authCookieName' or 'relevantAuthScope' is configured on valve '%s' to grant authenticated requests higher capacity headroom or separate limits.\n" +
					"2) If this subnet belongs to a trusted corporate office, partner API, or VPN gateway, consider whitelisting it in 'alwaysAllowedIPs=\"%s\"'.\n" +
					"3) Increase 'allowedRequestsPerSlot' if users legitimately execute high-frequency automated batch operations.",
					valveName, mergeWithExistingRegex(valveInfo.alwaysAllowedIps, cidrToRegex(subnetGroup)));

			String id = "auth-" + sanitizeId(serverId + "-" + valveName + "-" + subnetGroup);
			String title = String.format("Authenticated Users Blocked in %s (%s)", subnetGroup, entityName);

			findings.add(new AdvisorFinding(
					id,
					AdvisorCategory.AUTHENTICATED_COLLATERAL,
					AdvisorSeverity.CRITICAL,
					title,
					serverId,
					valveName,
					subnetGroup,
					entityName + " (" + country + ")",
					clientType,
					totalReq,
					blockedReq,
					blockPct,
					peakReq,
					valveInfo.allowedRequestsPerSlot,
					valveInfo.slotLength,
					valveInfo.alwaysAllowedIps,
					explanation,
					recommendation,
					null,
					null
			));
		}, params.toArray());
	}

	private void evaluateSearchEngineCollateral(
			Timestamp cutoff,
			List<String> servers,
			List<String> valves,
			List<AdvisorFinding> findings,
			Set<String> recommendedSubnets) {

		StringBuilder sql = new StringBuilder("""
				SELECT 
				    r.server_id,
				    r.valve_name,
				    r.subnet_group,
				    COALESCE(r.as_org, 'Search Engine Crawler') AS entity_name,
				    r.client_type,
				    SUM(r.total_requests) AS total_req,
				    SUM(r.blocked_requests) AS blocked_req,
				    MAX(r.max_requests_per_client) AS peak_req
				FROM client_subnet_rollups r
				WHERE r.client_type = 'SEARCH_ENGINE'
				  AND r.blocked_requests > 0
				  AND r.bucket_start >= ?
				""");

		List<Object> params = new ArrayList<>();
		params.add(cutoff);
		appendFilterClauses(sql, params, servers, valves);
		sql.append(" GROUP BY r.server_id, r.valve_name, r.subnet_group, r.as_org, r.client_type ORDER BY blocked_req DESC LIMIT 20");

		jdbcTemplate.query(sql.toString(), rs -> {
			String serverId = rs.getString("server_id");
			String valveName = rs.getString("valve_name");
			String subnetGroup = rs.getString("subnet_group");
			String entityName = rs.getString("entity_name");
			ClientType clientType = ClientType.valueOf(rs.getString("client_type"));
			long totalReq = rs.getLong("total_req");
			long blockedReq = rs.getLong("blocked_req");
			int peakReq = rs.getInt("peak_req");

			double blockPct = totalReq > 0 ? (double) blockedReq / totalReq * 100.0 : 100.0;
			blockPct = Math.round(blockPct * 10.0) / 10.0;

			ValveConfigInfo valveInfo = resolveValveConfig(serverId, valveName);
			String subnetRegex = cidrToRegex(subnetGroup);
			recommendedSubnets.add(subnetGroup);

			String suggestedRegex = mergeWithExistingRegex(valveInfo.alwaysAllowedIps, subnetRegex);
			String suggestedXml = String.format("""
					<!-- Update Valve '%s' in server.xml on %s to exempt verified search engine crawlers: -->
					<Valve className="org.henbru.antidos.AntiDoSValve"
					       monitorName="%s"
					       alwaysAllowedIPs="%s" />""",
					valveName, serverId, valveName, suggestedRegex);

			String explanation = String.format(
					"Verified search engine crawler '%s' in subnet %s was blocked %d times (%.1f%% of %d requests) by valve '%s' on node '%s'. " +
					"The crawler generated up to %d requests per client in a single slot, exceeding the configured limit of %s req / %ss.",
					entityName, subnetGroup, blockedReq, blockPct, totalReq, valveName, serverId,
					peakReq, formatLimit(valveInfo.allowedRequestsPerSlot), formatSlotLength(valveInfo.slotLength));

			String recommendation = String.format(
					"Search engine crawlers should not be rate-limited by strict human-oriented thresholds, as dropped requests result in HTTP 429 and indexing dropouts. " +
					"Whitelist subnet '%s' by updating 'alwaysAllowedIPs=\"%s\"' on valve '%s', or grant crawler paths higher limits.",
					subnetGroup, suggestedRegex, valveName);

			String id = "se-" + sanitizeId(serverId + "-" + valveName + "-" + subnetGroup);
			String title = String.format("%s Crawlers Blocked by '%s' on %s", entityName, valveName, serverId);

			findings.add(new AdvisorFinding(
					id,
					AdvisorCategory.SEARCH_ENGINE_COLLATERAL,
					AdvisorSeverity.CRITICAL,
					title,
					serverId,
					valveName,
					subnetGroup,
					entityName,
					clientType,
					totalReq,
					blockedReq,
					blockPct,
					peakReq,
					valveInfo.allowedRequestsPerSlot,
					valveInfo.slotLength,
					valveInfo.alwaysAllowedIps,
					explanation,
					recommendation,
					suggestedXml,
					suggestedRegex
			));
		}, params.toArray());
	}

	private void evaluateInternalInfrastructure(
			Timestamp cutoff,
			List<String> servers,
			List<String> valves,
			List<AdvisorFinding> findings,
			Set<String> recommendedSubnets) {

		StringBuilder sql = new StringBuilder("""
				SELECT 
				    r.server_id,
				    r.valve_name,
				    r.subnet_group,
				    COALESCE(r.as_org, 'Private Network (RFC 1918)') AS entity_name,
				    r.client_type,
				    SUM(r.total_requests) AS total_req,
				    SUM(r.blocked_requests) AS blocked_req,
				    MAX(r.max_requests_per_client) AS peak_req
				FROM client_subnet_rollups r
				WHERE r.client_type = 'PRIVATE_NETWORK'
				  AND r.blocked_requests > 0
				  AND r.bucket_start >= ?
				""");

		List<Object> params = new ArrayList<>();
		params.add(cutoff);
		appendFilterClauses(sql, params, servers, valves);
		sql.append(" GROUP BY r.server_id, r.valve_name, r.subnet_group, r.as_org, r.client_type ORDER BY blocked_req DESC LIMIT 20");

		jdbcTemplate.query(sql.toString(), rs -> {
			String serverId = rs.getString("server_id");
			String valveName = rs.getString("valve_name");
			String subnetGroup = rs.getString("subnet_group");
			String entityName = rs.getString("entity_name");
			ClientType clientType = ClientType.valueOf(rs.getString("client_type"));
			long totalReq = rs.getLong("total_req");
			long blockedReq = rs.getLong("blocked_req");
			int peakReq = rs.getInt("peak_req");

			double blockPct = totalReq > 0 ? (double) blockedReq / totalReq * 100.0 : 100.0;
			blockPct = Math.round(blockPct * 10.0) / 10.0;

			ValveConfigInfo valveInfo = resolveValveConfig(serverId, valveName);
			String subnetRegex = cidrToRegex(subnetGroup);
			recommendedSubnets.add(subnetGroup);

			AdvisorSeverity severity = (blockedReq >= 500 || blockPct >= 50.0) ? AdvisorSeverity.CRITICAL : AdvisorSeverity.WARNING;
			String suggestedRegex = mergeWithExistingRegex(valveInfo.alwaysAllowedIps, subnetRegex);
			String suggestedXml = String.format("""
					<!-- Whitelist internal subnet '%s' on Valve '%s' in server.xml on %s: -->
					<Valve className="org.henbru.antidos.AntiDoSValve"
					       monitorName="%s"
					       alwaysAllowedIPs="%s" />""",
					subnetGroup, valveName, serverId, valveName, suggestedRegex);

			String explanation = String.format(
					"Internal infrastructure or intranet clients in subnet %s were blocked %d times (%.1f%%) by valve '%s' on node '%s' (peak %d req/client vs. limit %s). " +
					"This typically happens when internal services/users access public endpoints without whitelisting, or when a reverse proxy / ingress controller IP is evaluated because RemoteIpValve is missing.",
					subnetGroup, blockedReq, blockPct, valveName, serverId, peakReq, formatLimit(valveInfo.allowedRequestsPerSlot));

			String recommendation = String.format(
					"1) If this subnet represents trusted corporate, campus, or service networks: Whitelist the subnet in 'alwaysAllowedIPs=\"%s\"' on valve '%s'.\n" +
					"2) If traffic passes through an internal reverse proxy (Nginx, HAProxy, AWS ALB): Ensure Tomcat's RemoteIpValve is placed before AntiDoSValve with remoteIpHeader=\"x-forwarded-for\" so actual client IPs are seen.",
					suggestedRegex, valveName);

			String id = "priv-" + sanitizeId(serverId + "-" + valveName + "-" + subnetGroup);
			String title = String.format("Internal RFC 1918 Network (%s) Blocked by '%s' on %s", subnetGroup, valveName, serverId);

			findings.add(new AdvisorFinding(
					id,
					AdvisorCategory.INTERNAL_INFRASTRUCTURE,
					severity,
					title,
					serverId,
					valveName,
					subnetGroup,
					entityName,
					clientType,
					totalReq,
					blockedReq,
					blockPct,
					peakReq,
					valveInfo.allowedRequestsPerSlot,
					valveInfo.slotLength,
					valveInfo.alwaysAllowedIps,
					explanation,
					recommendation,
					suggestedXml,
					suggestedRegex
			));
		}, params.toArray());
	}

	private void evaluateResidentialNatRisks(
			Timestamp cutoff,
			List<String> servers,
			List<String> valves,
			List<AdvisorFinding> findings) {

		StringBuilder sql = new StringBuilder("""
				SELECT 
				    r.server_id,
				    r.valve_name,
				    r.subnet_group,
				    COALESCE(r.as_org, 'Residential ISP') AS entity_name,
				    COALESCE(r.country_code, 'XX') AS country_code,
				    r.client_type,
				    SUM(r.total_requests) AS total_req,
				    SUM(r.blocked_requests) AS blocked_req,
				    MAX(r.distinct_clients) AS max_clients,
				    MAX(r.max_requests_per_client) AS peak_req,
				    ROUND(SUM(r.returning_requests) * 100.0 / NULLIF(SUM(r.returning_tracked_requests), 0), 1) AS ret_pct
				FROM client_subnet_rollups r
				WHERE r.client_type IN ('RESIDENTIAL', 'PRIVACY_RELAY', 'UNKNOWN')
				  AND r.blocked_requests >= 50
				  AND r.bucket_start >= ?
				""");

		List<Object> params = new ArrayList<>();
		params.add(cutoff);
		appendFilterClauses(sql, params, servers, valves);
		sql.append(" GROUP BY r.server_id, r.valve_name, r.subnet_group, r.as_org, r.country_code, r.client_type " +
				" HAVING ret_pct >= 75.0 ORDER BY blocked_req DESC LIMIT 10");

		jdbcTemplate.query(sql.toString(), rs -> {
			String serverId = rs.getString("server_id");
			String valveName = rs.getString("valve_name");
			String subnetGroup = rs.getString("subnet_group");
			String entityName = rs.getString("entity_name");
			String country = rs.getString("country_code");
			ClientType clientType = ClientType.valueOf(rs.getString("client_type"));
			long totalReq = rs.getLong("total_req");
			long blockedReq = rs.getLong("blocked_req");
			int maxClients = rs.getInt("max_clients");
			int peakReq = rs.getInt("peak_req");
			double retPct = rs.getDouble("ret_pct");

			double blockPct = totalReq > 0 ? (double) blockedReq / totalReq * 100.0 : 100.0;
			blockPct = Math.round(blockPct * 10.0) / 10.0;

			ValveConfigInfo valveInfo = resolveValveConfig(serverId, valveName);

			String explanation = String.format(
					"Subnet %s (%s, %s) had %d blocked requests (%.1f%%) on valve '%s', despite having a very high returning visitor ratio (%.1f%% returning cookies) and %d distinct client(s). " +
					"This indicates legitimate returning users or a shared Carrier-Grade NAT (CGNAT) / university / corporate network where multiple users share an external IP.",
					subnetGroup, entityName, country, blockedReq, blockPct, valveName, retPct, maxClients);

			String recommendation = String.format(
					"To avoid false-positive lockouts for legitimate returning users:\n" +
					"1) Enable visitor cookie tracking: set visitorCookieEnabled=\"true\" on valve '%s' so returning users receive higher request headroom.\n" +
					"2) If this is an IP-level valve (/32) and users share an IP, consider switching to subnet aggregation (ipv4SubnetMask=\"24\") with increased allowedRequestsPerSlot.",
					valveName);

			String suggestedXml = String.format("""
					<!-- Enable visitor cookie tracking on Valve '%s' in server.xml: -->
					<Valve className="org.henbru.antidos.AntiDoSValve"
					       monitorName="%s"
					       visitorCookieEnabled="true"
					       visitorCookieName="_adv" />""",
					valveName, valveName);

			String id = "nat-" + sanitizeId(serverId + "-" + valveName + "-" + subnetGroup);
			String title = String.format("Potential NAT / Returning User False-Positive (%s, %s)", subnetGroup, entityName);

			findings.add(new AdvisorFinding(
					id,
					AdvisorCategory.RESIDENTIAL_TUNING,
					AdvisorSeverity.WARNING,
					title,
					serverId,
					valveName,
					subnetGroup,
					entityName + " (" + country + ")",
					clientType,
					totalReq,
					blockedReq,
					blockPct,
					peakReq,
					valveInfo.allowedRequestsPerSlot,
					valveInfo.slotLength,
					valveInfo.alwaysAllowedIps,
					explanation,
					recommendation,
					suggestedXml,
					null
			));
		}, params.toArray());
	}

	private void evaluateDatacenterScraping(
			Timestamp cutoff,
			List<String> servers,
			List<String> valves,
			List<AdvisorFinding> findings) {

		StringBuilder sql = new StringBuilder("""
				SELECT 
				    r.server_id,
				    r.valve_name,
				    COALESCE(r.asn, 0) AS asn,
				    COALESCE(r.as_org, 'Datacenter / Cloud') AS entity_name,
				    COUNT(DISTINCT r.subnet_group) AS subnets,
				    SUM(r.total_requests) AS total_req,
				    SUM(r.blocked_requests) AS blocked_req
				FROM client_subnet_rollups r
				WHERE r.client_type = 'DATACENTER'
				  AND r.blocked_requests >= 5000
				  AND r.bucket_start >= ?
				""");

		List<Object> params = new ArrayList<>();
		params.add(cutoff);
		appendFilterClauses(sql, params, servers, valves);
		sql.append(" GROUP BY r.server_id, r.valve_name, r.asn, r.as_org ORDER BY blocked_req DESC LIMIT 5");

		jdbcTemplate.query(sql.toString(), rs -> {
			String serverId = rs.getString("server_id");
			String valveName = rs.getString("valve_name");
			long asn = rs.getLong("asn");
			String entityName = rs.getString("entity_name");
			int subnets = rs.getInt("subnets");
			long totalReq = rs.getLong("total_req");
			long blockedReq = rs.getLong("blocked_req");

			double blockPct = totalReq > 0 ? (double) blockedReq / totalReq * 100.0 : 100.0;
			blockPct = Math.round(blockPct * 10.0) / 10.0;

			ValveConfigInfo valveInfo = resolveValveConfig(serverId, valveName);

			String explanation = String.format(
					"AntiDoSValve successfully blocked %d requests (%.1f%%) originating from %d distinct subnets in %s (ASN %d) on valve '%s'. " +
					"The Valve is actively mitigating this cloud scraping/scanning wave.",
					blockedReq, blockPct, subnets, entityName, asn, valveName);

			String recommendation = String.format(
					"The Anti-DoS Valve is working as intended. However, processing tens of thousands of malicious requests in Tomcat threads consumes CPU and socket resources. " +
					"Consider offloading ASN %d or its primary CIDR blocks to an upstream firewall (iptables, nftables, AWS WAF, or Cloudflare edge rule) during sustained attacks.",
					asn);

			String iptablesRule = asn > 0 ? "# Block ASN " + asn + " (" + entityName + ") at edge or via iptables" : "";

			String id = "dc-" + sanitizeId(serverId + "-" + valveName + "-asn" + asn);
			String title = String.format("High-Volume Cloud Scraping from %s (ASN %d, %d subnets)", entityName, asn, subnets);

			findings.add(new AdvisorFinding(
					id,
					AdvisorCategory.DATACENTER_OFFLOAD,
					AdvisorSeverity.INFO,
					title,
					serverId,
					valveName,
					"ASN " + asn + " (" + subnets + " subnets)",
					entityName,
					ClientType.DATACENTER,
					totalReq,
					blockedReq,
					blockPct,
					0,
					valveInfo.allowedRequestsPerSlot,
					valveInfo.slotLength,
					valveInfo.alwaysAllowedIps,
					explanation,
					recommendation,
					null,
					iptablesRule
			));
		}, params.toArray());
	}

	private void evaluateStealthCarpetAttacks(
			Timestamp cutoff,
			List<String> servers,
			List<String> valves,
			List<AdvisorFinding> findings) {

		StringBuilder sql = new StringBuilder("""
				SELECT 
				    r.server_id,
				    r.valve_name,
				    COALESCE(r.asn, 0) AS asn,
				    COALESCE(r.as_org, 'Unknown ASN') AS entity_name,
				    COALESCE(r.country_code, 'XX') AS country_code,
				    COUNT(DISTINCT r.subnet_group) AS subnets,
				    SUM(r.distinct_clients) AS estimated_bots,
				    SUM(r.total_requests) AS total_req,
				    SUM(r.blocked_requests) AS blocked_req,
				    SUM(r.authenticated_requests) AS auth_req,
				    SUM(r.returning_requests) AS ret_req,
				    SUM(r.returning_tracked_requests) AS ret_tracked
				FROM client_subnet_rollups r
				WHERE r.client_type NOT IN ('SEARCH_ENGINE', 'PRIVATE_NETWORK')
				  AND r.asn IS NOT NULL AND r.asn > 0
				  AND r.bucket_start >= ?
				""");

		List<Object> params = new ArrayList<>();
		params.add(cutoff);
		appendFilterClauses(sql, params, servers, valves);
		sql.append(" GROUP BY r.server_id, r.valve_name, r.asn, r.as_org, r.country_code " +
				" HAVING SUM(r.total_requests) >= 5000 " +
				"    AND COUNT(DISTINCT r.subnet_group) >= 3 " +
				"    AND (SUM(r.blocked_requests) * 100.0 / SUM(r.total_requests)) < 2.0 " +
				"    AND (SUM(r.authenticated_requests) * 100.0 / SUM(r.total_requests)) < 1.0 " +
				" ORDER BY total_req DESC LIMIT 10");

		jdbcTemplate.query(sql.toString(), rs -> {
			String serverId = rs.getString("server_id");
			String valveName = rs.getString("valve_name");
			long asn = rs.getLong("asn");
			String entityName = rs.getString("entity_name");
			String country = rs.getString("country_code");
			int subnets = rs.getInt("subnets");
			long totalReq = rs.getLong("total_req");
			long blockedReq = rs.getLong("blocked_req");
			long retReq = rs.getLong("ret_req");
			long retTracked = rs.getLong("ret_tracked");

			double retPct = retTracked > 0 ? (double) retReq / retTracked * 100.0 : 0.0;
			if (retPct >= 20.0) {
				return; // Skip if legitimate returning traffic
			}

			double blockPct = totalReq > 0 ? (double) blockedReq / totalReq * 100.0 : 0.0;
			blockPct = Math.round(blockPct * 10.0) / 10.0;

			ValveConfigInfo valveInfo = resolveValveConfig(serverId, valveName);
			AdvisorSeverity severity = (totalReq >= 50000) ? AdvisorSeverity.CRITICAL : AdvisorSeverity.WARNING;

			String explanation = String.format(
					"Autonomous System %s (ASN %d, %s) generated %s requests across %d distinct /24 subnets on valve '%s' on node '%s', " +
					"yet only %d requests (%.1f%%) were blocked. " +
					"Traffic had virtually 0%% authenticated sessions and %.1f%% returning visitors. " +
					"The source is horizontally distributing traffic across multiple IP blocks to evade individual rate-limit thresholds.",
					entityName, asn, country, String.format("%,d", totalReq), subnets, valveName, serverId, blockedReq, blockPct, retPct);

			String recommendation = String.format(
					"This horizontal carpet attack evades local single-client rate limits. Recommended actions:\n" +
					"1) Block or challenge ASN %d (%s) or its primary CIDR blocks upstream at your edge firewall (iptables, AWS WAF, Cloudflare WAF).\n" +
					"2) If this valve uses IP-level tracking (/32), configure a subnet-level valve (ipv4SubnetMask=\"24\") or tighten 'allowedRequestsPerSlot'.\n" +
					"3) Set 'activeSampleThreshold=\"50\"' on valve '%s' to automatically capture forensic URI and User-Agent samples of active unblocked subnets.",
					asn, entityName, valveName);

			String iptablesRule = asn > 0 ? String.format("# Drop ASN %d (%s) at edge or firewall:\n# iptables -I INPUT -m set --match-set asn_%d src -j DROP\n# Distinct /24 subnets observed: %d", asn, entityName, asn, subnets) : "";
			String id = "carpet-" + sanitizeId(serverId + "-" + valveName + "-asn" + asn);
			String title = String.format("Unblocked Stealth Carpet Attack from %s (ASN %d, %d subnets)", entityName, asn, subnets);

			findings.add(new AdvisorFinding(
					id,
					AdvisorCategory.STEALTH_CARPET_ATTACK,
					severity,
					title,
					serverId,
					valveName,
					"ASN " + asn + " (" + subnets + " subnets)",
					entityName + " (" + country + ")",
					ClientType.DATACENTER,
					totalReq,
					blockedReq,
					blockPct,
					0,
					valveInfo.allowedRequestsPerSlot,
					valveInfo.slotLength,
					valveInfo.alwaysAllowedIps,
					explanation,
					recommendation,
					null,
					iptablesRule
			));
		}, params.toArray());
	}

	private void evaluateChameleonScrapers(
			Timestamp cutoff,
			List<String> servers,
			List<String> valves,
			List<AdvisorFinding> findings) {

		StringBuilder sql = new StringBuilder("""
				SELECT 
				    r.server_id,
				    r.valve_name,
				    r.subnet_group,
				    COALESCE(r.as_org, 'Unknown Org') AS entity_name,
				    COALESCE(r.country_code, 'XX') AS country_code,
				    r.client_type,
				    SUM(r.total_requests) AS total_req,
				    SUM(r.blocked_requests) AS blocked_req,
				    MAX(r.distinct_clients) AS max_clients,
				    MAX(r.distinct_user_agents) AS max_uas,
				    SUM(r.authenticated_requests) AS auth_req,
				    SUM(r.returning_requests) AS ret_req,
				    SUM(r.returning_tracked_requests) AS ret_tracked
				FROM client_subnet_rollups r
				WHERE r.client_type NOT IN ('SEARCH_ENGINE', 'PRIVATE_NETWORK')
				  AND r.distinct_user_agents >= 5
				  AND r.bucket_start >= ?
				""");

		List<Object> params = new ArrayList<>();
		params.add(cutoff);
		appendFilterClauses(sql, params, servers, valves);
		sql.append(" GROUP BY r.server_id, r.valve_name, r.subnet_group, r.as_org, r.country_code, r.client_type " +
				" HAVING SUM(r.total_requests) >= 300 " +
				"    AND (SUM(r.authenticated_requests) * 100.0 / SUM(r.total_requests)) < 5.0 " +
				" ORDER BY max_uas DESC, total_req DESC LIMIT 10");

		jdbcTemplate.query(sql.toString(), rs -> {
			String serverId = rs.getString("server_id");
			String valveName = rs.getString("valve_name");
			String subnetGroup = rs.getString("subnet_group");
			String entityName = rs.getString("entity_name");
			String country = rs.getString("country_code");
			ClientType clientType = ClientType.valueOf(rs.getString("client_type"));
			long totalReq = rs.getLong("total_req");
			long blockedReq = rs.getLong("blocked_req");
			int maxClients = rs.getInt("max_clients");
			int maxUas = rs.getInt("max_uas");
			long retReq = rs.getLong("ret_req");
			long retTracked = rs.getLong("ret_tracked");

			double retPct = retTracked > 0 ? (double) retReq / retTracked * 100.0 : 0.0;
			if (retPct >= 20.0) {
				return; // Legitimate returning user / NAT pool
			}
			double uaRatio = maxClients > 0 ? (double) maxUas / maxClients : maxUas;
			if (uaRatio < 2.0 && maxUas < 8) {
				return; // Normal 1:1 client-to-UA ratio
			}

			double blockPct = totalReq > 0 ? (double) blockedReq / totalReq * 100.0 : 0.0;
			blockPct = Math.round(blockPct * 10.0) / 10.0;

			ValveConfigInfo valveInfo = resolveValveConfig(serverId, valveName);

			String explanation = String.format(
					"Subnet %s (%s, %s) generated %s requests on valve '%s' on node '%s' using at least %d distinct User-Agent signatures across %d client IP(s), " +
					"with 0%% authenticated sessions and %.1f%% returning visitors. " +
					"Unlike legitimate corporate NAT gateways, rotating User-Agent strings without session continuity strongly indicates an automated crawler or vulnerability scanner masking its identity.",
					subnetGroup, entityName, country, String.format("%,d", totalReq), valveName, serverId, maxUas, maxClients, retPct);

			String recommendation = String.format(
					"Do NOT whitelist this subnet. Recommended actions:\n" +
					"1) Inspect captured sample URIs and User-Agents in Client Events for subnet '%s' to identify targeted endpoints.\n" +
					"2) If requests target login or sensitive forms, enforce CAPTCHA or WAF managed bot challenge.\n" +
					"3) Consider temporarily blocking subnet '%s' via 'alwaysForbiddenIPs=\"%s\"' on valve '%s'.",
					subnetGroup, subnetGroup, cidrToRegex(subnetGroup), valveName);

			String id = "cham-" + sanitizeId(serverId + "-" + valveName + "-" + subnetGroup);
			String title = String.format("User-Agent Rotating Scraper / Chameleon in %s (%s)", subnetGroup, entityName);

			findings.add(new AdvisorFinding(
					id,
					AdvisorCategory.CHAMELEON_BOT,
					AdvisorSeverity.WARNING,
					title,
					serverId,
					valveName,
					subnetGroup,
					entityName + " (" + country + ")",
					clientType,
					totalReq,
					blockedReq,
					blockPct,
					0,
					valveInfo.allowedRequestsPerSlot,
					valveInfo.slotLength,
					valveInfo.alwaysAllowedIps,
					explanation,
					recommendation,
					null,
					null
			));
		}, params.toArray());
	}

	private void evaluateMissingActiveSampling(
			List<String> servers,
			List<String> valves,
			List<AdvisorFinding> findings) {

		if (monitoredValveRepository == null) {
			return;
		}

		List<MonitoredValve> allValves = monitoredValveRepository.findAll();
		for (MonitoredValve v : allValves) {
			if (!v.isActive()) {
				continue;
			}
			if (servers != null && !servers.isEmpty() && !servers.contains(v.serverId())) {
				continue;
			}
			if (valves != null && !valves.isEmpty() && !valves.contains(v.valveName())) {
				continue;
			}
			if ("OFF".equalsIgnoreCase(v.collectorIntegration())) {
				continue;
			}

			// Subnet-aggregated valves lacking active forensic sampling
			if (v.ipv4SubnetMask() <= 24 && v.activeSampleThreshold() <= 0) {
				String id = "samp-" + sanitizeId(v.serverId() + "-" + v.valveName());
				String title = String.format("Forensic Active Sampling Inactive on '%s' (%s)", v.valveName(), v.serverId());
				String explanation = String.format(
						"Valve '%s' on node '%s' operates with subnet aggregation (/%d) but 'activeSampleThreshold' is set to 0. " +
						"When distributed or horizontal scraping attacks stay below the blocking limit (%s req / %ss), no request URI, HTTP method, or User-Agent forensic samples are captured for incident response.",
						v.valveName(), v.serverId(), v.ipv4SubnetMask(), formatLimit(v.allowedRequestsPerSlot()), formatSlotLength(v.slotLength()));

				String recommendation = String.format(
						"Configure 'activeSampleThreshold=\"50\"' on valve '%s' in server.xml. " +
						"The Valve will then record a single forensic sample (URI, method, User-Agent) when an active subnet hits 50 requests per slot, providing immediate visibility into targeted endpoints during stealth incidents.",
						v.valveName());

				String suggestedXml = String.format("""
						<!-- Enable active forensic sampling on Valve '%s' in server.xml: -->
						<Valve className="org.henbru.antidos.AntiDoSValve"
						       monitorName="%s"
						       activeSampleThreshold="50" />""",
						v.valveName(), v.valveName());

				findings.add(new AdvisorFinding(
						id,
						AdvisorCategory.SAMPLING_TUNING,
						AdvisorSeverity.INFO,
						title,
						v.serverId(),
						v.valveName(),
						"Subnet Mask /" + v.ipv4SubnetMask(),
						"Valve Configuration",
						ClientType.UNKNOWN,
						0,
						0,
						0.0,
						0,
						v.allowedRequestsPerSlot(),
						v.slotLength(),
						v.alwaysAllowedIPs(),
						explanation,
						recommendation,
						suggestedXml,
						null
				));
			}
		}
	}

	private void appendFilterClauses(StringBuilder sql, List<Object> params, List<String> servers, List<String> valves) {
		if (servers != null && !servers.isEmpty()) {
			sql.append(" AND r.server_id IN (");
			for (int i = 0; i < servers.size(); i++) {
				if (i > 0) sql.append(", ");
				sql.append("?");
				params.add(servers.get(i));
			}
			sql.append(")");
		}
		if (valves != null && !valves.isEmpty()) {
			sql.append(" AND r.valve_name IN (");
			for (int i = 0; i < valves.size(); i++) {
				if (i > 0) sql.append(", ");
				sql.append("?");
				params.add(valves.get(i));
			}
			sql.append(")");
		}
	}

	public static String cidrToRegex(String cidr) {
		if (cidr == null || cidr.isBlank()) {
			return "";
		}
		cidr = cidr.trim();
		if (!cidr.contains("/")) {
			return cidr.replace(".", "\\.");
		}
		String[] parts = cidr.split("/");
		String ip = parts[0];
		int prefix;
		try {
			prefix = Integer.parseInt(parts[1]);
		} catch (NumberFormatException e) {
			prefix = 24;
		}

		if (ip.contains(".")) {
			String[] octets = ip.split("\\.");
			if (prefix <= 8 && octets.length >= 1) {
				return octets[0] + "\\..*";
			} else if (prefix <= 16 && octets.length >= 2) {
				return octets[0] + "\\." + octets[1] + "\\..*";
			} else if (prefix <= 24 && octets.length >= 3) {
				return octets[0] + "\\." + octets[1] + "\\." + octets[2] + "\\..*";
			} else if (octets.length >= 4) {
				return octets[0] + "\\." + octets[1] + "\\." + octets[2] + "\\." + octets[3];
			}
		} else if (ip.contains(":")) {
			int colonCount = prefix / 16;
			String[] hextets = ip.split(":");
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < Math.min(colonCount, hextets.length); i++) {
				if (!hextets[i].isEmpty()) {
					if (sb.length() > 0) sb.append(":");
					sb.append(hextets[i]);
				}
			}
			return sb.length() > 0 ? sb.append(":.*").toString() : ip + ".*";
		}
		return Pattern.quote(ip) + ".*";
	}

	public static String mergeWithExistingRegex(String existing, String newSubnetRegex) {
		if (existing == null || existing.isBlank()) {
			return newSubnetRegex;
		}
		existing = existing.trim();
		if (existing.contains(newSubnetRegex)) {
			return existing;
		}
		return existing + "|" + newSubnetRegex;
	}

	private String buildConsolidatedRegex(Set<String> subnets) {
		if (subnets == null || subnets.isEmpty()) {
			return "";
		}
		List<String> regexes = new ArrayList<>();
		for (String s : subnets) {
			String r = cidrToRegex(s);
			if (!r.isBlank() && !regexes.contains(r)) {
				regexes.add(r);
			}
		}
		return String.join("|", regexes);
	}

	private String buildConsolidatedServerXmlSnippet(String consolidatedRegex) {
		if (consolidatedRegex == null || consolidatedRegex.isBlank()) {
			return "<!-- No unwhitelisted internal subnets or blocked search engines detected. -->";
		}
		return String.format("""
				<!-- Consolidated AntiDoSValve alwaysAllowedIPs configuration: -->
				<Valve className="org.henbru.antidos.AntiDoSValve"
				       monitorName="PRIMARY-LIMITER"
				       alwaysAllowedIPs="%s" />""",
				consolidatedRegex);
	}

	private ValveConfigInfo resolveValveConfig(String serverId, String valveName) {
		if (monitoredValveRepository != null) {
			try {
				Optional<MonitoredValve> opt = monitoredValveRepository.findByServerIdAndValveName(serverId, valveName);
				if (opt.isPresent()) {
					MonitoredValve v = opt.get();
					return new ValveConfigInfo(
							v.allowedRequestsPerSlot() >= 0 ? v.allowedRequestsPerSlot() : null,
							v.slotLength() > 0 ? v.slotLength() : null,
							v.alwaysAllowedIPs()
					);
				}
			} catch (Exception e) {
				log.debug("Could not resolve valve config for {}/{}: {}", serverId, valveName, e.getMessage());
			}
		}
		return new ValveConfigInfo(null, null, null);
	}

	private static String sanitizeId(String s) {
		return s.replaceAll("[^a-zA-Z0-9_-]", "-").toLowerCase();
	}

	private static String formatLimit(Integer limit) {
		return limit != null ? String.valueOf(limit) : "N/A";
	}

	private static String formatSlotLength(Integer slotLength) {
		return slotLength != null ? String.valueOf(slotLength) : "N/A";
	}

	private record ValveConfigInfo(Integer allowedRequestsPerSlot, Integer slotLength, String alwaysAllowedIps) {}
}
