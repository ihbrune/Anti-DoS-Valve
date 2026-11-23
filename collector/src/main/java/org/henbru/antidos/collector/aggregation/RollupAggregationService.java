package org.henbru.antidos.collector.aggregation;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientSubnetRollup;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.storage.SubnetRollupRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Service that rolls up raw client_events into aggregated subnet time-bucket records (client_subnet_rollups).
 * Supports configurable window durations (default: 60 minutes) and automated retention cleanup.
 */
@Service
public class RollupAggregationService {

	private static final Logger log = LoggerFactory.getLogger(RollupAggregationService.class);

	private final JdbcTemplate jdbcTemplate;
	private final SubnetRollupRepository rollupRepository;
	private final CollectorProperties properties;
	private final SubnetProfileService subnetProfileService;
	private final UserAgentMemoryService userAgentMemoryService;
	private final org.henbru.antidos.collector.storage.EndpointRollupRepository endpointRollupRepository;
	private final org.henbru.antidos.collector.storage.UaMitigationRollupRepository uaMitigationRollupRepository;
	private final java.util.concurrent.atomic.AtomicBoolean realtimePending = new java.util.concurrent.atomic.AtomicBoolean(false);
	private final java.util.concurrent.atomic.AtomicBoolean realtimeWorkerRunning = new java.util.concurrent.atomic.AtomicBoolean(false);

	@Autowired
	public RollupAggregationService(
			JdbcTemplate jdbcTemplate,
			SubnetRollupRepository rollupRepository,
			CollectorProperties properties,
			@Autowired(required = false) SubnetProfileService subnetProfileService,
			@Autowired(required = false) UserAgentMemoryService userAgentMemoryService,
			@Autowired(required = false) org.henbru.antidos.collector.storage.EndpointRollupRepository endpointRollupRepository,
			@Autowired(required = false) org.henbru.antidos.collector.storage.UaMitigationRollupRepository uaMitigationRollupRepository
	) {
		this.jdbcTemplate = jdbcTemplate;
		this.rollupRepository = rollupRepository;
		this.properties = properties;
		this.subnetProfileService = subnetProfileService;
		this.userAgentMemoryService = userAgentMemoryService;
		this.endpointRollupRepository = endpointRollupRepository;
		this.uaMitigationRollupRepository = uaMitigationRollupRepository;
	}

	public RollupAggregationService(
			JdbcTemplate jdbcTemplate,
			SubnetRollupRepository rollupRepository,
			CollectorProperties properties,
			SubnetProfileService subnetProfileService,
			UserAgentMemoryService userAgentMemoryService,
			org.henbru.antidos.collector.storage.EndpointRollupRepository endpointRollupRepository
	) {
		this(jdbcTemplate, rollupRepository, properties, subnetProfileService, userAgentMemoryService, endpointRollupRepository, null);
	}

	public RollupAggregationService(
			JdbcTemplate jdbcTemplate,
			SubnetRollupRepository rollupRepository,
			CollectorProperties properties,
			SubnetProfileService subnetProfileService,
			UserAgentMemoryService userAgentMemoryService
	) {
		this(jdbcTemplate, rollupRepository, properties, subnetProfileService, userAgentMemoryService, null);
	}

	public RollupAggregationService(
			JdbcTemplate jdbcTemplate,
			SubnetRollupRepository rollupRepository,
			CollectorProperties properties,
			SubnetProfileService subnetProfileService
	) {
		this(jdbcTemplate, rollupRepository, properties, subnetProfileService, null, null);
	}

	public RollupAggregationService(
			JdbcTemplate jdbcTemplate,
			SubnetRollupRepository rollupRepository,
			CollectorProperties properties
	) {
		this(jdbcTemplate, rollupRepository, properties, null, null, null);
	}

	/**
	 * Aggregates client events for the specified time window into subnet rollups.
	 *
	 * @param bucketStart Start boundary (inclusive)
	 * @param bucketEnd   End boundary (exclusive)
	 * @return Number of rollups persisted
	 */
	public int aggregateWindow(Instant bucketStart, Instant bucketEnd) {
		if (bucketStart == null || bucketEnd == null || !bucketEnd.isAfter(bucketStart)) {
			throw new IllegalArgumentException("Invalid window: bucketEnd must be after bucketStart");
		}

		int bucketMinutes = (int) ChronoUnit.MINUTES.between(bucketStart, bucketEnd);
		if (bucketMinutes <= 0) {
			bucketMinutes = properties.getRollupWindowMinutes();
		}

		String sql = """
				SELECT
				    server_id,
				    valve_name,
				    subnet_group,
				    SUM(request_count) AS total_requests,
				    SUM(CASE WHEN status = 'ACTIVE' THEN request_count ELSE 0 END) AS active_requests,
				    SUM(CASE WHEN status = 'BLOCKED' THEN request_count ELSE 0 END) AS blocked_requests,
				    SUM(CASE WHEN status = 'MARKED' THEN request_count ELSE 0 END) AS marked_requests,
				    CASE WHEN MAX(distinct_clients) > COUNT(DISTINCT client_key) THEN MAX(distinct_clients) ELSE COUNT(DISTINCT client_key) END AS distinct_clients,
				    COALESCE(MAX(distinct_user_agents), 0) AS distinct_user_agents,
				    MIN(request_count) AS min_requests_per_client,
				    MAX(request_count) AS max_requests_per_client,
				    COUNT(DISTINCT slot_key) AS slots_active_count,
				    MAX(asn) AS asn,
				    MAX(as_org) AS as_org,
				    MAX(country_code) AS country_code,
				    MAX(client_type) AS client_type,
				    COALESCE(SUM(returning_count), 0) AS returning_requests,
				    COALESCE(SUM(CASE WHEN returning_count IS NOT NULL THEN request_count ELSE 0 END), 0) AS returning_tracked_requests,
				    COALESCE(SUM(authenticated_count), 0) AS authenticated_requests,
				    COALESCE(SUM(CASE WHEN authenticated_count IS NOT NULL THEN request_count ELSE 0 END), 0) AS authenticated_tracked_requests,
				    COALESCE(SUM(ua_mismatch_count), 0) AS ua_mismatch_requests
				FROM client_events
				WHERE slot_time >= ? AND slot_time < ? AND subnet_group IS NOT NULL AND subnet_group != ''
				GROUP BY server_id, valve_name, subnet_group
				""";

		final int finalMinutes = bucketMinutes;
		List<ClientSubnetRollup> rollups = jdbcTemplate.query(
				sql,
				(rs, rowNum) -> {
					Long asn = rs.getObject("asn") != null ? rs.getLong("asn") : null;
					String rawType = rs.getString("client_type");
					ClientType clientType = rawType != null ? ClientType.valueOf(rawType) : ClientType.UNKNOWN;

					long returningRequests = rs.getLong("returning_requests");
					long returningTrackedRequests = rs.getLong("returning_tracked_requests");
					long authenticatedRequests = rs.getLong("authenticated_requests");
					long authenticatedTrackedRequests = rs.getLong("authenticated_tracked_requests");
					long uaMismatchRequests = rs.getLong("ua_mismatch_requests");

					return new ClientSubnetRollup(
							null,
							bucketStart,
							bucketEnd,
							finalMinutes,
							rs.getString("server_id"),
							rs.getString("valve_name"),
							rs.getString("subnet_group"),
							rs.getLong("total_requests"),
							rs.getLong("active_requests"),
							rs.getLong("blocked_requests"),
							rs.getLong("marked_requests"),
							rs.getInt("distinct_clients"),
							rs.getInt("distinct_user_agents"),
							rs.getInt("min_requests_per_client"),
							rs.getInt("max_requests_per_client"),
							rs.getInt("slots_active_count"),
							asn,
							rs.getString("as_org"),
							rs.getString("country_code"),
							clientType,
							Instant.now(),
							returningRequests,
							returningTrackedRequests,
							authenticatedRequests,
							authenticatedTrackedRequests,
							uaMismatchRequests
					);
				},
				Timestamp.from(bucketStart),
				Timestamp.from(bucketEnd)
		);

		if (!rollups.isEmpty()) {
			rollupRepository.batchUpsert(rollups);
			log.info("Persisted {} subnet rollups for window [{} -> {}] ({} min)",
					rollups.size(), bucketStart, bucketEnd, bucketMinutes);
		} else {
			log.debug("No client events to roll up for window [{} -> {}]", bucketStart, bucketEnd);
		}

		if (userAgentMemoryService != null) {
			try {
				userAgentMemoryService.aggregateHourlyWindow(bucketStart, bucketEnd);
			} catch (Exception e) {
				log.debug("User-Agent hourly rollup skipped for [{} -> {}]: {}", bucketStart, bucketEnd, e.getMessage());
			}
		}

		if (endpointRollupRepository != null) {
			try {
				aggregateEndpointsWindow(bucketStart, bucketEnd);
			} catch (Exception e) {
				log.debug("Endpoint rollup skipped for [{} -> {}]: {}", bucketStart, bucketEnd, e.getMessage());
			}
		}

		if (uaMitigationRollupRepository != null) {
			try {
				aggregateUaMitigationWindow(bucketStart, bucketEnd);
			} catch (Exception e) {
				log.debug("User-Agent mitigation rollup skipped for [{} -> {}]: {}", bucketStart, bucketEnd, e.getMessage());
			}
		}

		return rollups.size();
	}

	/**
	 * Aggregates client events for the specified time window into dynamic User-Agent mitigation rollups.
	 *
	 * @param bucketStart Start boundary (inclusive)
	 * @param bucketEnd   End boundary (exclusive)
	 * @return Number of UA mitigation rollups persisted
	 */
	public int aggregateUaMitigationWindow(Instant bucketStart, Instant bucketEnd) {
		if (uaMitigationRollupRepository == null || bucketStart == null || bucketEnd == null) {
			return 0;
		}

		String sql = """
				SELECT
				    server_id,
				    valve_name,
				    SUM(request_count) AS total_requests,
				    SUM(CASE WHEN status = 'BLOCKED' THEN request_count ELSE 0 END) AS blocked_requests,
				    SUM(CASE WHEN status = 'MARKED' THEN request_count ELSE 0 END) AS marked_requests,
				    COUNT(DISTINCT client_key) AS distinct_ua_rules
				FROM client_events
				WHERE slot_time >= ? AND slot_time < ?
				  AND client_key LIKE 'UA:%'
				GROUP BY server_id, valve_name
				""";

		List<org.henbru.antidos.collector.model.UaMitigationRollup> list = jdbcTemplate.query(
				sql,
				(rs, rowNum) -> new org.henbru.antidos.collector.model.UaMitigationRollup(
						bucketStart,
						rs.getString("server_id"),
						rs.getString("valve_name"),
						rs.getLong("total_requests"),
						rs.getLong("blocked_requests"),
						rs.getLong("marked_requests"),
						rs.getInt("distinct_ua_rules")
				),
				Timestamp.from(bucketStart),
				Timestamp.from(bucketEnd)
		);

		if (!list.isEmpty()) {
			uaMitigationRollupRepository.batchUpsert(list);
			log.info("Persisted {} UA mitigation rollups for window [{} -> {}]", list.size(), bucketStart, bucketEnd);
		}
		return list.size();
	}

	/**
	 * Aggregates client events for the specified time window into endpoint rollups.
	 *
	 * @param bucketStart Start boundary (inclusive)
	 * @param bucketEnd   End boundary (exclusive)
	 * @return Number of endpoint rollups persisted
	 */
	public int aggregateEndpointsWindow(Instant bucketStart, Instant bucketEnd) {
		if (endpointRollupRepository == null || bucketStart == null || bucketEnd == null) {
			return 0;
		}

		String sql = """
				SELECT
				    server_id,
				    valve_name,
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
				    COUNT(DISTINCT NULLIF(subnet_group, '')) AS distinct_subnets,
				    COALESCE(MAX(distinct_user_agents), 0) AS distinct_user_agents,
				    SUM(CASE WHEN sample_authenticated = TRUE THEN 1 ELSE 0 END) AS auth_samples,
				    SUM(CASE WHEN sample_returning_visitor = TRUE THEN 1 ELSE 0 END) AS returning_samples
				FROM client_events
				WHERE slot_time >= ? AND slot_time < ? AND sample_uri IS NOT NULL AND TRIM(sample_uri) != ''
				GROUP BY server_id, valve_name, sample_uri, sample_method
				""";

		java.util.Map<String, org.henbru.antidos.collector.model.EndpointRollup> merged = new java.util.LinkedHashMap<>();
		jdbcTemplate.query(
				sql,
				rs -> {
					String sId = rs.getString("server_id");
					String vName = rs.getString("valve_name");
					String rawUri = rs.getString("sample_uri");
					String clean = org.henbru.antidos.collector.model.EndpointRollup.normalizeUri(rawUri);
					String method = rs.getString("sample_method");
					String key = (sId != null ? sId : "") + "#" + (vName != null ? vName : "") + "#" + clean + "#" + method;

					org.henbru.antidos.collector.model.EndpointRollup existing = merged.get(key);
					if (existing == null) {
						merged.put(key, new org.henbru.antidos.collector.model.EndpointRollup(
								bucketStart,
								sId,
								vName,
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
						merged.put(key, new org.henbru.antidos.collector.model.EndpointRollup(
								bucketStart,
								sId,
								vName,
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
				},
				Timestamp.from(bucketStart),
				Timestamp.from(bucketEnd)
		);

		if (!merged.isEmpty()) {
			List<org.henbru.antidos.collector.model.EndpointRollup> list = new ArrayList<>(merged.values());
			endpointRollupRepository.batchUpsert(list);
			log.info("Persisted {} endpoint rollups for window [{} -> {}]", list.size(), bucketStart, bucketEnd);
			return list.size();
		}
		return 0;
	}
	/**
	 * Execution result of a subnet rollup aggregation run.
	 */
	public record RollupExecutionResult(
			Instant executedAt,
			int persistedRollups,
			long durationMs
	) {}

	private volatile RollupExecutionResult lastRollupResult;

	public RollupExecutionResult getLastRollupResult() {
		return lastRollupResult;
	}

	/**
	 * Signals the coalescing real-time rollup worker to refresh the current in-progress rollup bucket
	 * asynchronously on a Virtual Thread without blocking the caller (poller).
	 */
	public void signalRealtimeRollupRefresh() {
		if (!properties.getMode().isBackgroundProcessingEnabled() || !properties.isRollupEnabled()) {
			return;
		}
		realtimePending.set(true);
		if (realtimeWorkerRunning.compareAndSet(false, true)) {
			Thread.ofVirtual().name("realtime-rollup-worker").start(this::runRealtimeRollupLoop);
		}
	}

	private void runRealtimeRollupLoop() {
		try {
			while (realtimePending.getAndSet(false)) {
				try {
					// Coalesce bursty parallel endpoint polls over a 2-second quiet window
					Thread.sleep(2000L);
					realtimePending.set(false);
					aggregateCurrentBucket();
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					break;
				} catch (Exception e) {
					log.debug("Real-time rollup refresh encountered an issue: {}", e.getMessage());
				}
			}
		} finally {
			realtimeWorkerRunning.set(false);
			if (realtimePending.get() && realtimeWorkerRunning.compareAndSet(false, true)) {
				Thread.ofVirtual().name("realtime-rollup-worker").start(this::runRealtimeRollupLoop);
			}
		}
	}

	/**
	 * Aggregates the currently open (in-progress) rollup bucket so Advisor and Mitigation rules
	 * have near-real-time visibility without waiting for the 15-minute cron.
	 */
	public int aggregateCurrentBucket() {
		if (!properties.getMode().isBackgroundProcessingEnabled() || !properties.isRollupEnabled()) {
			return 0;
		}
		int windowMinutes = Math.max(1, properties.getRollupWindowMinutes());
		Instant now = Instant.now();
		long currentEpochMinutes = now.getEpochSecond() / 60;
		long bucketStartMinutes = (currentEpochMinutes / windowMinutes) * windowMinutes;
		Instant bStart = Instant.ofEpochSecond(bucketStartMinutes * 60);
		Instant bEnd = bStart.plus(windowMinutes, ChronoUnit.MINUTES);
		int persisted = aggregateWindow(bStart, bEnd);
		if (userAgentMemoryService != null) {
			try {
				userAgentMemoryService.refreshProfiles24h();
			} catch (Exception e) {
				log.debug("Real-time User-Agent 24h profile refresh skipped: {}", e.getMessage());
			}
		}
		return persisted;
	}

	/**
	 * Scheduled aggregation job running every 15 minutes by default.
	 * Checks and catches up recent completed windows based on rollupWindowMinutes.
	 */
	@Scheduled(cron = "${collector.rollup.cron:0 */15 * * * *}")
	public void scheduleRollup() {
		if (!properties.getMode().isBackgroundProcessingEnabled() || !properties.isRollupEnabled()) {
			return;
		}

		try {
			// Catch up the last 6 hours of completed windows aligned to configured rollupWindowMinutes
			executeManualCatchUp(6);
		} catch (Exception e) {
			log.error("Error executing scheduled subnet rollup: {}", e.getMessage(), e);
		}
	}

	/**
	 * Manually executes a catch-up run for the specified lookback hours, recording execution metrics.
	 */
	public RollupExecutionResult executeManualCatchUp(int lookbackHours) {
		long start = System.currentTimeMillis();
		int persisted = aggregateCatchUp(lookbackHours);
		if (subnetProfileService != null) {
			try {
				subnetProfileService.refreshProfiles();
			} catch (Exception e) {
				log.warn("Subnet profiles refresh failed after rollup catchup: {}", e.getMessage());
			}
		}
		if (userAgentMemoryService != null) {
			try {
				userAgentMemoryService.backfillIfEmpty();
				userAgentMemoryService.refreshProfiles24h();
			} catch (Exception e) {
				log.warn("User-Agent profiles refresh failed after rollup catchup: {}", e.getMessage());
			}
		}
		long durationMs = System.currentTimeMillis() - start;
		RollupExecutionResult result = new RollupExecutionResult(Instant.now(), persisted, durationMs);
		this.lastRollupResult = result;
		return result;
	}

	/**
	 * Catches up all completed windows within the specified lookback hours.
	 * Idempotent thanks to database ON CONFLICT upsert.
	 *
	 * @param lookbackHours Hours to look back
	 * @return Total number of rollups persisted
	 */
	public int aggregateCatchUp(int lookbackHours) {
		if (!properties.isRollupEnabled() || lookbackHours <= 0) {
			return 0;
		}

		int windowMinutes = properties.getRollupWindowMinutes();
		Instant now = Instant.now();
		long currentEpochMinutes = now.getEpochSecond() / 60;
		long latestAlignedEndMinutes = (currentEpochMinutes / windowMinutes) * windowMinutes;
		long earliestEndMinutes = latestAlignedEndMinutes - ((long) lookbackHours * 60);

		int totalPersisted = 0;
		for (long endMin = earliestEndMinutes + windowMinutes; endMin <= latestAlignedEndMinutes; endMin += windowMinutes) {
			Instant bEnd = Instant.ofEpochSecond(endMin * 60);
			Instant bStart = bEnd.minus(windowMinutes, ChronoUnit.MINUTES);
			if (bEnd.isBefore(now.minus(1, ChronoUnit.MINUTES))) {
				totalPersisted += aggregateWindow(bStart, bEnd);
			}
		}
		return totalPersisted;
	}

	@org.springframework.context.event.EventListener(org.springframework.boot.context.event.ApplicationReadyEvent.class)
	public void onStartup() {
		if (properties.getMode().isBackgroundProcessingEnabled() && properties.isRollupEnabled()) {
			Thread.ofVirtual().name("rollup-startup-catchup").start(() -> {
				try {
					Thread.sleep(5000);
					executeManualCatchUp(24);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				} catch (Exception e) {
					log.warn("Initial rollup catchup encountered an issue: {}", e.getMessage());
				}
			});
		}
	}

	/**
	 * Scheduled retention cleanup for subnet rollups running daily at 03:30 AM.
	 * Executes tiered compaction:
	 * 1. Low-activity benign rollups (blocked=0, marked=0, total_requests <= lowActivityRollupMaxRequests)
	 *    are purged after lowActivityRollupRetentionDays (e.g. 7 days).
	 * 2. Remaining rollups (including all security events and significant volume) are purged after rollupRetentionDays.
	 */
	@Scheduled(cron = "${collector.rollup.cleanup-cron:0 30 3 * * *}")
	public void cleanupOldRollups() {
		if (!properties.getMode().isBackgroundProcessingEnabled() || !properties.isRollupEnabled()) {
			return;
		}

		try {
			int lowActivityDays = properties.getLowActivityRollupRetentionDays() > 0 ? properties.getLowActivityRollupRetentionDays() : 7;
			long maxRequests = properties.getLowActivityRollupMaxRequests() >= 0 ? properties.getLowActivityRollupMaxRequests() : 5L;
			Instant lowActivityCutoff = Instant.now().minus(lowActivityDays, ChronoUnit.DAYS);
			int deletedLowActivity = rollupRepository.deleteLowActivityOlderThan(lowActivityCutoff, maxRequests);
			if (deletedLowActivity > 0) {
				log.info("Tiered cleanup purged {} low-activity benign subnet rollups (requests <= {}) older than {} days (cutoff: {})",
						deletedLowActivity, maxRequests, lowActivityDays, lowActivityCutoff);
			}

			Instant cutoff = Instant.now().minus(properties.getRollupRetentionDays(), ChronoUnit.DAYS);
			int deleted = rollupRepository.deleteOlderThan(cutoff);
			if (deleted > 0) {
				log.info("Purged {} historical subnet rollups older than {} days (cutoff: {})",
						deleted, properties.getRollupRetentionDays(), cutoff);
			}
			if (userAgentMemoryService != null) {
				int deletedUa = userAgentMemoryService.cleanupOldHourlyRollups();
				if (deletedUa > 0) {
					log.info("Purged {} historical User-Agent hourly rollups older than {} days",
							deletedUa, properties.getRollupRetentionDays());
				}
			}
			if (endpointRollupRepository != null) {
				int deletedEp = endpointRollupRepository.deleteOlderThan(cutoff);
				if (deletedEp > 0) {
					log.info("Purged {} historical endpoint rollups older than {} days",
							deletedEp, properties.getRollupRetentionDays());
				}
			}
			if (uaMitigationRollupRepository != null) {
				int deletedUaMit = uaMitigationRollupRepository.deleteOlderThan(cutoff);
				if (deletedUaMit > 0) {
					log.info("Purged {} historical UA mitigation rollups older than {} days",
							deletedUaMit, properties.getRollupRetentionDays());
				}
			}
		} catch (Exception e) {
			log.error("Error during subnet rollup retention cleanup: {}", e.getMessage(), e);
		}
	}
}
