package org.henbru.antidos.collector.aggregation;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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

	@Autowired
	public RollupAggregationService(
			JdbcTemplate jdbcTemplate,
			SubnetRollupRepository rollupRepository,
			CollectorProperties properties,
			@Autowired(required = false) SubnetProfileService subnetProfileService
	) {
		this.jdbcTemplate = jdbcTemplate;
		this.rollupRepository = rollupRepository;
		this.properties = properties;
		this.subnetProfileService = subnetProfileService;
	}

	public RollupAggregationService(
			JdbcTemplate jdbcTemplate,
			SubnetRollupRepository rollupRepository,
			CollectorProperties properties
	) {
		this(jdbcTemplate, rollupRepository, properties, null);
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
				    COALESCE(SUM(CASE WHEN authenticated_count IS NOT NULL THEN request_count ELSE 0 END), 0) AS authenticated_tracked_requests
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
							rs.getInt("min_requests_per_client"),
							rs.getInt("max_requests_per_client"),
							rs.getInt("slots_active_count"),
							asn,
							rs.getString("as_org"),
							rs.getString("country_code"),
							clientType,
							returningRequests,
							returningTrackedRequests,
							authenticatedRequests,
							authenticatedTrackedRequests
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

		return rollups.size();
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
	 * Scheduled aggregation job running every 15 minutes by default.
	 * Checks and catches up recent completed windows based on rollupWindowMinutes.
	 */
	@Scheduled(cron = "${collector.rollup.cron:0 */15 * * * *}")
	public void scheduleRollup() {
		if (!properties.isRollupEnabled()) {
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
		if (properties.isRollupEnabled()) {
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
	 */
	@Scheduled(cron = "${collector.rollup.cleanup-cron:0 30 3 * * *}")
	public void cleanupOldRollups() {
		if (!properties.isRollupEnabled()) {
			return;
		}

		try {
			Instant cutoff = Instant.now().minus(properties.getRollupRetentionDays(), ChronoUnit.DAYS);
			int deleted = rollupRepository.deleteOlderThan(cutoff);
			if (deleted > 0) {
				log.info("Purged {} historical subnet rollups older than {} days (cutoff: {})",
						deleted, properties.getRollupRetentionDays(), cutoff);
			}
		} catch (Exception e) {
			log.error("Error during subnet rollup retention cleanup: {}", e.getMessage(), e);
		}
	}
}
