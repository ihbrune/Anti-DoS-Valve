package org.henbru.antidos.collector.system;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.henbru.antidos.collector.config.ValveRuleConfig;

/**
 * Aggregated domain transfer object capturing all system parameters, storage diagnostics,
 * automation states, threat intelligence indexes, and runtime environment metrics.
 */
public record SystemStatusDto(
		ConfigInfo config,
		DatabaseInfo database,
		SchedulerInfo schedulers,
		ThreatIntelInfo intel,
		RuntimeInfo runtime,
		FleetHealthInfo fleetHealth
) {

	public record ConfigInfo(
			String configFile,
			boolean configFileExists,
			String configAbsolutePath,
			int pollIntervalSeconds,
			boolean parallelFleetPolling,
			int slowPollThresholdMs,
			int retentionDays,
			int pollLogRetentionDays,
			int entityRetentionDays,
			boolean rollupEnabled,
			int rollupWindowMinutes,
			int rollupRetentionDays,
			int enrichmentTtlDays,
			boolean demoMode,
			ValveRuleConfig defaultValveRules,
			Map<String, ValveRuleConfig> valveRules,
			List<EndpointDisplayInfo> endpoints
	) {}

	public record EndpointDisplayInfo(
			String name,
			String url,
			boolean enabled,
			boolean pollIntermediateSlots,
			boolean hasToken,
			List<String> valves
	) {}

	public record DatabaseInfo(
			String engine,
			String sanitizedJdbcUrl,
			boolean isSqlite,
			String sqliteFilePath,
			long sqliteFileSizeBytes,
			String sqliteFileSizeFormatted,
			Instant sqliteLastModified,
			Map<String, Long> tableCounts,
			HikariPoolInfo hikari,
			FlywayInfo flyway
	) {}

	public record HikariPoolInfo(
			int activeConnections,
			int idleConnections,
			int totalConnections,
			int maxPoolSize,
			int threadsAwaiting
	) {}

	public record FlywayInfo(
			String currentVersion,
			String description,
			String installedOn
	) {}

	public record SchedulerInfo(
			String retentionCron,
			Instant lastRetentionRun,
			String lastRetentionSummary,
			String rollupCron,
			int rollupWindowMinutes,
			Instant lastRollupRun,
			String lastRollupSummary,
			String crawlerSyncCron,
			boolean crawlerSyncEnabled,
			Instant lastCrawlerSyncRun,
			int activeCrawlerFeeds,
			Instant lastFleetPollTime
	) {}

	public record ThreatIntelInfo(
			boolean enrichmentEnabled,
			int ttlDays,
			MmdbInfo asnMmdb,
			MmdbInfo countryMmdb,
			CustomAsnInfo customAsns,
			int inMemoryV4Ranges,
			int inMemoryV6Ranges,
			int inMemoryTotalRanges,
			int entityCacheSize,
			int maxCacheEntries
	) {}

	public record MmdbInfo(
			String configuredPath,
			boolean loaded,
			boolean fileExists,
			long fileSizeBytes,
			String fileSizeFormatted,
			Instant fileLastModified,
			String databaseType,
			Instant buildDate,
			String buildDateFormatted,
			Long ageDays
	) {}

	public record CustomAsnInfo(
			String configuredPath,
			boolean fileExists,
			int totalDatacenterAsns
	) {}

	public record RuntimeInfo(
			String appVersion,
			String javaVersion,
			String javaVendor,
			boolean virtualThreadsEnabled,
			String osName,
			String osArch,
			int availableProcessors,
			Instant startTime,
			long uptimeSeconds,
			String uptimeFormatted,
			long heapUsedBytes,
			long heapMaxBytes,
			String heapUsedFormatted,
			String heapMaxFormatted,
			int heapPercent
	) {}

	public record FleetHealthInfo(
			int totalEndpoints,
			int enabledEndpoints,
			int onlineEndpoints,
			int offlineEndpoints
	) {}
}
