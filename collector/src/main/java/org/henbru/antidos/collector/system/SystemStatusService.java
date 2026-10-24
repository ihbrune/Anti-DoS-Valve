package org.henbru.antidos.collector.system;

import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.henbru.antidos.collector.aggregation.RollupAggregationService;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.enrichment.AsnClassifierService;
import org.henbru.antidos.collector.enrichment.EntityResolver;
import org.henbru.antidos.collector.enrichment.IntelRegistry;
import org.henbru.antidos.collector.enrichment.MmdbEnrichmentProvider;
import org.henbru.antidos.collector.model.CrawlerFeed;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.poller.CollectorPollerService;
import org.henbru.antidos.collector.poller.CollectorScheduler;
import org.henbru.antidos.collector.storage.CrawlerFeedRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Service consolidating diagnostic telemetry, storage metrics, active cascade configurations,
 * and operational scheduler status for the System & Settings dashboard.
 */
@Service
@SuppressWarnings("null")
public class SystemStatusService {

	private static final Logger log = LoggerFactory.getLogger(SystemStatusService.class);

	private final CollectorProperties properties;
	private final JdbcTemplate jdbcTemplate;
	private final DataSource dataSource;
	private final Flyway flyway;
	private final CollectorScheduler collectorScheduler;
	private final RollupAggregationService rollupAggregationService;
	private final CrawlerFeedRepository crawlerFeedRepository;
	private final CollectorPollerService collectorPollerService;
	private final MmdbEnrichmentProvider mmdbProvider;
	private final AsnClassifierService asnClassifierService;
	private final IntelRegistry intelRegistry;
	private final EntityResolver entityResolver;
	private final HeartbeatRepository heartbeatRepository;
	private final boolean virtualThreadsEnabled;

	@Autowired
	public SystemStatusService(
			CollectorProperties properties,
			JdbcTemplate jdbcTemplate,
			DataSource dataSource,
			@Autowired(required = false) Flyway flyway,
			CollectorScheduler collectorScheduler,
			RollupAggregationService rollupAggregationService,
			CrawlerFeedRepository crawlerFeedRepository,
			CollectorPollerService collectorPollerService,
			MmdbEnrichmentProvider mmdbProvider,
			AsnClassifierService asnClassifierService,
			IntelRegistry intelRegistry,
			EntityResolver entityResolver,
			HeartbeatRepository heartbeatRepository,
			@Value("${spring.threads.virtual.enabled:false}") boolean virtualThreadsEnabled) {
		this.properties = properties;
		this.jdbcTemplate = jdbcTemplate;
		this.dataSource = dataSource;
		this.flyway = flyway;
		this.collectorScheduler = collectorScheduler;
		this.rollupAggregationService = rollupAggregationService;
		this.crawlerFeedRepository = crawlerFeedRepository;
		this.collectorPollerService = collectorPollerService;
		this.mmdbProvider = mmdbProvider;
		this.asnClassifierService = asnClassifierService;
		this.intelRegistry = intelRegistry;
		this.entityResolver = entityResolver;
		this.heartbeatRepository = heartbeatRepository;
		this.virtualThreadsEnabled = virtualThreadsEnabled;
	}

	public SystemStatusDto getSystemStatus() {
		return new SystemStatusDto(
				buildConfigInfo(),
				buildDatabaseInfo(),
				buildSchedulerInfo(),
				buildThreatIntelInfo(),
				buildRuntimeInfo(),
				buildFleetHealthInfo()
		);
	}

	private SystemStatusDto.ConfigInfo buildConfigInfo() {
		String cfgFile = properties.getConfigFile();
		boolean exists = false;
		String absPath = null;
		if (cfgFile != null && !cfgFile.isBlank()) {
			File f = new File(cfgFile);
			exists = f.exists();
			absPath = f.getAbsolutePath();
		}

		List<SystemStatusDto.EndpointDisplayInfo> endpointDisplays = new ArrayList<>();
		for (EndpointConfig ep : properties.getEndpoints()) {
			if (ep != null) {
				endpointDisplays.add(new SystemStatusDto.EndpointDisplayInfo(
						ep.getName() != null ? ep.getName() : "Unnamed",
						ep.getUrl(),
						ep.isEnabled(),
						ep.isPollIntermediateSlots(),
						ep.getToken() != null && !ep.getToken().isBlank(),
						ep.getValveNames()
				));
			}
		}

		int ttlDays = properties.getEnrichment() != null ? properties.getEnrichment().getTtlDays() : 30;

		return new SystemStatusDto.ConfigInfo(
				cfgFile,
				exists,
				absPath,
				properties.getPollIntervalSeconds(),
				properties.isParallelFleetPolling(),
				properties.getSlowPollThresholdMs(),
				properties.getRetentionDays(),
				properties.getPollLogRetentionDays(),
				properties.getEntityRetentionDays(),
				properties.isRollupEnabled(),
				properties.getRollupWindowMinutes(),
				properties.getRollupRetentionDays(),
				ttlDays,
				properties.isDemoMode(),
				properties.getDefaultValveRules(),
				properties.getValveRules(),
				endpointDisplays
		);
	}

	private SystemStatusDto.DatabaseInfo buildDatabaseInfo() {
		String engine = "Unknown";
		String rawUrl = "";
		if (dataSource instanceof HikariDataSource hikari) {
			rawUrl = hikari.getJdbcUrl();
			engine = hikari.getDriverClassName() != null && hikari.getDriverClassName().contains("sqlite")
					? "SQLite" : (hikari.getDriverClassName() != null && hikari.getDriverClassName().contains("postgresql") ? "PostgreSQL" : "RDBMS");
		}
		String sanitizedUrl = sanitizeJdbcUrl(rawUrl);

		boolean isSqlite = rawUrl != null && rawUrl.startsWith("jdbc:sqlite:");
		String sqliteFilePath = null;
		long sqliteFileSizeBytes = 0;
		String sqliteFileSizeFormatted = "N/A";
		Instant sqliteLastModified = null;

		if (isSqlite) {
			String pathPart = rawUrl.substring("jdbc:sqlite:".length());
			int qIdx = pathPart.indexOf('?');
			if (qIdx >= 0) {
				pathPart = pathPart.substring(0, qIdx);
			}
			File dbFile = new File(pathPart);
			sqliteFilePath = dbFile.getAbsolutePath();
			if (dbFile.exists() && dbFile.isFile()) {
				sqliteFileSizeBytes = dbFile.length();
				sqliteFileSizeFormatted = formatBytes(sqliteFileSizeBytes);
				sqliteLastModified = Instant.ofEpochMilli(dbFile.lastModified());
			}
		}

		Map<String, Long> tableCounts = new LinkedHashMap<>();
		tableCounts.put("slot_snapshots", countTable("slot_snapshots"));
		tableCounts.put("client_events", countTable("client_events"));
		tableCounts.put("client_subnet_rollups", countTable("client_subnet_rollups"));
		tableCounts.put("network_entity", countTable("network_entity"));
		tableCounts.put("poll_event_log", countTable("poll_event_log"));
		tableCounts.put("intel_range", countTable("intel_range"));
		tableCounts.put("crawler_feeds", countTable("crawler_feeds"));

		SystemStatusDto.HikariPoolInfo hikariInfo = null;
		if (dataSource instanceof HikariDataSource hikari) {
			int maxPool = hikari.getMaximumPoolSize();
			HikariPoolMXBean poolBean = hikari.getHikariPoolMXBean();
			if (poolBean != null) {
				hikariInfo = new SystemStatusDto.HikariPoolInfo(
						poolBean.getActiveConnections(),
						poolBean.getIdleConnections(),
						poolBean.getTotalConnections(),
						maxPool,
						poolBean.getThreadsAwaitingConnection()
				);
			} else {
				hikariInfo = new SystemStatusDto.HikariPoolInfo(0, 0, 0, maxPool, 0);
			}
		}

		SystemStatusDto.FlywayInfo flywayInfo = null;
		if (flyway != null) {
			try {
				MigrationInfo current = flyway.info().current();
				if (current != null) {
					flywayInfo = new SystemStatusDto.FlywayInfo(
							current.getVersion() != null ? current.getVersion().getVersion() : "Unknown",
							current.getDescription(),
							current.getInstalledOn() != null ? current.getInstalledOn().toString() : null
					);
				}
			} catch (Exception e) {
				log.debug("Unable to read Flyway info: {}", e.getMessage());
			}
		}

		return new SystemStatusDto.DatabaseInfo(
				engine,
				sanitizedUrl,
				isSqlite,
				sqliteFilePath,
				sqliteFileSizeBytes,
				sqliteFileSizeFormatted,
				sqliteLastModified,
				tableCounts,
				hikariInfo,
				flywayInfo
		);
	}

	private SystemStatusDto.SchedulerInfo buildSchedulerInfo() {
		CollectorScheduler.RetentionCleanupResult retentionResult = collectorScheduler != null
				? collectorScheduler.getLastRetentionResult() : null;
		Instant lastRetentionRun = retentionResult != null ? retentionResult.executedAt() : null;
		String lastRetentionSummary = retentionResult != null
				? String.format(Locale.ROOT, "Purged %d snapshots, %d events, %d logs, %d orphan entities (%dms)",
				retentionResult.deletedSlots(), retentionResult.deletedEvents(),
				retentionResult.deletedLogs(), retentionResult.deletedEntities(), retentionResult.durationMs())
				: "Pending next scheduled run (daily at 03:00)";

		RollupAggregationService.RollupExecutionResult rollupResult = rollupAggregationService != null
				? rollupAggregationService.getLastRollupResult() : null;
		Instant lastRollupRun = rollupResult != null ? rollupResult.executedAt() : null;
		String lastRollupSummary = rollupResult != null
				? String.format(Locale.ROOT, "Persisted %d subnet rollups (%dms)",
				rollupResult.persistedRollups(), rollupResult.durationMs())
				: (properties.isRollupEnabled() ? "Pending next scheduled run (every 15 min)" : "Subnet Rollup disabled");

		String crawlerCron = properties.getEnrichment() != null && properties.getEnrichment().getCrawlerSyncCron() != null
				? properties.getEnrichment().getCrawlerSyncCron() : "0 0 4 * * *";
		boolean crawlerEnabled = properties.getEnrichment() != null && properties.getEnrichment().isCrawlerSyncEnabled();

		Instant lastCrawlerSync = null;
		int activeFeeds = 0;
		if (crawlerFeedRepository != null) {
			try {
				List<CrawlerFeed> feeds = crawlerFeedRepository.findAll();
				for (CrawlerFeed f : feeds) {
					if (f != null && !"DISABLED".equalsIgnoreCase(f.status())) {
						activeFeeds++;
					}
					if (f != null && f.lastSyncedAt() != null) {
						if (lastCrawlerSync == null || f.lastSyncedAt().isAfter(lastCrawlerSync)) {
							lastCrawlerSync = f.lastSyncedAt();
						}
					}
				}
			} catch (Exception ignored) {
			}
		}

		Instant lastFleetPoll = collectorPollerService != null ? collectorPollerService.getLastFleetPollTime() : null;

		return new SystemStatusDto.SchedulerInfo(
				"0 0 3 * * *",
				lastRetentionRun,
				lastRetentionSummary,
				"0 */15 * * * *",
				properties.getRollupWindowMinutes(),
				lastRollupRun,
				lastRollupSummary,
				crawlerCron,
				crawlerEnabled,
				lastCrawlerSync,
				activeFeeds,
				lastFleetPoll
		);
	}

	private SystemStatusDto.ThreatIntelInfo buildThreatIntelInfo() {
		boolean enabled = properties.getEnrichment() != null && properties.getEnrichment().isEnabled();
		int ttlDays = properties.getEnrichment() != null ? properties.getEnrichment().getTtlDays() : 30;

		String asnPath = properties.getEnrichment() != null ? properties.getEnrichment().getAsnDatabasePath() : null;
		SystemStatusDto.MmdbInfo asnMmdb = inspectMmdb(asnPath, mmdbProvider != null && mmdbProvider.hasAsnReader(),
				mmdbProvider != null ? mmdbProvider.getAsnMetadata() : null);

		String countryPath = properties.getEnrichment() != null ? properties.getEnrichment().getCountryDatabasePath() : null;
		SystemStatusDto.MmdbInfo countryMmdb = inspectMmdb(countryPath, mmdbProvider != null && mmdbProvider.hasCountryReader(),
				mmdbProvider != null ? mmdbProvider.getCountryMetadata() : null);

		String customAsnPath = properties.getEnrichment() != null ? properties.getEnrichment().getCustomDatacenterAsnsFile() : null;
		boolean customExists = false;
		if (customAsnPath != null && !customAsnPath.isBlank()) {
			customExists = new File(customAsnPath).exists();
		}
		int totalDatacenterAsns = asnClassifierService != null ? asnClassifierService.getHostingAsnCount() : 0;
		SystemStatusDto.CustomAsnInfo customAsns = new SystemStatusDto.CustomAsnInfo(customAsnPath, customExists, totalDatacenterAsns);

		int v4Ranges = intelRegistry != null ? intelRegistry.getV4RangeCount() : 0;
		int v6Ranges = intelRegistry != null ? intelRegistry.getV6RangeCount() : 0;
		int totalRanges = intelRegistry != null ? intelRegistry.size() : 0;

		int cacheSize = entityResolver != null ? entityResolver.getCacheSize() : 0;
		int maxCache = entityResolver != null ? entityResolver.getMaxCacheEntries() : 50_000;

		return new SystemStatusDto.ThreatIntelInfo(
				enabled,
				ttlDays,
				asnMmdb,
				countryMmdb,
				customAsns,
				v4Ranges,
				v6Ranges,
				totalRanges,
				cacheSize,
				maxCache
		);
	}

	private SystemStatusDto.MmdbInfo inspectMmdb(String path, boolean loaded, com.maxmind.db.Metadata metadata) {
		if (path == null || path.isBlank()) {
			return new SystemStatusDto.MmdbInfo("Not configured", false, false, 0, "N/A", null, null, null, null, null);
		}
		File f = new File(path);
		boolean exists = f.exists() && f.isFile();
		long size = exists ? f.length() : 0;
		String sizeFormatted = exists ? formatBytes(size) : "N/A";
		Instant lastMod = exists ? Instant.ofEpochMilli(f.lastModified()) : null;

		String dbType = metadata != null ? metadata.getDatabaseType() : null;
		Instant buildDate = metadata != null && metadata.getBuildDate() != null
				? metadata.getBuildDate().toInstant() : null;

		String buildDateFormatted = null;
		Long ageDays = null;
		Instant effectiveDate = buildDate != null ? buildDate : lastMod;
		if (effectiveDate != null) {
			long days = java.time.temporal.ChronoUnit.DAYS.between(effectiveDate, Instant.now());
			ageDays = Math.max(0, days);
			String dateStr = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd")
					.withZone(java.time.ZoneId.systemDefault())
					.format(effectiveDate);
			if (ageDays == 0) {
				buildDateFormatted = dateStr + " (heute)";
			} else if (ageDays == 1) {
				buildDateFormatted = dateStr + " (gestern)";
			} else {
				buildDateFormatted = dateStr + " (vor " + ageDays + " Tagen)";
			}
		}

		return new SystemStatusDto.MmdbInfo(
				path,
				loaded,
				exists,
				size,
				sizeFormatted,
				lastMod,
				dbType,
				buildDate,
				buildDateFormatted,
				ageDays
		);
	}

	private SystemStatusDto.RuntimeInfo buildRuntimeInfo() {
		String appVersion = getClass().getPackage() != null && getClass().getPackage().getImplementationVersion() != null
				? getClass().getPackage().getImplementationVersion() : "1.7.4-SNAPSHOT";

		String javaVersion = System.getProperty("java.version");
		String javaVendor = System.getProperty("java.vendor");
		String osName = System.getProperty("os.name");
		String osArch = System.getProperty("os.arch");
		int availableProcessors = Runtime.getRuntime().availableProcessors();

		RuntimeMXBean runtimeMx = ManagementFactory.getRuntimeMXBean();
		Instant startTime = Instant.ofEpochMilli(runtimeMx.getStartTime());
		long uptimeSec = runtimeMx.getUptime() / 1000;
		String uptimeFormatted = formatDuration(uptimeSec);

		long totalMem = Runtime.getRuntime().totalMemory();
		long freeMem = Runtime.getRuntime().freeMemory();
		long maxMem = Runtime.getRuntime().maxMemory();
		long usedMem = totalMem - freeMem;
		int heapPercent = maxMem > 0 ? (int) Math.round(((double) usedMem / maxMem) * 100) : 0;

		return new SystemStatusDto.RuntimeInfo(
				appVersion,
				javaVersion,
				javaVendor,
				virtualThreadsEnabled,
				osName,
				osArch,
				availableProcessors,
				startTime,
				uptimeSec,
				uptimeFormatted,
				usedMem,
				maxMem,
				formatBytes(usedMem),
				formatBytes(maxMem),
				heapPercent
		);
	}

	private SystemStatusDto.FleetHealthInfo buildFleetHealthInfo() {
		List<EndpointConfig> allEndpoints = properties.getEndpoints();
		int total = allEndpoints.size();
		int enabled = (int) allEndpoints.stream().filter(EndpointConfig::isEnabled).count();

		int online = 0;
		int offline = 0;
		if (heartbeatRepository != null) {
			try {
				List<EndpointHeartbeat> heartbeats = heartbeatRepository.findAll();
				for (EndpointHeartbeat hb : heartbeats) {
					if (hb.online()) {
						online++;
					} else {
						offline++;
					}
				}
			} catch (Exception ignored) {
			}
		}

		return new SystemStatusDto.FleetHealthInfo(total, enabled, online, offline);
	}

	private long countTable(String tableName) {
		try {
			Long count = jdbcTemplate.queryForObject("SELECT count(*) FROM " + tableName, Long.class);
			return count != null ? count : 0L;
		} catch (Exception e) {
			log.debug("Could not count table {}: {}", tableName, e.getMessage());
			return 0L;
		}
	}

	private String sanitizeJdbcUrl(String url) {
		if (url == null || url.isBlank()) {
			return "";
		}
		// Mask password query param if present
		return url.replaceAll("(?i)(password=)[^&;]+", "$1********");
	}

	public static String formatBytes(long bytes) {
		if (bytes < 1024) {
			return bytes + " B";
		} else if (bytes < 1024 * 1024) {
			return String.format(Locale.ROOT, "%.1f KB", bytes / 1024.0);
		} else if (bytes < 1024L * 1024 * 1024) {
			return String.format(Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0));
		} else {
			return String.format(Locale.ROOT, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
		}
	}

	public static String formatDuration(long seconds) {
		long days = seconds / 86400;
		long hours = (seconds % 86400) / 3600;
		long minutes = (seconds % 3600) / 60;
		long secs = seconds % 60;

		if (days > 0) {
			return String.format(Locale.ROOT, "%dd %dh %dm", days, hours, minutes);
		} else if (hours > 0) {
			return String.format(Locale.ROOT, "%dh %dm %ds", hours, minutes, secs);
		} else if (minutes > 0) {
			return String.format(Locale.ROOT, "%dm %ds", minutes, secs);
		} else {
			return secs + "s";
		}
	}
}
