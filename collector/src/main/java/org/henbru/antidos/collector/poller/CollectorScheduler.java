package org.henbru.antidos.collector.poller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Scheduled runner invoking periodic polling cycles and daily data retention cleanups.
 */
@Component
public class CollectorScheduler {

	private static final Logger log = LoggerFactory.getLogger(CollectorScheduler.class);

	private final CollectorPollerService pollerService;
	private final SlotSnapshotRepository slotSnapshotRepository;
	private final ClientEventRepository clientEventRepository;
	private final org.henbru.antidos.collector.storage.PollEventLogRepository pollEventLogRepository;
	private final org.henbru.antidos.collector.enrichment.CrawlerSyncService crawlerSyncService;
	private final org.henbru.antidos.collector.storage.NetworkEntityRepository networkEntityRepository;
	private final org.henbru.antidos.collector.enrichment.EntityResolver entityResolver;
	private final org.henbru.antidos.collector.report.DailyReportService dailyReportService;
	private final CollectorProperties properties;

	public CollectorScheduler(
			CollectorPollerService pollerService,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			org.henbru.antidos.collector.storage.PollEventLogRepository pollEventLogRepository,
			org.henbru.antidos.collector.enrichment.CrawlerSyncService crawlerSyncService,
			org.henbru.antidos.collector.storage.NetworkEntityRepository networkEntityRepository,
			org.henbru.antidos.collector.enrichment.EntityResolver entityResolver,
			org.henbru.antidos.collector.report.DailyReportService dailyReportService,
			CollectorProperties properties) {
		this.pollerService = pollerService;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
		this.pollEventLogRepository = pollEventLogRepository;
		this.crawlerSyncService = crawlerSyncService;
		this.networkEntityRepository = networkEntityRepository;
		this.entityResolver = entityResolver;
		this.dailyReportService = dailyReportService;
		this.properties = properties;
	}

	@jakarta.annotation.PostConstruct
	@SuppressWarnings("null")
	public void logConfigurationSummary() {
		java.util.List<org.henbru.antidos.collector.config.EndpointConfig> endpoints = properties.getEndpoints();
		if (endpoints.isEmpty()) {
			log.info("Collector started: 0 endpoints configured (create 'collector-config.yaml' to add Tomcat servers).");
		} else {
			log.info("Collector started: Loaded {} configured endpoint(s): {}",
					endpoints.size(),
					endpoints.stream().map(org.henbru.antidos.collector.config.EndpointConfig::getName).toList());
		}
	}

	@Scheduled(fixedDelayString = "#{${collector.poll-interval-seconds:15} * 1000}", initialDelay = 2000)
	public void runScheduledPoll() {
		try {
			pollerService.pollFleet();
		} catch (Exception e) {
			log.error("Unexpected error in collector poll cycle: {}", e.getMessage(), e);
		}
	}

	public record RetentionCleanupResult(
			Instant executedAt,
			int deletedSlots,
			int deletedEvents,
			int deletedLogs,
			int deletedEntities,
			int expiredEntities,
			long durationMs
	) {}

	private volatile RetentionCleanupResult lastRetentionResult;

	public RetentionCleanupResult getLastRetentionResult() {
		return lastRetentionResult;
	}

	/**
	 * Daily retention cleanup: deletes snapshots, client events, and poll event logs older than configured retention days.
	 * Also purges unreferenced/orphan network entities and marks stale enrichments (> TTL) for re-resolution.
	 */
	@Scheduled(cron = "0 0 3 * * *") // Daily at 03:00 AM
	public RetentionCleanupResult runRetentionCleanup() {
		long start = System.currentTimeMillis();
		int days = properties.getRetentionDays() > 0 ? properties.getRetentionDays() : 30;
		Instant cutoff = Instant.now().minus(days, ChronoUnit.DAYS);
		log.info("Running daily data retention cleanup for records older than {} days (cutoff: {})", days, cutoff);

		int deletedSlots = slotSnapshotRepository.deleteOlderThan(cutoff);
		int deletedEvents = clientEventRepository.deleteOlderThan(cutoff);

		int logDays = properties.getPollLogRetentionDays() > 0 ? properties.getPollLogRetentionDays() : 1;
		Instant logCutoff = Instant.now().minus(logDays, ChronoUnit.DAYS);
		int deletedLogs = pollEventLogRepository.deleteOlderThan(logCutoff);

		// Clean up unreferenced/orphan network entities older than entity-retention-days
		int entityDays = properties.getEntityRetentionDays() > 0 ? properties.getEntityRetentionDays() : Math.max(days, 30);
		Instant entityCutoff = Instant.now().minus(entityDays, ChronoUnit.DAYS);
		int deletedEntities = networkEntityRepository != null ? networkEntityRepository.deleteOrphans(entityCutoff) : 0;

		// Expire stale enrichment entries past TTL (e.g. 30 days) to trigger re-enrichment against updated MMDB / feeds
		int ttlDays = properties.getEnrichment() != null && properties.getEnrichment().getTtlDays() > 0
				? properties.getEnrichment().getTtlDays() : 30;
		Instant ttlCutoff = Instant.now().minus(ttlDays, ChronoUnit.DAYS);
		int expiredEntities = networkEntityRepository != null ? networkEntityRepository.markExpiredEnrichment(ttlCutoff) : 0;
		if (expiredEntities > 0 && entityResolver != null) {
			entityResolver.clearCache();
		}

		long durationMs = System.currentTimeMillis() - start;
		RetentionCleanupResult result = new RetentionCleanupResult(
				Instant.now(), deletedSlots, deletedEvents, deletedLogs, deletedEntities, expiredEntities, durationMs
		);
		this.lastRetentionResult = result;

		log.info("Retention cleanup completed in {}ms: purged {} slot snapshots, {} client events, {} poll event logs, {} orphan entities, and expired {} stale entities for re-enrichment",
				durationMs, deletedSlots, deletedEvents, deletedLogs, deletedEntities, expiredEntities);
		return result;
	}

	/**
	 * Daily operational report generation: runs at 01:00 AM (2 hours prior to 03:00 AM retention cleanup)
	 * to compile and persist normalized fleet metrics and incident forensics for yesterday.
	 */
	@Scheduled(cron = "${collector.report.cron:0 0 1 * * *}")
	public void runScheduledDailyReport() {
		if (properties.isReportEnabled() && dailyReportService != null) {
			try {
				dailyReportService.generateReportForYesterday();
			} catch (Exception e) {
				log.error("Unexpected error in scheduled daily report generation: {}", e.getMessage(), e);
			}
		}
	}

	/**
	 * Daily synchronization of verified search engine and AI crawler IP ranges.
	 */
	@Scheduled(cron = "${collector.enrichment.crawler-sync-cron:0 0 4 * * *}")
	public void runScheduledCrawlerSync() {
		try {
			crawlerSyncService.syncAll();
		} catch (Exception e) {
			log.error("Unexpected error in scheduled crawler synchronization: {}", e.getMessage(), e);
		}
	}

	/**
	 * Hourly catch-up synchronization for crawler feeds that previously failed.
	 */
	@Scheduled(cron = "${collector.enrichment.crawler-retry-cron:0 15 * * * *}")
	public void runScheduledCrawlerRetry() {
		if (crawlerSyncService == null) {
			return;
		}
		try {
			int recovered = crawlerSyncService.syncFailedFeeds();
			if (recovered > 0) {
				log.info("Scheduled crawler catch-up sync recovered {} previously failed feed(s)", recovered);
			}
		} catch (Exception e) {
			log.error("Unexpected error in scheduled crawler retry synchronization: {}", e.getMessage(), e);
		}
	}
}
