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
	private final CollectorProperties properties;

	public CollectorScheduler(
			CollectorPollerService pollerService,
			SlotSnapshotRepository slotSnapshotRepository,
			ClientEventRepository clientEventRepository,
			CollectorProperties properties) {
		this.pollerService = pollerService;
		this.slotSnapshotRepository = slotSnapshotRepository;
		this.clientEventRepository = clientEventRepository;
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

	/**
	 * Daily retention cleanup: deletes snapshots and client events older than configured retentionDays.
	 */
	@Scheduled(cron = "0 0 3 * * *") // Daily at 03:00 AM
	public void runRetentionCleanup() {
		int days = properties.getRetentionDays() > 0 ? properties.getRetentionDays() : 30;
		Instant cutoff = Instant.now().minus(days, ChronoUnit.DAYS);
		log.info("Running daily data retention cleanup for records older than {} days (cutoff: {})", days, cutoff);

		int deletedSlots = slotSnapshotRepository.deleteOlderThan(cutoff);
		int deletedEvents = clientEventRepository.deleteOlderThan(cutoff);
		log.info("Retention cleanup completed: purged {} slot snapshots and {} client events", deletedSlots, deletedEvents);
	}
}
