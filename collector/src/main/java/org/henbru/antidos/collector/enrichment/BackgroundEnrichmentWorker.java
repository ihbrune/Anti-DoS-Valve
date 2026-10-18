package org.henbru.antidos.collector.enrichment;

import java.util.ArrayList;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.BlockedClientEvent;
import org.henbru.antidos.collector.model.IpEnrichmentResult;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Background worker running on Virtual Threads to enrich newly ingested blocked client events
 * without blocking the real-time collector polling engine.
 */
@Component
public class BackgroundEnrichmentWorker {

	private static final Logger log = LoggerFactory.getLogger(BackgroundEnrichmentWorker.class);

	private static final int BATCH_SIZE = 250;

	private final ClientEventRepository clientEventRepository;
	private final IpEnrichmentService enrichmentService;
	private final CollectorProperties properties;

	public BackgroundEnrichmentWorker(
			ClientEventRepository clientEventRepository,
			IpEnrichmentService enrichmentService,
			CollectorProperties properties) {
		this.clientEventRepository = clientEventRepository;
		this.enrichmentService = enrichmentService;
		this.properties = properties;
	}

	@Scheduled(fixedDelay = 2000, initialDelay = 3000)
	public void processPendingEnrichments() {
		if (!properties.getEnrichment().isEnabled()) {
			return;
		}
		try {
			enrichPendingBatch(BATCH_SIZE);
		} catch (Exception e) {
			log.error("Error in background IP enrichment worker: {}", e.getMessage(), e);
		}
	}

	public int enrichPendingBatch(int limit) {
		List<BlockedClientEvent> pending = clientEventRepository.findPendingEnrichment(limit);
		if (pending == null || pending.isEmpty()) {
			return 0;
		}

		List<BlockedClientEvent> enrichedList = new ArrayList<>(pending.size());
		for (BlockedClientEvent event : pending) {
			try {
				IpEnrichmentResult result = enrichmentService.enrich(event.clientKey());
				enrichedList.add(event.withEnrichment(result));
			} catch (Exception e) {
				log.warn("Failed to enrich client {}: {}", event.clientKey(), e.getMessage());
			}
		}

		if (!enrichedList.isEmpty()) {
			clientEventRepository.batchUpdateEnrichment(enrichedList);
			log.debug("Enriched batch of {} blocked client events in background", enrichedList.size());
		}

		return enrichedList.size();
	}
}
