package org.henbru.antidos.collector.enrichment;

import java.util.ArrayList;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.IpEnrichmentResult;
import org.henbru.antidos.collector.model.NetworkEntity;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.NetworkEntityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Background worker that continuously enriches pending NetworkEntity records and ClientEvents
 * with ASN, AS Organization, Geolocation, and Client Classification without blocking polling threads.
 */
@Component
public class BackgroundEnrichmentWorker {

	private static final Logger log = LoggerFactory.getLogger(BackgroundEnrichmentWorker.class);

	private static final int BATCH_SIZE = 250;

	private final ClientEventRepository clientEventRepository;
	private final IpEnrichmentService enrichmentService;
	private final NetworkEntityRepository networkEntityRepository;
	private final EntityResolver entityResolver;
	private final CollectorProperties properties;

	@Autowired
	public BackgroundEnrichmentWorker(
			ClientEventRepository clientEventRepository,
			IpEnrichmentService enrichmentService,
			NetworkEntityRepository networkEntityRepository,
			EntityResolver entityResolver,
			CollectorProperties properties) {
		this.clientEventRepository = clientEventRepository;
		this.enrichmentService = enrichmentService;
		this.networkEntityRepository = networkEntityRepository;
		this.entityResolver = entityResolver;
		this.properties = properties;
	}

	public BackgroundEnrichmentWorker(
			ClientEventRepository clientEventRepository,
			IpEnrichmentService enrichmentService,
			CollectorProperties properties) {
		this(clientEventRepository, enrichmentService, null, null, properties);
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
		int enrichedEntities = 0;

		// 1. Enrich pending NetworkEntity instances
		if (networkEntityRepository != null && entityResolver != null) {
			List<NetworkEntity> pendingEntities = networkEntityRepository.findPendingEnrichment(limit);
			if (pendingEntities != null && !pendingEntities.isEmpty()) {
				for (NetworkEntity entity : pendingEntities) {
					try {
						entityResolver.resolve(entity);
						enrichedEntities++;
					} catch (Exception e) {
						log.warn("Failed to enrich network entity {}: {}", entity.clientKey(), e.getMessage());
					}
				}
				log.debug("Enriched batch of {} network entities in background", enrichedEntities);
			}
		}

		// 2. Enrich pending ClientEvent records (ensures backwards compatibility and entity_id linking)
		List<ClientEvent> pending = clientEventRepository.findPendingEnrichment(limit);
		if (pending == null || pending.isEmpty()) {
			return enrichedEntities;
		}

		List<ClientEvent> enrichedList = new ArrayList<>(pending.size());
		for (ClientEvent event : pending) {
			try {
				Long entityId = event.entityId();
				if (entityId == null && entityResolver != null) {
					NetworkEntity entity = entityResolver.getOrCreate(event.clientKey(), event.slotTime());
					entityId = entity.id();
				}
				IpEnrichmentResult result = enrichmentService.enrich(event.clientKey());
				ClientEvent enriched = event.withEnrichment(result);
				if (entityId != null) {
					enriched = enriched.withEntityId(entityId);
				}
				enrichedList.add(enriched);
			} catch (Exception e) {
				log.warn("Failed to enrich client {}: {}", event.clientKey(), e.getMessage());
			}
		}

		if (!enrichedList.isEmpty()) {
			clientEventRepository.batchUpdateEnrichment(enrichedList);
			log.debug("Enriched batch of {} client events in background", enrichedList.size());
		}

		return enrichedList.size() + enrichedEntities;
	}
}
