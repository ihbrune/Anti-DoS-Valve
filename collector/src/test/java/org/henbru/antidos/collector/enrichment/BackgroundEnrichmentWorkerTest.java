package org.henbru.antidos.collector.enrichment;

import java.time.Instant;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.BlockedClientEvent;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.EnrichmentStatus;
import org.henbru.antidos.collector.model.IpEnrichmentResult;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BackgroundEnrichmentWorkerTest {

	@Test
	@SuppressWarnings("unchecked")
	void testEnrichPendingBatch() {
		ClientEventRepository repo = mock(ClientEventRepository.class);
		IpEnrichmentService enrichmentService = mock(IpEnrichmentService.class);
		CollectorProperties properties = new CollectorProperties();

		BlockedClientEvent event1 = new BlockedClientEvent(
				1L, "Node-1", "VALVE", 100L, Instant.now(), "198.51.100.42",
				10, 0, true, true, Instant.now()
		);
		assertEquals(EnrichmentStatus.PENDING, event1.enrichmentStatus());

		when(repo.findPendingEnrichment(250)).thenReturn(List.of(event1));
		when(enrichmentService.enrich("198.51.100.42")).thenReturn(
				new IpEnrichmentResult(24940L, "Hetzner Online GmbH", "DE", ClientType.DATACENTER)
		);

		BackgroundEnrichmentWorker worker = new BackgroundEnrichmentWorker(repo, enrichmentService, properties);
		int processed = worker.enrichPendingBatch(250);

		assertEquals(1, processed);

		ArgumentCaptor<List<BlockedClientEvent>> captor = ArgumentCaptor.forClass(List.class);
		verify(repo).batchUpdateEnrichment(captor.capture());

		List<BlockedClientEvent> updated = captor.getValue();
		assertEquals(1, updated.size());
		BlockedClientEvent enriched = updated.get(0);
		assertEquals(24940L, enriched.asn());
		assertEquals("Hetzner Online GmbH", enriched.asOrg());
		assertEquals("DE", enriched.countryCode());
		assertEquals(ClientType.DATACENTER, enriched.clientType());
		assertEquals(EnrichmentStatus.ENRICHED, enriched.enrichmentStatus());
	}
}
