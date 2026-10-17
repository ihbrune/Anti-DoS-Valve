package org.henbru.antidos.collector;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.model.BlockedClientEvent;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class DatabaseMigrationAndRepositoryTest {

	@Autowired
	private HeartbeatRepository heartbeatRepository;

	@Autowired
	private SlotSnapshotRepository slotSnapshotRepository;

	@Autowired
	private ClientEventRepository clientEventRepository;

	@Test
	void testHeartbeatRepositoryUpsertAndFind() {
		Instant now = Instant.now();
		EndpointHeartbeat hb = new EndpointHeartbeat(
				"TEST-NODE-1", "http://localhost:8080/antidos-status", true, now, now, null, 15L, 2);

		heartbeatRepository.upsert(hb);

		Optional<EndpointHeartbeat> found = heartbeatRepository.findByServerId("TEST-NODE-1");
		assertTrue(found.isPresent());
		assertEquals("http://localhost:8080/antidos-status", found.get().url());
		assertTrue(found.get().online());
		assertEquals(2, found.get().valvesCount());

		// Test updating heartbeat on failure
		EndpointHeartbeat failure = found.get().failure(Instant.now(), "Connection timed out");
		heartbeatRepository.upsert(failure);

		Optional<EndpointHeartbeat> updated = heartbeatRepository.findByServerId("TEST-NODE-1");
		assertTrue(updated.isPresent());
		assertFalse(updated.get().online());
		assertEquals("Connection timed out", updated.get().lastError());
		assertNotNull(updated.get().lastSuccessAt()); // Retains last success!
	}

	@Test
	void testSlotSnapshotRepositoryUpsertAndAggregates() {
		Instant start = Instant.now().minus(5, ChronoUnit.MINUTES);
		Instant end = Instant.now().minus(4, ChronoUnit.MINUTES);
		Instant poll = Instant.now();

		SlotSnapshot s1 = new SlotSnapshot(
				null, "TEST-NODE-1", "VALVE-A", 1000L, start, end, 500L, 20, 2, true, poll);
		slotSnapshotRepository.upsert(s1);

		Optional<Long> latestKey = slotSnapshotRepository.findLatestSlotKey("TEST-NODE-1", "VALVE-A");
		assertTrue(latestKey.isPresent());
		assertEquals(1000L, latestKey.get());

		// Upsert updated total requests (idempotency)
		SlotSnapshot s1Updated = new SlotSnapshot(
				null, "TEST-NODE-1", "VALVE-A", 1000L, start, end, 600L, 25, 3, true, poll);
		slotSnapshotRepository.upsert(s1Updated);

		List<SlotSnapshot> recent = slotSnapshotRepository.findRecent("TEST-NODE-1", "VALVE-A", 10);
		assertFalse(recent.isEmpty());
		assertEquals(600L, recent.getFirst().totalRequests());

		long sumReq = slotSnapshotRepository.sumRequestsSince(Instant.now().minus(1, ChronoUnit.HOURS));
		assertTrue(sumReq >= 600L);
	}

	@Test
	void testClientEventRepositoryBatchUpsertAndAnalytics() {
		Instant now = Instant.now();
		BlockedClientEvent e1 = new BlockedClientEvent(
				null, "NODE-A", "VALVE-1", 100L, now, "198.51.100.42", 50, 10, true, true, now);
		BlockedClientEvent e2 = new BlockedClientEvent(
				null, "NODE-B", "VALVE-1", 100L, now, "198.51.100.42", 70, 0, true, true, now);
		BlockedClientEvent e3 = new BlockedClientEvent(
				null, "NODE-A", "VALVE-1", 100L, now, "203.0.113.99", 20, 0, true, true, now);

		clientEventRepository.batchUpsert(List.of(e1, e2, e3));

		// Top offender analytics
		List<TopOffenderSummary> top = clientEventRepository.findTopOffenders(Instant.now().minus(1, ChronoUnit.HOURS), 10);
		assertFalse(top.isEmpty());

		TopOffenderSummary primary = top.getFirst();
		assertEquals("198.51.100.42", primary.clientKey());
		assertEquals(130L, primary.totalBlockedRequests()); // 60 from NODE-A + 70 from NODE-B
		assertEquals(2, primary.distinctServersTargeted()); // Targeted both NODE-A and NODE-B!

		// Count distinct clients
		long distinct = clientEventRepository.countDistinctBlockedClientsSince(Instant.now().minus(1, ChronoUnit.HOURS));
		assertTrue(distinct >= 2L);
	}
}
