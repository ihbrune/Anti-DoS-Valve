package org.henbru.antidos.collector;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.henbru.antidos.collector.model.BlockedClientEvent;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.PollEventLog;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.PollEventLogRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class DatabaseMigrationAndRepositoryTest {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private HeartbeatRepository heartbeatRepository;

	@Autowired
	private SlotSnapshotRepository slotSnapshotRepository;

	@Autowired
	private ClientEventRepository clientEventRepository;

	@Autowired
	private PollEventLogRepository pollEventLogRepository;

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

		// Verify finding recent slots without valve filter (all valves on server)
		List<SlotSnapshot> recentNoValve = slotSnapshotRepository.findRecent("TEST-NODE-1", null, 10);
		assertFalse(recentNoValve.isEmpty());
		assertEquals("VALVE-A", recentNoValve.getFirst().valveName());

		List<SlotSnapshot> recentEmptyValve = slotSnapshotRepository.findRecent("TEST-NODE-1", "", 10);
		assertFalse(recentEmptyValve.isEmpty());

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

	@Test
	void testClientEventRepositoryAdvancedFilteringAndSubnetRollup() {
		Instant now = Instant.now();
		BlockedClientEvent e1 = new BlockedClientEvent(
				null, "SERVER-PROD-1", "VALVE-API", 200L, now.minus(30, ChronoUnit.MINUTES), "198.51.100.10", 30, 0, true, true, now);
		BlockedClientEvent e2 = new BlockedClientEvent(
				null, "SERVER-PROD-2", "VALVE-API", 200L, now.minus(25, ChronoUnit.MINUTES), "198.51.100.25", 50, 0, true, true, now);
		BlockedClientEvent e3 = new BlockedClientEvent(
				null, "SERVER-STAGE", "VALVE-API", 200L, now.minus(20, ChronoUnit.MINUTES), "198.51.100.99", 100, 0, true, true, now);
		BlockedClientEvent e4 = new BlockedClientEvent(
				null, "SERVER-PROD-1", "VALVE-ADMIN", 200L, now.minus(15, ChronoUnit.MINUTES), "198.51.100.10", 40, 0, true, true, now);
		BlockedClientEvent e5 = new BlockedClientEvent(
				null, "SERVER-PROD-1", "VALVE-API", 200L, now.minus(10, ChronoUnit.MINUTES), "203.0.113.5", 80, 0, true, true, now);

		clientEventRepository.batchUpsert(List.of(e1, e2, e3, e4, e5));

		// 1. Multi-server + multi-valve filter: Only PROD-1 and PROD-2, only VALVE-API
		List<BlockedClientEvent> filtered = clientEventRepository.findRecentEventsFiltered(
				List.of("SERVER-PROD-1", "SERVER-PROD-2"),
				List.of("VALVE-API"),
				now.minus(1, ChronoUnit.HOURS),
				now,
				(String) null,
				50,
				0
		);
		// Should include e1, e2, e5 (e3 is SERVER-STAGE, e4 is VALVE-ADMIN)
		assertEquals(3, filtered.size());

		// 2. Subnet range search: search for "198.51.100.0/24" (or "198.51.100.")
		List<BlockedClientEvent> subnetHits = clientEventRepository.findRecentEventsFiltered(
				List.of("SERVER-PROD-1", "SERVER-PROD-2"),
				List.of("VALVE-API"),
				(Instant) null,
				(Instant) null,
				"198.51.100.",
				50,
				0
		);
		// Should match e1 (198.51.100.10) and e2 (198.51.100.25), but NOT e5 (203.0.113.5)
		assertEquals(2, subnetHits.size());

		// 3. Subnet Rollup in Top Offenders: Group by "SUBNET"
		List<TopOffenderSummary> subnetRollup = clientEventRepository.findTopOffendersFiltered(
				List.of("SERVER-PROD-1", "SERVER-PROD-2"),
				List.of("VALVE-API"),
				now.minus(1, ChronoUnit.HOURS),
				now,
				(String) null,
				"SUBNET",
				10
		);
		assertFalse(subnetRollup.isEmpty());
		// e1 (30 reqs) and e2 (50 reqs) are in same subnet 198.51.100.0/24 -> 80 reqs!
		// e5 (80 reqs) in 203.0.113.0/24
		TopOffenderSummary topSubnet = subnetRollup.stream()
				.filter(s -> "198.51.100.0/24".equals(s.clientKey()))
				.findFirst()
				.orElse(null);
		assertNotNull(topSubnet);
		assertEquals(80L, topSubnet.totalBlockedRequests());
		assertEquals(2, topSubnet.distinctServersTargeted()); // Targeted both PROD-1 and PROD-2!
	}

	@Test
	void testClientEventRepositoryClassificationAndAsnFilteringAndAsnRollup() {
		Instant now = Instant.now();
		BlockedClientEvent e1 = new BlockedClientEvent(
				null, "SERVER-PROD-1", "VALVE-API", 300L, now.minus(30, ChronoUnit.MINUTES), "198.51.100.1",
				4, 32, null, null, null, null, "198.51.100.0/24",
				50, 0, false, true, now,
				3320L, "Deutsche Telekom AG", "DE", ClientType.RESIDENTIAL, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		);
		BlockedClientEvent e2 = new BlockedClientEvent(
				null, "SERVER-PROD-2", "VALVE-API", 300L, now.minus(25, ChronoUnit.MINUTES), "198.51.100.2",
				4, 32, null, null, null, null, "198.51.100.0/24",
				70, 0, false, true, now,
				3320L, "Deutsche Telekom AG", "DE", ClientType.RESIDENTIAL, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		);
		BlockedClientEvent e3 = new BlockedClientEvent(
				null, "SERVER-PROD-1", "VALVE-API", 300L, now.minus(20, ChronoUnit.MINUTES), "203.0.113.10",
				4, 32, null, null, null, null, "203.0.113.0/24",
				100, 0, false, true, now,
				8075L, "Microsoft Corporation", "US", ClientType.DATACENTER, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		);
		BlockedClientEvent e4 = new BlockedClientEvent(
				null, "SERVER-PROD-1", "VALVE-API", 300L, now.minus(15, ChronoUnit.MINUTES), "10.68.1.1",
				4, 32, null, null, null, null, "10.68.1.0/24",
				20, 0, false, true, now,
				null, "Private Network", null, ClientType.PRIVATE_NETWORK, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		);

		clientEventRepository.batchUpsert(List.of(e1, e2, e3, e4));

		// 1. Filter by clientTypes = PRIVATE_NETWORK
		List<BlockedClientEvent> privateEvents = clientEventRepository.findRecentEventsFiltered(
				null, null, now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("PRIVATE_NETWORK"), null, 50, 0
		);
		assertTrue(privateEvents.stream().anyMatch(e -> "10.68.1.1".equals(e.clientKey())));
		assertTrue(privateEvents.stream().allMatch(e -> e.clientType() == ClientType.PRIVATE_NETWORK));

		// 2. Filter by numeric ASN = 3320
		List<BlockedClientEvent> telekomEvents = clientEventRepository.findRecentEventsFiltered(
				null, null, now.minus(1, ChronoUnit.HOURS), now, null,
				null, 3320L, 50, 0
		);
		assertEquals(2, telekomEvents.size());
		assertTrue(telekomEvents.stream().allMatch(e -> Long.valueOf(3320L).equals(e.asn())));

		// 3. Filter by query string "AS8075" (clientQuery automatic ASN parsing)
		List<BlockedClientEvent> msEvents = clientEventRepository.findRecentEventsFiltered(
				null, null, now.minus(1, ChronoUnit.HOURS), now, "AS8075",
				null, null, 50, 0
		);
		assertEquals(1, msEvents.size());
		assertEquals("203.0.113.10", msEvents.getFirst().clientKey());

		// 4. Top Offenders Rollup by ASN
		List<TopOffenderSummary> asnRollup = clientEventRepository.findTopOffendersFiltered(
				null, null, now.minus(1, ChronoUnit.HOURS), now, null,
				null, null, "ASN", 10
		);
		assertFalse(asnRollup.isEmpty());

		TopOffenderSummary as3320 = asnRollup.stream()
				.filter(o -> "AS3320".equals(o.clientKey()))
				.findFirst()
				.orElse(null);
		assertNotNull(as3320, "Should have grouped entries under AS3320");
		assertEquals(120L, as3320.totalBlockedRequests(), "Should sum 50 + 70 requests from e1 and e2");
		assertEquals(2, as3320.distinctClientsCount(), "Should have 2 distinct IPs in AS3320");
		assertEquals(2, as3320.distinctServersTargeted(), "Should span 2 servers (PROD-1, PROD-2)");
	}

	@Test
	void testPollEventLogRepositoryOperations() {
		Instant now = Instant.now();
		PollEventLog log1 = new PollEventLog(
				null, "NODE-A", "http://node-a:8080/antidos-status", now.minus(10, ChronoUnit.MINUTES),
				"SUCCESS", 200, 35L, 2, 2, 0, "Polled 2 valves", null
		);
		PollEventLog log2 = new PollEventLog(
				null, "NODE-B", "http://node-b:8080/antidos-status", now.minus(5, ChronoUnit.MINUTES),
				"ERROR", 0, 5002L, 0, 0, 0, "Connection refused", "Connection refused"
		);
		PollEventLog log3 = new PollEventLog(
				null, "NODE-A", "http://node-a:8080/antidos-status", now,
				"WARNING", 200, 1400L, 2, 2, 0, "Slow response: 1400 ms", null
		);

		pollEventLogRepository.insert(log1);
		pollEventLogRepository.insert(log2);
		pollEventLogRepository.insert(log3);

		// Query all recent
		List<PollEventLog> all = pollEventLogRepository.findRecent(null, "ALL", null, 10);
		assertTrue(all.size() >= 3);

		// Filter by ERROR
		List<PollEventLog> errors = pollEventLogRepository.findRecent(null, "ERROR", null, 10);
		assertTrue(errors.stream().anyMatch(e -> "NODE-B".equals(e.serverId()) && "ERROR".equals(e.status())));

		// Filter by server
		List<PollEventLog> nodeA = pollEventLogRepository.findRecent(null, "ALL", "NODE-A", 10);
		assertTrue(nodeA.stream().allMatch(e -> "NODE-A".equals(e.serverId())));

		// Cursor pagination using beforeId
		Long topId = all.getFirst().id();
		List<PollEventLog> paged = pollEventLogRepository.findRecent(topId, "ALL", null, 2);
		assertFalse(paged.isEmpty());
		assertTrue(paged.getFirst().id() < topId);

		// Count stats
		long errCount = pollEventLogRepository.countByStatusSince("ERROR", now.minus(1, ChronoUnit.HOURS));
		assertTrue(errCount >= 1L);

		// Delete retention older than 30 days
		PollEventLog veryOld = new PollEventLog(
				null, "NODE-OLD", "http://old:8080/antidos-status", now.minus(40, ChronoUnit.DAYS),
				"SUCCESS", 200, 30L, 1, 1, 0, "Old entry", null
		);
		pollEventLogRepository.insert(veryOld);
		int deletedOld = pollEventLogRepository.deleteOlderThan(now.minus(30, ChronoUnit.DAYS));
		assertTrue(deletedOld >= 1);
	}

	@Test
	void testLegacyEventWithNullRangesAndRepair() {
		Instant now = Instant.now();
		// Simulate a pre-V3 legacy row with null ranges and subnet_group = client_key
		jdbcTemplate.update("""
				INSERT INTO blocked_client_events (
				    server_id, valve_name, slot_key, slot_time, client_key,
				    ip_version, cidr_prefix, ip_v4_start, ip_v4_end, ip_v6_start, ip_v6_end, subnet_group,
				    request_count, retained_count, is_locked, is_completed, last_updated_at,
				    client_type, enrichment_status
				) VALUES (
				    'LEGACY-SERVER', 'LEGACY-VALVE', 999999, ?, '52.167.114.213',
				    4, 32, NULL, NULL, NULL, NULL, '52.167.114.213',
				    42, 0, 1, 1, ?,
				    'UNKNOWN', 'PENDING'
				)
				""", Timestamp.from(now), Timestamp.from(now));

		// 1. Searching for exact IP "52.167.114.213" should find the legacy row even before repair!
		List<BlockedClientEvent> ipHits = clientEventRepository.findRecentEventsFiltered(
				List.of("LEGACY-SERVER"), null, null, null, "52.167.114.213", 10, 0
		);
		assertFalse(ipHits.isEmpty(), "Should find legacy event when searching for exact client IP");
		assertEquals("52.167.114.213", ipHits.getFirst().clientKey());
		// ROW_MAPPER dynamic fallback should already present canonical subnetGroup
		assertEquals("52.167.114.0/24", ipHits.getFirst().subnetGroup());

		// 2. Searching for shorthand "52.167.114" should also find it
		List<BlockedClientEvent> shorthandHits = clientEventRepository.findRecentEventsFiltered(
				List.of("LEGACY-SERVER"), null, null, null, "52.167.114", 10, 0
		);
		assertFalse(shorthandHits.isEmpty(), "Should find legacy event when searching for prefix '52.167.114'");

		// 3. Trigger repairUnnormalizedEvents
		clientEventRepository.repairUnnormalizedEvents();

		// 4. Verify DB row was updated with canonical IP range and subnet_group
		Map<String, Object> repairedRow = jdbcTemplate.queryForMap(
				"SELECT subnet_group, ip_v4_start, ip_v4_end FROM blocked_client_events WHERE server_id = 'LEGACY-SERVER' AND slot_key = 999999"
		);
		assertEquals("52.167.114.0/24", repairedRow.get("subnet_group"));
		assertNotNull(repairedRow.get("ip_v4_start"));
		assertEquals(IpNetworkUtil.ipv4ToLong("52.167.114.213"), ((Number) repairedRow.get("ip_v4_start")).longValue());

		// 5. Querying by subnet "52.167.114.0/24" now matches properly via CIDR containment
		List<BlockedClientEvent> subnetHits = clientEventRepository.findRecentEventsFiltered(
				List.of("LEGACY-SERVER"), null, null, null, "52.167.114.0/24", 10, 0
		);
		assertFalse(subnetHits.isEmpty(), "Should find repaired event when searching for canonical subnet");
	}
}

