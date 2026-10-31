package org.henbru.antidos.collector;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.DailyReport;
import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.henbru.antidos.collector.model.PollEventLog;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.HeartbeatRepository;
import org.henbru.antidos.collector.storage.PollEventLogRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

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

	@Autowired
	private org.henbru.antidos.collector.storage.NetworkEntityRepository networkEntityRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.IntelSourceRepository intelSourceRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.IntelRangeRepository intelRangeRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.CrawlerFeedRepository crawlerFeedRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.SubnetRollupRepository subnetRollupRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.SubnetProfileRepository subnetProfileRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.DailyReportRepository dailyReportRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.DailyReportNoteRepository dailyReportNoteRepository;

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
		jdbcTemplate.update("DELETE FROM client_events WHERE client_key IN ('198.51.100.42', '203.0.113.99') OR server_id IN ('NODE-A', 'NODE-B')");
		Instant now = Instant.now();
		ClientEvent e1 = new ClientEvent(
				null, "NODE-A", "VALVE-1", 100L, now, "198.51.100.42", 50, 10, true, true, now);
		ClientEvent e2 = new ClientEvent(
				null, "NODE-B", "VALVE-1", 100L, now, "198.51.100.42", 70, 0, true, true, now);
		ClientEvent e3 = new ClientEvent(
				null, "NODE-A", "VALVE-1", 100L, now, "203.0.113.99", 20, 0, true, true, now);

		clientEventRepository.batchUpsert(List.of(e1, e2, e3));

		// Top offender analytics
		List<TopOffenderSummary> top = clientEventRepository.findTopOffenders(Instant.now().minus(1, ChronoUnit.HOURS), 10);
		assertFalse(top.isEmpty());

		TopOffenderSummary primary = top.getFirst();
		assertEquals("198.51.100.42", primary.clientKey());
		assertEquals(120L, primary.totalBlockedRequests()); // 50 from NODE-A + 70 from NODE-B (without retained_count)
		assertEquals(120L, primary.totalRequests());
		assertEquals(2, primary.distinctServersTargeted()); // Targeted both NODE-A and NODE-B!

		// Count distinct clients
		long distinct = clientEventRepository.countDistinctBlockedClientsSince(Instant.now().minus(1, ChronoUnit.HOURS));
		assertTrue(distinct >= 2L);
	}

	@Test
	void testClientEventRepositoryAdvancedFilteringAndSubnetRollup() {
		Instant now = Instant.now();
		ClientEvent e1 = new ClientEvent(
				null, "SERVER-PROD-1", "VALVE-API", 200L, now.minus(30, ChronoUnit.MINUTES), "198.51.100.10", 30, 0, true, true, now);
		ClientEvent e2 = new ClientEvent(
				null, "SERVER-PROD-2", "VALVE-API", 200L, now.minus(25, ChronoUnit.MINUTES), "198.51.100.25", 50, 0, true, true, now);
		ClientEvent e3 = new ClientEvent(
				null, "SERVER-STAGE", "VALVE-API", 200L, now.minus(20, ChronoUnit.MINUTES), "198.51.100.99", 100, 0, true, true, now);
		ClientEvent e4 = new ClientEvent(
				null, "SERVER-PROD-1", "VALVE-ADMIN", 200L, now.minus(15, ChronoUnit.MINUTES), "198.51.100.10", 40, 0, true, true, now);
		ClientEvent e5 = new ClientEvent(
				null, "SERVER-PROD-1", "VALVE-API", 200L, now.minus(10, ChronoUnit.MINUTES), "203.0.113.5", 80, 0, true, true, now);

		clientEventRepository.batchUpsert(List.of(e1, e2, e3, e4, e5));

		// 1. Multi-server + multi-valve filter: Only PROD-1 and PROD-2, only VALVE-API
		List<ClientEvent> filtered = clientEventRepository.findRecentEventsFiltered(
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
		List<ClientEvent> subnetHits = clientEventRepository.findRecentEventsFiltered(
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
		jdbcTemplate.update("DELETE FROM client_events WHERE server_id LIKE 'SERVER-ASN-%' OR asn IN (3320, 8075)");
		Instant now = Instant.now();
		ClientEvent e1 = new ClientEvent(
				null, "SERVER-ASN-1", "VALVE-API", 300L, now.minus(30, ChronoUnit.MINUTES), "198.51.100.1",
				4, 32, null, null, null, null, "198.51.100.0/24",
				50, 0, false, true, now,
				3320L, "Deutsche Telekom AG", "DE", ClientType.RESIDENTIAL, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		);
		ClientEvent e2 = new ClientEvent(
				null, "SERVER-ASN-2", "VALVE-API", 300L, now.minus(25, ChronoUnit.MINUTES), "198.51.100.2",
				4, 32, null, null, null, null, "198.51.100.0/24",
				70, 0, false, true, now,
				3320L, "Deutsche Telekom AG", "DE", ClientType.RESIDENTIAL, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		);
		ClientEvent e3 = new ClientEvent(
				null, "SERVER-ASN-1", "VALVE-API", 300L, now.minus(20, ChronoUnit.MINUTES), "203.0.113.10",
				4, 32, null, null, null, null, "203.0.113.0/24",
				100, 0, false, true, now,
				8075L, "Microsoft Corporation", "US", ClientType.DATACENTER, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		);
		ClientEvent e4 = new ClientEvent(
				null, "SERVER-ASN-1", "VALVE-API", 300L, now.minus(15, ChronoUnit.MINUTES), "10.68.1.1",
				4, 32, null, null, null, null, "10.68.1.0/24",
				20, 0, false, true, now,
				null, "Private Network", null, ClientType.PRIVATE_NETWORK, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		);
		ClientEvent e5 = new ClientEvent(
				null, "SERVER-ASN-1", "VALVE-API", 300L, now.minus(10, ChronoUnit.MINUTES), "185.220.101.4",
				4, 32, null, null, null, null, "185.220.101.0/24",
				60, 0, false, true, now,
				24940L, "Hetzner Online GmbH", "DE", ClientType.TOR_EXIT_NODE, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		);

		clientEventRepository.batchUpsert(List.of(e1, e2, e3, e4, e5));

		// 1. Filter by clientTypes = PRIVATE_NETWORK
		List<ClientEvent> privateEvents = clientEventRepository.findRecentEventsFiltered(
				null, null, now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("PRIVATE_NETWORK"), null, 50, 0
		);
		assertTrue(privateEvents.stream().anyMatch(e -> "10.68.1.1".equals(e.clientKey())));
		assertTrue(privateEvents.stream().allMatch(e -> e.clientType() == ClientType.PRIVATE_NETWORK));

		// 1b. Filter by clientTypes = TOR_EXIT_NODE
		List<ClientEvent> torEvents = clientEventRepository.findRecentEventsFiltered(
				null, null, now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("TOR_EXIT_NODE"), null, 50, 0
		);
		assertEquals(1, torEvents.size());
		assertEquals("185.220.101.4", torEvents.getFirst().clientKey());
		assertEquals(ClientType.TOR_EXIT_NODE, torEvents.getFirst().clientType());

		// 2. Filter by numeric ASN = 3320
		List<ClientEvent> telekomEvents = clientEventRepository.findRecentEventsFiltered(
				null, null, now.minus(1, ChronoUnit.HOURS), now, null,
				null, 3320L, 50, 0
		);
		assertEquals(2, telekomEvents.size());
		assertTrue(telekomEvents.stream().allMatch(e -> Long.valueOf(3320L).equals(e.asn())));

		// 3. Filter by query string "AS8075" (clientQuery automatic ASN parsing)
		List<ClientEvent> msEvents = clientEventRepository.findRecentEventsFiltered(
				null, null, now.minus(1, ChronoUnit.HOURS), now, "AS8075",
				null, null, 50, 0
		);
		assertEquals(1, msEvents.size());
		assertEquals("203.0.113.10", msEvents.getFirst().clientKey());

		// 3b. Filter by asOrg query string "telekom" (case-insensitive provider search)
		List<ClientEvent> telekomOrgEvents = clientEventRepository.findRecentEventsFiltered(
				null, null, now.minus(1, ChronoUnit.HOURS), now, null,
				null, null, "telekom", null, 50, 0
		);
		assertEquals(2, telekomOrgEvents.size());
		assertTrue(telekomOrgEvents.stream().allMatch(e -> e.asOrg() != null && e.asOrg().contains("Telekom")));

		// 3c. Filter by asOrg query string "MICROSOFT" (case-insensitive provider search)
		List<ClientEvent> msOrgEvents = clientEventRepository.findRecentEventsFiltered(
				null, null, now.minus(1, ChronoUnit.HOURS), now, null,
				null, null, "MICROSOFT", null, 50, 0
		);
		assertEquals(1, msOrgEvents.size());
		assertEquals("203.0.113.10", msOrgEvents.getFirst().clientKey());

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
		assertEquals(120L, as3320.totalRequests(), "Should sum 50 + 70 requests from e1 and e2");
		assertEquals(0L, as3320.totalBlockedRequests(), "Should have 0 blocked requests since e1 and e2 were active");
		assertEquals(2, as3320.distinctClientsCount(), "Should have 2 distinct IPs in AS3320");
		assertEquals(2, as3320.distinctServersTargeted(), "Should span 2 servers (PROD-1, PROD-2)");
	}

	@Test
	void testTopOffendersRankingByBlockedVsVolume() {
		Instant now = Instant.now();
		try {
			// Attacker: 200 requests, 200 blocked (status = BLOCKED)
			ClientEvent attacker = new ClientEvent(
					null, "SERVER-RANK-1", "VALVE-1", 400L, now.minus(15, ChronoUnit.MINUTES), "198.51.100.99",
					4, 32, null, null, null, null, "198.51.100.0/24",
					200, 50, true, ClientEvent.STATUS_BLOCKED, true, now,
					13335L, "Cloudflare, Inc.", "US", ClientType.DATACENTER, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
			);
			// High volume crawler: 2,500 requests, 0 blocked (status = ACTIVE)
			ClientEvent heavyCrawler = new ClientEvent(
					null, "SERVER-RANK-1", "VALVE-1", 400L, now.minus(10, ChronoUnit.MINUTES), "203.0.113.88",
					4, 32, null, null, null, null, "203.0.113.0/24",
					2500, 0, false, ClientEvent.STATUS_ACTIVE, true, now,
					24940L, "Hetzner Online GmbH", "DE", ClientType.DATACENTER, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
			);

			clientEventRepository.batchUpsert(List.of(attacker, heavyCrawler));

			// 1. Ranking by BLOCKED requests (default for Top Offenders)
			List<TopOffenderSummary> rankedByBlocked = clientEventRepository.findTopOffendersFiltered(
					List.of("SERVER-RANK-1"), null, now.minus(1, ChronoUnit.HOURS), null, null, null, null, null, null, "CLIENT", "BLOCKED", 10);
			assertFalse(rankedByBlocked.isEmpty());

			TopOffenderSummary firstBlocked = rankedByBlocked.getFirst();
			assertEquals("198.51.100.99", firstBlocked.clientKey(), "Attacker with 200 blocks should be ranked #1");
			assertEquals(200L, firstBlocked.totalBlockedRequests());
			assertEquals(200L, firstBlocked.totalRequests(), "retained_count (50) must not be added to total requests");

			TopOffenderSummary secondBlocked = rankedByBlocked.stream().filter(o -> "203.0.113.88".equals(o.clientKey())).findFirst().orElse(null);
			assertNotNull(secondBlocked);
			assertEquals(0L, secondBlocked.totalBlockedRequests());
			assertEquals(2500L, secondBlocked.totalRequests());

			// 2. Ranking by REQUEST volume (Active + Blocked)
			List<TopOffenderSummary> rankedByVolume = clientEventRepository.findTopOffendersFiltered(
					List.of("SERVER-RANK-1"), null, now.minus(1, ChronoUnit.HOURS), null, null, null, null, null, null, "CLIENT", "REQUESTS", 10);
			assertFalse(rankedByVolume.isEmpty());

			TopOffenderSummary firstVolume = rankedByVolume.getFirst();
			assertEquals("203.0.113.88", firstVolume.clientKey(), "Heavy crawler with 2500 requests should be ranked #1 by volume");
			assertEquals(0L, firstVolume.totalBlockedRequests());
			assertEquals(2500L, firstVolume.totalRequests());
		} finally {
			jdbcTemplate.update("DELETE FROM client_events WHERE server_id = 'SERVER-RANK-1'");
		}
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
		long totalCount = pollEventLogRepository.countSince(now.minus(1, ChronoUnit.HOURS));
		assertTrue(totalCount >= 3L);

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
		jdbcTemplate.update("DELETE FROM client_events WHERE server_id = 'LEGACY-SERVER' AND slot_key = 999999");
		// Simulate a pre-V3 legacy row with null ranges and subnet_group = client_key
		jdbcTemplate.update("""
				INSERT INTO client_events (
				    server_id, valve_name, slot_key, slot_time, client_key,
				    ip_version, cidr_prefix, ip_v4_start, ip_v4_end, ip_v6_start, ip_v6_end, subnet_group,
				    request_count, retained_count, is_locked, status, is_completed, last_updated_at,
				    client_type, enrichment_status
				) VALUES (
				    'LEGACY-SERVER', 'LEGACY-VALVE', 999999, ?, '52.167.114.213',
				    4, 32, NULL, NULL, NULL, NULL, '52.167.114.213',
				    42, 0, 1, 'BLOCKED', 1, ?,
				    'UNKNOWN', 'PENDING'
				)
				""", Timestamp.from(now), Timestamp.from(now));

		// 1. Searching for exact IP "52.167.114.213" should find the legacy row even before repair!
		List<ClientEvent> ipHits = clientEventRepository.findRecentEventsFiltered(
				List.of("LEGACY-SERVER"), null, null, null, "52.167.114.213", 10, 0
		);
		assertFalse(ipHits.isEmpty(), "Should find legacy event when searching for exact client IP");
		assertEquals("52.167.114.213", ipHits.getFirst().clientKey());
		// ROW_MAPPER dynamic fallback should already present canonical subnetGroup
		assertEquals("52.167.114.0/24", ipHits.getFirst().subnetGroup());

		// 2. Searching for shorthand "52.167.114" should also find it
		List<ClientEvent> shorthandHits = clientEventRepository.findRecentEventsFiltered(
				List.of("LEGACY-SERVER"), null, null, null, "52.167.114", 10, 0
		);
		assertFalse(shorthandHits.isEmpty(), "Should find legacy event when searching for prefix '52.167.114'");

		// 3. Trigger repairUnnormalizedEvents
		clientEventRepository.repairUnnormalizedEvents();

		// 4. Verify DB row was updated with canonical IP range and subnet_group
		Map<String, Object> repairedRow = jdbcTemplate.queryForMap(
				"SELECT subnet_group, ip_v4_start, ip_v4_end FROM client_events WHERE server_id = 'LEGACY-SERVER' AND slot_key = 999999"
		);
		assertEquals("52.167.114.0/24", repairedRow.get("subnet_group"));
		assertNotNull(repairedRow.get("ip_v4_start"));
		assertEquals(IpNetworkUtil.ipv4ToLong("52.167.114.213"), ((Number) repairedRow.get("ip_v4_start")).longValue());

		// 5. Querying by subnet "52.167.114.0/24" now matches properly via CIDR containment
		List<ClientEvent> subnetHits = clientEventRepository.findRecentEventsFiltered(
				List.of("LEGACY-SERVER"), null, null, null, "52.167.114.0/24", 10, 0
		);
		assertFalse(subnetHits.isEmpty(), "Should find repaired event when searching for canonical subnet");
	}

	@Test
	void testNetworkEntityAndIntelRepositories() {
		Instant now = Instant.now();

		// 1. Verify V5 migration initialized network entities from existing client events
		long entityCount = networkEntityRepository.count();
		assertTrue(entityCount >= 0, "Network entities table should be queryable");

		// 2. Insert new NetworkEntity
		org.henbru.antidos.collector.model.IpNetworkInfo net = IpNetworkUtil.parse("198.51.100.222");
		org.henbru.antidos.collector.model.NetworkEntity entity = org.henbru.antidos.collector.model.NetworkEntity.pending(
				"198.51.100.222", net, now);
		networkEntityRepository.batchUpsert(List.of(entity));

		Optional<org.henbru.antidos.collector.model.NetworkEntity> found = networkEntityRepository.findByClientKey("198.51.100.222");
		assertTrue(found.isPresent(), "Entity should be found by clientKey");
		assertEquals("198.51.100.222", found.get().clientKey());
		assertEquals("198.51.100.0/24", found.get().subnetGroup());
		assertNotNull(found.get().enrichmentStatus());

		// 3. Test findPendingEnrichment and batchUpdateEnrichment
		List<org.henbru.antidos.collector.model.NetworkEntity> pending = networkEntityRepository.findPendingEnrichment(10);
		assertNotNull(pending, "findPendingEnrichment should return a non-null list");

		org.henbru.antidos.collector.model.NetworkEntity enriched = new org.henbru.antidos.collector.model.NetworkEntity(
				found.get().id(),
				"198.51.100.222",
				4,
				32,
				found.get().ipV4Start(),
				found.get().ipV4End(),
				null,
				null,
				"198.51.100.0/24",
				"198.51.100.0/24",
				64496L,
				"Documentation Net",
				"US",
				ClientType.DATACENTER,
				"DATACENTER",
				org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED,
				now,
				"v1",
				found.get().firstSeen(),
				now
		);
		networkEntityRepository.batchUpdateEnrichment(List.of(enriched));

		Optional<org.henbru.antidos.collector.model.NetworkEntity> updated = networkEntityRepository.findById(found.get().id());
		assertTrue(updated.isPresent());
		assertEquals(Long.valueOf(64496L), updated.get().asn());
		assertEquals("Documentation Net", updated.get().asOrg());
		assertEquals(ClientType.DATACENTER, updated.get().clientType());
		assertEquals("DATACENTER", updated.get().tags());
		assertEquals(org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED, updated.get().enrichmentStatus());

		// 4. Test IntelSourceRepository and IntelRangeRepository
		org.henbru.antidos.collector.model.IntelSource src = new org.henbru.antidos.collector.model.IntelSource(
				"test-intel-src",
				"FEED",
				"Test Source",
				"TOR_EXIT_NODE",
				"https://example.com/tor.txt",
				1L,
				now,
				"SUCCESS",
				1,
				null
		);
		intelSourceRepository.upsert(src);

		Optional<org.henbru.antidos.collector.model.IntelSource> foundSrc = intelSourceRepository.findByKey("test-intel-src");
		assertTrue(foundSrc.isPresent());
		assertEquals("Test Source", foundSrc.get().name());

		org.henbru.antidos.collector.model.IntelRange range = new org.henbru.antidos.collector.model.IntelRange(
				null,
				"test-intel-src",
				"198.51.100.222/32",
				4,
				32,
				IpNetworkUtil.ipv4ToLong("198.51.100.222"),
				IpNetworkUtil.ipv4ToLong("198.51.100.222"),
				null,
				null,
				null,
				null,
				"TOR_EXIT_NODE",
				"Test Exit Node",
				1L,
				now
		);
		intelRangeRepository.replaceRangesForSource("test-intel-src", List.of(range));

		int count = intelRangeRepository.countRangesBySourceKey("test-intel-src");
		assertEquals(1, count);
		List<org.henbru.antidos.collector.model.IntelRange> allRanges = intelRangeRepository.findAll();
		assertTrue(allRanges.stream().anyMatch(r -> "test-intel-src".equals(r.sourceKey())));

		// Test recordSyncFailure preserves existing prefixCount and version
		intelSourceRepository.recordSyncFailure("test-intel-src", "HTTP 503");
		Optional<org.henbru.antidos.collector.model.IntelSource> failedSrc = intelSourceRepository.findByKey("test-intel-src");
		assertTrue(failedSrc.isPresent());
		assertEquals("FAILED", failedSrc.get().status());
		assertEquals("HTTP 503", failedSrc.get().lastError());
		assertEquals(1, failedSrc.get().prefixCount(), "Prefix count must be preserved on sync failure");

		// Test CrawlerFeedRepository recordSyncFailure
		org.henbru.antidos.collector.model.CrawlerFeed feed = new org.henbru.antidos.collector.model.CrawlerFeed(
				"test-feed", "Test Feed", "TOR_EXIT_NODE", "https://example.com/tor.txt", now, "SUCCESS", 42, null
		);
		crawlerFeedRepository.upsert(feed);
		crawlerFeedRepository.updateSyncStatus("test-feed", "SUCCESS", 42, null, now);
		crawlerFeedRepository.recordSyncFailure("test-feed", "ConnectTimeoutException: timed out");

		Optional<org.henbru.antidos.collector.model.CrawlerFeed> failedFeed = crawlerFeedRepository.findByKey("test-feed");
		assertTrue(failedFeed.isPresent());
		assertEquals("FAILED", failedFeed.get().status());
		assertEquals("ConnectTimeoutException: timed out", failedFeed.get().lastError());
		assertEquals(42, failedFeed.get().prefixCount(), "Prefix count must be preserved on sync failure");
		assertEquals(now.truncatedTo(ChronoUnit.SECONDS), failedFeed.get().lastSyncedAt().truncatedTo(ChronoUnit.SECONDS),
				"Last successful sync timestamp must be preserved");
	}

	@Test
	void testNetworkEntityRetentionAndTtlExpiration() {
		Instant now = Instant.now();
		Instant oldTime = now.minus(75, ChronoUnit.DAYS);

		// 1. Insert orphan entity (no events reference it)
		org.henbru.antidos.collector.model.IpNetworkInfo net1 = IpNetworkUtil.parse("198.51.100.77");
		org.henbru.antidos.collector.model.NetworkEntity orphan = new org.henbru.antidos.collector.model.NetworkEntity(
				null, "198.51.100.77", 4, 32, net1.v4Start(), net1.v4End(), null, null,
				net1.subnetGroup(), null, 12345L, "Old Net", "DE", ClientType.DATACENTER, null,
				org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED,
				oldTime, null, oldTime, oldTime
		);
		networkEntityRepository.batchUpsert(List.of(orphan));
		Optional<org.henbru.antidos.collector.model.NetworkEntity> savedOrphan = networkEntityRepository.findByClientKey("198.51.100.77");
		assertTrue(savedOrphan.isPresent());

		// 2. Insert active entity referenced by an event
		org.henbru.antidos.collector.model.IpNetworkInfo net2 = IpNetworkUtil.parse("198.51.100.88");
		org.henbru.antidos.collector.model.NetworkEntity active = new org.henbru.antidos.collector.model.NetworkEntity(
				null, "198.51.100.88", 4, 32, net2.v4Start(), net2.v4End(), null, null,
				net2.subnetGroup(), null, 12345L, "Active Net", "DE", ClientType.DATACENTER, null,
				org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED,
				oldTime, null, oldTime, oldTime
		);
		networkEntityRepository.batchUpsert(List.of(active));
		Optional<org.henbru.antidos.collector.model.NetworkEntity> savedActive = networkEntityRepository.findByClientKey("198.51.100.88");
		assertTrue(savedActive.isPresent());

		// Link event to savedActive
		ClientEvent event = new ClientEvent(
				null, "TEST-SRV", "VALVE", 100L, now, "198.51.100.88",
				4, 32, net2.v4Start(), net2.v4End(), null, null, net2.subnetGroup(),
				10, 0, false, ClientEvent.STATUS_BLOCKED, true, now,
				12345L, "Active Net", "DE", ClientType.DATACENTER, org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		).withEntityId(savedActive.get().id());
		clientEventRepository.batchUpsert(List.of(event));

		// 3. Run deleteOrphans with 60 day cutoff
		int deleted = networkEntityRepository.deleteOrphans(now.minus(60, ChronoUnit.DAYS));
		assertTrue(deleted >= 1, "Should have deleted at least 1 orphan entity");

		Optional<org.henbru.antidos.collector.model.NetworkEntity> checkOrphan = networkEntityRepository.findByClientKey("198.51.100.77");
		assertFalse(checkOrphan.isPresent(), "Orphan entity should be deleted");

		Optional<org.henbru.antidos.collector.model.NetworkEntity> checkActive = networkEntityRepository.findByClientKey("198.51.100.88");
		assertTrue(checkActive.isPresent(), "Referenced entity must NOT be deleted");

		// 4. Test markExpiredEnrichment (30-day TTL)
		jdbcTemplate.update("UPDATE network_entity SET resolved_at = ?, enrichment_status = 'ENRICHED', client_type = 'DATACENTER' WHERE id = ?",
				Timestamp.from(oldTime), checkActive.get().id());

		int expiredCount = networkEntityRepository.markExpiredEnrichment(now.minus(30, ChronoUnit.DAYS));
		assertTrue(expiredCount >= 1, "Should have marked stale entity as PENDING");

		Optional<org.henbru.antidos.collector.model.NetworkEntity> reloadedActive = networkEntityRepository.findByClientKey("198.51.100.88");
		assertTrue(reloadedActive.isPresent());
		assertEquals(org.henbru.antidos.collector.model.EnrichmentStatus.PENDING, reloadedActive.get().enrichmentStatus());
	}

	@Test
	void testClientEventsStatusFilteringAndRetention() {
		Instant now = Instant.now();
		Instant oldSlot = now.minus(5, ChronoUnit.DAYS);

		ClientEvent blockedOld = new ClientEvent(
				null, "RET-SRV", "VALVE", 101L, oldSlot, "198.51.100.51",
				50, 0, true, ClientEvent.STATUS_BLOCKED, true, oldSlot
		);
		ClientEvent activeOld = new ClientEvent(
				null, "RET-SRV", "VALVE", 101L, oldSlot, "198.51.100.52",
				10, 0, false, ClientEvent.STATUS_ACTIVE, true, oldSlot
		);
		ClientEvent activeNew = new ClientEvent(
				null, "RET-SRV", "VALVE", 102L, now, "198.51.100.53",
				25, 0, false, ClientEvent.STATUS_ACTIVE, true, now
		);

		clientEventRepository.batchUpsert(List.of(blockedOld, activeOld, activeNew));

		// 1. Filter by status: BLOCKED
		List<ClientEvent> blockedHits = clientEventRepository.findRecentEventsFiltered(
				List.of("RET-SRV"), null, null, null, null, null, null, "BLOCKED", 50, 0
		);
		assertEquals(1, blockedHits.size());
		assertEquals("198.51.100.51", blockedHits.getFirst().clientKey());
		assertEquals(ClientEvent.STATUS_BLOCKED, blockedHits.getFirst().status());

		// 2. Filter by status: ACTIVE
		List<ClientEvent> activeHits = clientEventRepository.findRecentEventsFiltered(
				List.of("RET-SRV"), null, null, null, null, null, null, "ACTIVE", 50, 0
		);
		assertEquals(2, activeHits.size());
		assertTrue(activeHits.stream().allMatch(e -> ClientEvent.STATUS_ACTIVE.equals(e.status())));

		// 3. Status-specific retention cleanup: Delete ACTIVE events older than 2 days
		int deletedActive = clientEventRepository.deleteOlderThan(now.minus(2, ChronoUnit.DAYS), ClientEvent.STATUS_ACTIVE);
		assertTrue(deletedActive >= 1, "Should have deleted at least 1 active event");

		// Blocked old event should still exist!
		List<ClientEvent> blockedAfterCleanup = clientEventRepository.findRecentEventsFiltered(
				List.of("RET-SRV"), null, null, null, "198.51.100.51", null, null, "BLOCKED", 10, 0
		);
		assertEquals(1, blockedAfterCleanup.size(), "Blocked event must remain intact after active retention cleanup");

		// Active old event should be gone
		List<ClientEvent> activeOldAfterCleanup = clientEventRepository.findRecentEventsFiltered(
				List.of("RET-SRV"), null, null, null, "198.51.100.52", null, null, "ACTIVE", 10, 0
		);
		assertTrue(activeOldAfterCleanup.isEmpty(), "Old active event should have been purged");

		// Active new event should still exist
		List<ClientEvent> activeNewAfterCleanup = clientEventRepository.findRecentEventsFiltered(
				List.of("RET-SRV"), null, null, null, "198.51.100.53", null, null, "ACTIVE", 10, 0
		);
		assertEquals(1, activeNewAfterCleanup.size(), "Recent active event must remain intact");
	}

	@Autowired
	private org.henbru.antidos.collector.storage.MonitoredValveRepository monitoredValveRepository;

	@Test
	void testMonitoredValveRepositoryUpsertAndFind() {
		Instant now = Instant.now();
		org.henbru.antidos.collector.model.MonitoredValve valve1 = new org.henbru.antidos.collector.model.MonitoredValve(
				"VALVE-NODE-1",
				"Primary-Rate-Limiter",
				"Test rate limiter",
				1,
				"BLOCKING",
				false,
				false,
				429,
				100,
				60,
				5,
				0.8f,
				32,
				64,
				15000,
				10000,
				"/api/*",
				"*.css, *.js",
				"127.0.0.1, 10.0.0.0/8",
				"198.51.100.22",
				"/antidos-status",
				"127.0.0.1",
				now,
				12345
		);

		monitoredValveRepository.upsert(valve1);

		Optional<org.henbru.antidos.collector.model.MonitoredValve> foundOpt =
				monitoredValveRepository.findByServerIdAndValveName("VALVE-NODE-1", "Primary-Rate-Limiter");
		assertTrue(foundOpt.isPresent());
		org.henbru.antidos.collector.model.MonitoredValve found = foundOpt.get();
		assertEquals("VALVE-NODE-1", found.serverId());
		assertEquals("Primary-Rate-Limiter", found.valveName());
		assertEquals("Test rate limiter", found.description());
		assertEquals("BLOCKING", found.monitorMode());
		assertTrue(found.isBlocking());
		assertEquals(100, found.allowedRequestsPerSlot());
		assertEquals(60, found.slotLength());
		assertEquals(5, found.numberOfSlots());
		assertEquals(32, found.ipv4SubnetMask());
		assertEquals(64, found.ipv6SubnetMask());
		assertEquals("/api/*", found.relevantPaths());
		assertEquals("*.css, *.js", found.nonRelevantPaths());
		assertEquals("127.0.0.1, 10.0.0.0/8", found.alwaysAllowedIPs());
		assertEquals("198.51.100.22", found.alwaysForbiddenIPs());
		assertEquals("auto", found.collectorIntegration());
		assertEquals("AUTO", found.collectorIntegrationLabel());
		assertFalse(found.visitorCookieEnabled());
		assertEquals("_adv", found.visitorCookieName());
		assertEquals("OFF", found.visitorCookieLabel());
		assertEquals("badge-secondary", found.visitorCookieBadgeClass());
		assertFalse(found.authTrackingEnabled());
		assertEquals("OFF", found.authTrackingMode());
		assertEquals("OFF", found.authTrackingLabel());
		assertEquals("badge-secondary", found.authTrackingBadgeClass());
		assertEquals(12345, found.configHash());
		assertTrue(found.hasPathFilters());
		assertTrue(found.hasIpLists());

		// Test update on conflict
		org.henbru.antidos.collector.model.MonitoredValve updated = new org.henbru.antidos.collector.model.MonitoredValve(
				"VALVE-NODE-1",
				"Primary-Rate-Limiter",
				"Updated description",
				1,
				"MARKING",
				true,
				false,
				429,
				150,
				60,
				5,
				0.8f,
				32,
				64,
				20000,
				10000,
				"/api/*",
				"*.css",
				"127.0.0.1",
				null,
				"/antidos-status",
				null,
				"true",
				true,
				"_mycookie",
				true,
				"COOKIE",
				"AUTH_COOKIE",
				"/trust",
				900,
				50000,
				now.plusSeconds(10),
				99999,
				true
		);
		monitoredValveRepository.upsert(updated);

		Optional<org.henbru.antidos.collector.model.MonitoredValve> afterUpdate =
				monitoredValveRepository.findByServerIdAndValveName("VALVE-NODE-1", "Primary-Rate-Limiter");
		assertTrue(afterUpdate.isPresent());
		assertEquals("Updated description", afterUpdate.get().description());
		assertEquals("MARKING", afterUpdate.get().monitorMode());
		assertFalse(afterUpdate.get().isBlocking());
		assertTrue(afterUpdate.get().simulationMode());
		assertEquals(150, afterUpdate.get().allowedRequestsPerSlot());
		assertEquals("true", afterUpdate.get().collectorIntegration());
		assertEquals("ALWAYS ON", afterUpdate.get().collectorIntegrationLabel());
		assertTrue(afterUpdate.get().visitorCookieEnabled());
		assertEquals("_mycookie", afterUpdate.get().visitorCookieName());
		assertEquals("ACTIVE (_mycookie)", afterUpdate.get().visitorCookieLabel());
		assertEquals("badge-success", afterUpdate.get().visitorCookieBadgeClass());
		assertTrue(afterUpdate.get().authTrackingEnabled());
		assertEquals("COOKIE", afterUpdate.get().authTrackingMode());
		assertEquals("AUTH_COOKIE", afterUpdate.get().authCookieName());
		assertEquals("/trust", afterUpdate.get().authLoginPaths());
		assertEquals(900, afterUpdate.get().authSessionTtlSeconds());
		assertEquals(50000, afterUpdate.get().maxAuthCacheSize());
		assertEquals("COOKIE (AUTH_COOKIE)", afterUpdate.get().authTrackingLabel());
		assertEquals("badge-success", afterUpdate.get().authTrackingBadgeClass());
		assertEquals(99999, afterUpdate.get().configHash());

		List<org.henbru.antidos.collector.model.MonitoredValve> serverValves =
				monitoredValveRepository.findByServerId("VALVE-NODE-1");
		assertEquals(1, serverValves.size());

		List<String> distinct = monitoredValveRepository.findDistinctValveNames();
		assertTrue(distinct.contains("Primary-Rate-Limiter"));
		assertTrue(afterUpdate.get().isActive());

		// Test syncActiveValves and deleteByServerIdAndValveName
		monitoredValveRepository.upsert(new org.henbru.antidos.collector.model.MonitoredValve(
				"VALVE-NODE-1", "Secondary-Limiter", "Secondary", 2, "BLOCKING", false, false, 429,
				50, 60, 5, 0.8f, 32, 64, 10000, 10000, null, null, null, null, null, null, now, 11111));
		assertEquals(2, monitoredValveRepository.findByServerId("VALVE-NODE-1").size());

		// Sync with only Primary-Rate-Limiter active
		monitoredValveRepository.syncActiveValves("VALVE-NODE-1", List.of("Primary-Rate-Limiter"));
		assertTrue(monitoredValveRepository.findByServerIdAndValveName("VALVE-NODE-1", "Primary-Rate-Limiter").get().isActive());
		assertFalse(monitoredValveRepository.findByServerIdAndValveName("VALVE-NODE-1", "Secondary-Limiter").get().isActive());

		// Delete Secondary-Limiter
		int deleted = monitoredValveRepository.deleteByServerIdAndValveName("VALVE-NODE-1", "Secondary-Limiter");
		assertEquals(1, deleted);
		assertTrue(monitoredValveRepository.findByServerIdAndValveName("VALVE-NODE-1", "Secondary-Limiter").isEmpty());
	}


	@Autowired
	private org.henbru.antidos.collector.storage.NetworkAnnotationRepository networkAnnotationRepository;

	@Test
	void testNetworkAnnotationRepositoryUpsertAndQuery() {
		Instant now = Instant.now();
		org.henbru.antidos.collector.model.NetworkAnnotation asnNote = new org.henbru.antidos.collector.model.NetworkAnnotation(
				null,
				org.henbru.antidos.collector.model.AnnotationTargetType.ASN,
				"AS24940",
				24940L,
				null,
				4,
				32,
				null,
				null,
				null,
				null,
				org.henbru.antidos.collector.model.AnnotationVerdict.SUSPICIOUS,
				"### Hetzner Scanners\n- Test markdown note",
				now,
				now
		);

		networkAnnotationRepository.upsert(asnNote);

		Optional<org.henbru.antidos.collector.model.NetworkAnnotation> foundAsn =
				networkAnnotationRepository.findByTarget(org.henbru.antidos.collector.model.AnnotationTargetType.ASN, "AS24940");
		assertTrue(foundAsn.isPresent());
		assertEquals(24940L, foundAsn.get().asn());
		assertEquals(org.henbru.antidos.collector.model.AnnotationVerdict.SUSPICIOUS, foundAsn.get().verdict());
		assertEquals("### Hetzner Scanners\n- Test markdown note", foundAsn.get().noteMarkdown());

		// Test Subnet annotation
		org.henbru.antidos.collector.model.NetworkAnnotation subnetNote = new org.henbru.antidos.collector.model.NetworkAnnotation(
				null,
				org.henbru.antidos.collector.model.AnnotationTargetType.SUBNET,
				"198.51.100.0/24",
				null,
				"198.51.100.0/24",
				4,
				24,
				3325256704L,
				3325256959L,
				null,
				null,
				org.henbru.antidos.collector.model.AnnotationVerdict.LEGITIMATE,
				"- Partner API range",
				now,
				now
		);
		networkAnnotationRepository.upsert(subnetNote);

		Optional<org.henbru.antidos.collector.model.NetworkAnnotation> foundSubnet =
				networkAnnotationRepository.findBySubnet("198.51.100.0/24");
		assertTrue(foundSubnet.isPresent());
		assertEquals("198.51.100.0/24", foundSubnet.get().subnetGroup());
		assertEquals(org.henbru.antidos.collector.model.AnnotationVerdict.LEGITIMATE, foundSubnet.get().verdict());

		// Test upsert update
		Instant later = now.plusSeconds(60);
		org.henbru.antidos.collector.model.NetworkAnnotation updatedAsnNote = new org.henbru.antidos.collector.model.NetworkAnnotation(
				foundAsn.get().id(),
				org.henbru.antidos.collector.model.AnnotationTargetType.ASN,
				"AS24940",
				24940L,
				null,
				4,
				32,
				null,
				null,
				null,
				null,
				org.henbru.antidos.collector.model.AnnotationVerdict.MALICIOUS,
				"### Upgraded to Malicious\n- Coordinated bot attack detected",
				now,
				later
		);
		networkAnnotationRepository.upsert(updatedAsnNote);

		Optional<org.henbru.antidos.collector.model.NetworkAnnotation> afterUpdate =
				networkAnnotationRepository.findByTarget(org.henbru.antidos.collector.model.AnnotationTargetType.ASN, "AS24940");
		assertTrue(afterUpdate.isPresent());
		assertEquals(org.henbru.antidos.collector.model.AnnotationVerdict.MALICIOUS, afterUpdate.get().verdict());
		assertTrue(afterUpdate.get().noteMarkdown().contains("Upgraded to Malicious"));

		// Test count by verdict
		Map<org.henbru.antidos.collector.model.AnnotationVerdict, Long> counts = networkAnnotationRepository.countByVerdict();
		assertEquals(1L, counts.get(org.henbru.antidos.collector.model.AnnotationVerdict.MALICIOUS));
		assertEquals(1L, counts.get(org.henbru.antidos.collector.model.AnnotationVerdict.LEGITIMATE));

		// Test delete
		boolean deleted = networkAnnotationRepository.deleteById(foundSubnet.get().id());
		assertTrue(deleted);
		assertFalse(networkAnnotationRepository.findBySubnet("198.51.100.0/24").isPresent());
	}

	@Test
	void testCookieAndAuthMetricsPersistenceAndRollups() {
		Instant now = Instant.now().truncatedTo(ChronoUnit.MINUTES);

		// 1. ClientEvent with cookie and auth metrics
		ClientEvent eWithCookies = new ClientEvent(
				null, "COOKIE-NODE", "VALVE-A", 100L, now, "198.51.100.20",
				50, 0, false, ClientEvent.STATUS_ACTIVE, true, now,
				1, 40, 10
		).withEnrichment(new org.henbru.antidos.collector.model.IpEnrichmentResult(13335L, "Cloudflare", "US", ClientType.RESIDENTIAL));
		ClientEvent eWithoutCookies = new ClientEvent(
				null, "COOKIE-NODE", "VALVE-B", 100L, now, "198.51.100.21",
				30, 0, false, ClientEvent.STATUS_ACTIVE, true, now,
				1, null, null
		).withEnrichment(new org.henbru.antidos.collector.model.IpEnrichmentResult(13335L, "Cloudflare", "US", ClientType.RESIDENTIAL));
		clientEventRepository.batchUpsert(List.of(eWithCookies, eWithoutCookies));

		List<ClientEvent> events = clientEventRepository.findRecentEvents("COOKIE-NODE", "198.51.100.20", 5);
		assertFalse(events.isEmpty());
		ClientEvent loadedWith = events.getFirst();
		assertEquals(40, loadedWith.returningCount());
		assertEquals(10, loadedWith.authenticatedCount());
		assertTrue(loadedWith.isReturningTracked());
		assertTrue(loadedWith.isAuthenticatedTracked());
		assertEquals(80.0, loadedWith.returningRatio(), 0.01);
		assertEquals(20.0, loadedWith.authenticatedRatio(), 0.01);

		List<ClientEvent> eventsWithout = clientEventRepository.findRecentEvents("COOKIE-NODE", "198.51.100.21", 5);
		assertFalse(eventsWithout.isEmpty());
		ClientEvent loadedWithout = eventsWithout.getFirst();
		assertNull(loadedWithout.returningCount());
		assertNull(loadedWithout.authenticatedCount());
		assertFalse(loadedWithout.isReturningTracked());
		assertFalse(loadedWithout.isAuthenticatedTracked());
		assertNull(loadedWithout.returningRatio());
		assertNull(loadedWithout.authenticatedRatio());

		// 2. SubnetRollup with cookie and auth metrics
		Instant bStart = now.minus(1, ChronoUnit.HOURS);
		Instant bEnd = now;
		org.henbru.antidos.collector.model.ClientSubnetRollup rollup = new org.henbru.antidos.collector.model.ClientSubnetRollup(
				null, bStart, bEnd, 60, "COOKIE-NODE", "VALVE-A", "198.51.100.0/24",
				100L, 80L, 20L, 5, 10, 40, 6, 13335L, "Cloudflare", "US", ClientType.RESIDENTIAL,
				70L, 90L, 18L, 90L
		);
		subnetRollupRepository.batchUpsert(List.of(rollup));

		List<org.henbru.antidos.collector.model.ClientSubnetRollup> foundRollups =
				subnetRollupRepository.findRollupsFiltered(List.of("COOKIE-NODE"), null, null, null, null, null, null, 5, 0);
		assertFalse(foundRollups.isEmpty());
		org.henbru.antidos.collector.model.ClientSubnetRollup loadedRollup = foundRollups.getFirst();
		assertEquals(70L, loadedRollup.returningRequests());
		assertEquals(90L, loadedRollup.returningTrackedRequests());
		assertEquals(18L, loadedRollup.authenticatedRequests());
		assertEquals(90L, loadedRollup.authenticatedTrackedRequests());
		assertTrue(loadedRollup.isReturningTracked());
		assertTrue(loadedRollup.isAuthenticatedTracked());
		assertEquals(77.77, loadedRollup.returningRatio(), 0.1);
		assertEquals(20.0, loadedRollup.authenticatedRatio(), 0.1);

		// 3. SubnetProfile with cookie and auth metrics
		org.henbru.antidos.collector.model.SubnetProfile profile = new org.henbru.antidos.collector.model.SubnetProfile(
				"198.51.100.0/24",
				now.minus(30, ChronoUnit.DAYS),
				now,
				0,
				1000L,
				800L,
				200L,
				100.0,
				10,
				200L,
				800L,
				10,
				200L,
				1.5,
				13335L,
				"Cloudflare",
				"US",
				ClientType.RESIDENTIAL,
				now,
				600L,
				800L,
				160L,
				800L
		);
		subnetProfileRepository.batchUpsert(List.of(profile));

		Optional<org.henbru.antidos.collector.model.SubnetProfile> loadedProfile =
				subnetProfileRepository.findBySubnetGroup("198.51.100.0/24");
		assertTrue(loadedProfile.isPresent());
		assertEquals(600L, loadedProfile.get().last24hReturningRequests());
		assertEquals(800L, loadedProfile.get().last24hReturningTrackedRequests());
		assertEquals(160L, loadedProfile.get().last24hAuthenticatedRequests());
		assertEquals(800L, loadedProfile.get().last24hAuthenticatedTrackedRequests());
		assertTrue(loadedProfile.get().isReturningTracked24h());
		assertTrue(loadedProfile.get().isAuthenticatedTracked24h());
		assertEquals(75.0, loadedProfile.get().returningRatio24h(), 0.01);
		assertEquals(20.0, loadedProfile.get().authenticatedRatio24h(), 0.01);
	}

	@Test
	void testDailyReportRepositoryUpsertAndQuery() {
		String testDate = "2026-10-15";
		dailyReportRepository.deleteByReportDate(testDate);

		DailyReport report = new DailyReport(
				null,
				testDate,
				"NORMAL",
				1500000L,
				1200L,
				85.5,
				3.2,
				"MAIN_VALVE",
				"NODE_1",
				2,
				5,
				"# Daily Report 2026-10-15\nEverything fine.",
				Instant.now(),
				Instant.now()
		);

		dailyReportRepository.upsert(report);

		Optional<DailyReport> loaded = dailyReportRepository.findByReportDate(testDate);
		assertTrue(loaded.isPresent());
		assertEquals("NORMAL", loaded.get().status());
		assertEquals(1500000L, loaded.get().totalRequests());
		assertEquals(1200L, loaded.get().totalBlocked());
		assertEquals(85.5, loaded.get().peakRequestsPerSec(), 0.01);
		assertEquals("MAIN_VALVE", loaded.get().peakValveName());
		assertEquals("NODE_1", loaded.get().peakServerId());
		assertTrue(loaded.get().reportMarkdown().contains("# Daily Report"));

		// Test update (upsert)
		DailyReport updated = new DailyReport(
				null,
				testDate,
				"ATTACK_MITIGATED",
				2000000L,
				50000L,
				195.0,
				12.5,
				"MAIN_VALVE",
				"NODE_1",
				2,
				25,
				"# Daily Report 2026-10-15 (Updated)\nAttack mitigated.",
				report.createdAt(),
				Instant.now()
		);
		dailyReportRepository.upsert(updated);

		Optional<DailyReport> reloaded = dailyReportRepository.findByReportDate(testDate);
		assertTrue(reloaded.isPresent());
		assertEquals("ATTACK_MITIGATED", reloaded.get().status());
		assertEquals(2000000L, reloaded.get().totalRequests());
		assertEquals(50000L, reloaded.get().totalBlocked());
		assertEquals(195.0, reloaded.get().peakRequestsPerSec(), 0.01);

		assertTrue(dailyReportRepository.findAllReportDates().contains(testDate));
	}

	@Test
	void testDailyReportNoteRepositoryUpsertAndQuery() {
		String testDate = "2026-10-18";
		dailyReportNoteRepository.deleteByReportDate(testDate);

		dailyReportNoteRepository.upsert(testDate, "Initial note: Routine deployment between 02:00 and 03:00.");

		Optional<org.henbru.antidos.collector.model.DailyReportNote> loaded = dailyReportNoteRepository.findByReportDate(testDate);
		assertTrue(loaded.isPresent());
		assertEquals(testDate, loaded.get().reportDate());
		assertTrue(loaded.get().hasContent());
		assertTrue(loaded.get().noteMarkdown().contains("Routine deployment"));

		// Upsert update
		dailyReportNoteRepository.upsert(testDate, "Updated note: Deployment completed, scrapers detected from AS13335.");

		Optional<org.henbru.antidos.collector.model.DailyReportNote> updated = dailyReportNoteRepository.findByReportDate(testDate);
		assertTrue(updated.isPresent());
		assertTrue(updated.get().noteMarkdown().contains("AS13335"));

		List<String> datesWithNotes = dailyReportNoteRepository.findDatesWithNotes();
		assertTrue(datesWithNotes.contains(testDate));

		dailyReportNoteRepository.deleteByReportDate(testDate);
		assertTrue(dailyReportNoteRepository.findByReportDate(testDate).isEmpty());
	}

	@Test
	void testSampleRequestMetadataPersistence() {
		Instant now = Instant.now().truncatedTo(ChronoUnit.MINUTES);
		String ip = "198.51.100.99";

		// 1. Insert blocked incident with sample metadata
		ClientEvent eventWithSample = new ClientEvent(
				null, "SAMPLE-NODE", "API-LIMITER", 200L, now, ip,
				150, 0, true, ClientEvent.STATUS_BLOCKED, true, now,
				1, null, null, "POST", "/wp-login.php", "curl/7.88.1"
		);
		clientEventRepository.batchUpsert(List.of(eventWithSample));

		List<ClientEvent> loadedEvents = clientEventRepository.findRecentEvents("SAMPLE-NODE", ip, 5);
		assertFalse(loadedEvents.isEmpty());
		ClientEvent loaded = loadedEvents.getFirst();
		assertTrue(loaded.hasSample());
		assertEquals("POST", loaded.sampleMethod());
		assertEquals("/wp-login.php", loaded.sampleUri());
		assertEquals("curl/7.88.1", loaded.sampleUserAgent());
		assertEquals("POST /wp-login.php", loaded.formattedSample());

		// 2. Simulate subsequent poll update in the same slot without sample data -> COALESCE must preserve existing sample
		ClientEvent updateWithoutSample = new ClientEvent(
				null, "SAMPLE-NODE", "API-LIMITER", 200L, now, ip,
				200, 0, true, ClientEvent.STATUS_BLOCKED, true, now,
				1, null, null, null, null, null
		);
		clientEventRepository.batchUpsert(List.of(updateWithoutSample));

		List<ClientEvent> reloadedEvents = clientEventRepository.findRecentEvents("SAMPLE-NODE", ip, 5);
		assertFalse(reloadedEvents.isEmpty());
		ClientEvent reloaded = reloadedEvents.getFirst();
		assertEquals(200, reloaded.requestCount());
		assertTrue(reloaded.hasSample(), "COALESCE in upsert must preserve previously recorded sample");
		assertEquals("POST", reloaded.sampleMethod());
		assertEquals("/wp-login.php", reloaded.sampleUri());
		assertEquals("curl/7.88.1", reloaded.sampleUserAgent());
	}
}


