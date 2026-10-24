package org.henbru.antidos.collector.aggregation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.ClientSubnetRollup;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.SubnetRollupRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class RollupAggregationServiceTest {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private ClientEventRepository clientEventRepository;

	@Autowired
	private SubnetRollupRepository rollupRepository;

	@Autowired
	private RollupAggregationService aggregationService;

	@Autowired
	private CollectorProperties properties;

	@BeforeEach
	void setUp() {
		jdbcTemplate.update("DELETE FROM client_subnet_rollups");
		jdbcTemplate.update("DELETE FROM client_events");
	}

	@Test
	void testAggregateWindowWithActiveAndBlockedClients() {
		Instant now = Instant.now().truncatedTo(ChronoUnit.HOURS);
		Instant bucketStart = now.minus(2, ChronoUnit.HOURS);
		Instant bucketEnd = now.minus(1, ChronoUnit.HOURS);
		Instant slotTime1 = bucketStart.plus(10, ChronoUnit.MINUTES);
		Instant slotTime2 = bucketStart.plus(25, ChronoUnit.MINUTES);

		// Subnet A on Node-1: 3 distinct clients, mix of ACTIVE and BLOCKED
		ClientEvent e1 = new ClientEvent(
				null, "Node-1", "Limiter", 1001L, slotTime1, "198.51.100.10",
				5, 0, false, ClientEvent.STATUS_ACTIVE, true, slotTime1
		).withEnrichment(new org.henbru.antidos.collector.model.IpEnrichmentResult(13335L, "Cloudflare", "US", ClientType.RESIDENTIAL));

		ClientEvent e2 = new ClientEvent(
				null, "Node-1", "Limiter", 1001L, slotTime1, "198.51.100.11",
				3, 0, false, ClientEvent.STATUS_ACTIVE, true, slotTime1
		).withEnrichment(new org.henbru.antidos.collector.model.IpEnrichmentResult(13335L, "Cloudflare", "US", ClientType.RESIDENTIAL));

		ClientEvent e3 = new ClientEvent(
				null, "Node-1", "Limiter", 1002L, slotTime2, "198.51.100.12",
				25, 0, true, ClientEvent.STATUS_BLOCKED, true, slotTime2
		).withEnrichment(new org.henbru.antidos.collector.model.IpEnrichmentResult(13335L, "Cloudflare", "US", ClientType.RESIDENTIAL));

		// Subnet B on Node-2: 1 single client on Node-2
		ClientEvent e4 = new ClientEvent(
				null, "Node-2", "Limiter", 1001L, slotTime1, "203.0.113.50",
				100, 0, true, ClientEvent.STATUS_BLOCKED, true, slotTime1
		).withEnrichment(new org.henbru.antidos.collector.model.IpEnrichmentResult(24940L, "Hetzner", "DE", ClientType.DATACENTER));

		// Event outside the window (should not be included)
		ClientEvent outside = new ClientEvent(
				null, "Node-1", "Limiter", 9999L, now, "198.51.100.99",
				50, 0, false, ClientEvent.STATUS_ACTIVE, true, now
		);

		clientEventRepository.batchUpsert(List.of(e1, e2, e3, e4, outside));

		// 1. Run aggregation for [bucketStart -> bucketEnd]
		int rollupsCreated = aggregationService.aggregateWindow(bucketStart, bucketEnd);
		assertEquals(2, rollupsCreated, "Should create 2 rollups (Subnet A on Node-1, Subnet B on Node-2)");

		// 2. Query rollups for Node-1
		List<ClientSubnetRollup> node1Rollups = rollupRepository.findRollupsFiltered(
				List.of("Node-1"), null, null, null, null, null, null, 10, 0
		);
		assertEquals(1, node1Rollups.size());
		ClientSubnetRollup r1 = node1Rollups.getFirst();

		assertEquals("Node-1", r1.serverId());
		assertEquals("Limiter", r1.valveName());
		assertEquals("198.51.100.0/24", r1.subnetGroup());
		assertEquals(33L, r1.totalRequests(), "5 + 3 + 25 = 33 total requests");
		assertEquals(8L, r1.activeRequests(), "5 + 3 = 8 active requests");
		assertEquals(25L, r1.blockedRequests(), "25 blocked requests");
		assertEquals(3, r1.distinctClients(), "3 distinct IPs in Subnet A");
		assertEquals(3, r1.minRequestsPerClient());
		assertEquals(25, r1.maxRequestsPerClient());
		assertEquals(2, r1.slotsActiveCount(), "Active across 2 distinct slots");
		assertEquals(13335L, r1.asn());
		assertEquals("US", r1.countryCode());
		assertEquals(ClientType.RESIDENTIAL, r1.clientType());
		assertEquals(60, r1.bucketMinutes());
		assertEquals(11.0, r1.averageRequestsPerClient(), 0.01);

		// 3. Query rollups for Node-2
		List<ClientSubnetRollup> node2Rollups = rollupRepository.findRollupsFiltered(
				List.of("Node-2"), null, null, null, null, null, null, 10, 0
		);
		assertEquals(1, node2Rollups.size());
		ClientSubnetRollup r2 = node2Rollups.getFirst();
		assertEquals("Node-2", r2.serverId());
		assertEquals("203.0.113.0/24", r2.subnetGroup());
		assertEquals(100L, r2.totalRequests());
		assertEquals(100L, r2.blockedRequests());
		assertEquals(0L, r2.activeRequests());
		assertEquals(1, r2.distinctClients());
		assertEquals(ClientType.DATACENTER, r2.clientType());

		// 4. Test filter by Subnet Query
		List<ClientSubnetRollup> subnetFilter = rollupRepository.findRollupsFiltered(
				null, null, null, null, "198.51.100", null, null, 10, 0
		);
		assertEquals(1, subnetFilter.size());
		assertEquals("198.51.100.0/24", subnetFilter.getFirst().subnetGroup());

		// 5. Test filter by ClientType
		List<ClientSubnetRollup> residentialRollups = rollupRepository.findRollupsFiltered(
				null, null, null, null, null, null, List.of("RESIDENTIAL"), 10, 0
		);
		assertEquals(1, residentialRollups.size());
		assertEquals("Node-1", residentialRollups.getFirst().serverId());

		// 6. Test retention deletion
		Instant purgeCutoff = bucketEnd.plus(1, ChronoUnit.HOURS);
		int deleted = rollupRepository.deleteOlderThan(purgeCutoff);
		assertEquals(2, deleted);
		assertEquals(0, rollupRepository.countRollupsFiltered(null, null, null, null, null, null, null));
	}

	@Test
	void testPotentialResidentialProxyHeuristic() {
		Instant now = Instant.now();
		// 10 distinct clients, 30 requests -> 3.0 avg req/client, residential
		ClientSubnetRollup proxyCandidate = new ClientSubnetRollup(
				1L, now, now.plus(1, ChronoUnit.HOURS), 60, "Node-1", "Limiter", "198.51.100.0/24",
				30L, 30L, 0L, 10, 1, 4, 5, 12345L, "ISP Net", "DE", ClientType.RESIDENTIAL
		);
		assertTrue(proxyCandidate.isPotentialResidentialProxy());

		// High request count per client (50 avg) -> Not a residential proxy pattern
		ClientSubnetRollup regularHeavyUser = new ClientSubnetRollup(
				2L, now, now.plus(1, ChronoUnit.HOURS), 60, "Node-1", "Limiter", "198.51.100.0/24",
				500L, 500L, 0L, 10, 20, 80, 5, 12345L, "ISP Net", "DE", ClientType.RESIDENTIAL
		);
		assertFalse(regularHeavyUser.isPotentialResidentialProxy());

		// Datacenter scraper -> Not a residential proxy
		ClientSubnetRollup datacenterBot = new ClientSubnetRollup(
				3L, now, now.plus(1, ChronoUnit.HOURS), 60, "Node-1", "Limiter", "203.0.113.0/24",
				30L, 30L, 0L, 10, 1, 4, 5, 24940L, "Hetzner", "DE", ClientType.DATACENTER
		);
		assertFalse(datacenterBot.isPotentialResidentialProxy());
	}
}
