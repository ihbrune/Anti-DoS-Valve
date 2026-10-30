package org.henbru.antidos.collector.demo;

import static org.hamcrest.Matchers.containsString;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.model.ValveDetailsDto;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
		"collector.demo-mode=true",
		"spring.datasource.url=jdbc:sqlite:target/demo-test.db?busy_timeout=60000"
})
@SuppressWarnings("null")
class DemoModeTest {

	static {
		for (String suffix : new String[]{"", "-wal", "-shm"}) {
			java.io.File f = new java.io.File("target/demo-test.db" + suffix);
			if (f.exists()) {
				f.delete();
			}
		}
	}

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private MockValveSimulator simulator;

	@Autowired
	private CollectorProperties properties;

	@Autowired
	private com.fasterxml.jackson.databind.ObjectMapper objectMapper;

	@Autowired
	private org.henbru.antidos.collector.storage.SlotSnapshotRepository slotSnapshotRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.PollEventLogRepository pollEventLogRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.HeartbeatRepository heartbeatRepository;

	@Autowired
	private org.henbru.antidos.collector.aggregation.SubnetProfileService subnetProfileService;

	@Autowired
	private org.henbru.antidos.collector.aggregation.AnalyticsService analyticsService;

	@Test
	void testDemoEndpointsAutoConfigured() {
		assertTrue(properties.isDemoMode(), "Demo mode should be enabled via properties");
		assertFalse(properties.getEndpoints().isEmpty(), "Endpoints list should not be empty");

		EndpointConfig edge = properties.getEndpoints().stream()
				.filter(e -> "Demo-Edge-EU".equals(e.getName()))
				.findFirst()
				.orElse(null);
		assertNotNull(edge, "Demo-Edge-EU should be configured");
		assertTrue(edge.getUrl().contains("/mock-valve/edge-eu/antidos-status"));
		assertEquals("demo-token", edge.getToken());

		EndpointConfig api = properties.getEndpoints().stream()
				.filter(e -> "Demo-API-Gateway".equals(e.getName()))
				.findFirst()
				.orElse(null);
		assertNotNull(api, "Demo-API-Gateway should be configured");

		EndpointConfig staging = properties.getEndpoints().stream()
				.filter(e -> "Demo-Staging-Node".equals(e.getName()))
				.findFirst()
				.orElse(null);
		assertNotNull(staging, "Demo-Staging-Node should be configured");
	}

	@Test
	void testMockControllerJsonIsCompatibleWithValveStatusClient() throws Exception {
		// Fetch JSON via MockMvc
		String overviewJson = mockMvc.perform(get("/mock-valve/edge-eu/antidos-status")
						.header("Authorization", "Bearer demo-token"))
				.andExpect(status().isOk())
				.andReturn()
				.getResponse()
				.getContentAsString();

		// Verify that ValveStatusClient can deserialize it into ValveOverviewDto
		ValveOverviewDto overview = objectMapper.readValue(overviewJson, ValveOverviewDto.class);
		assertNotNull(overview);
		assertEquals(4, overview.valves().size(), "Edge node should provide Primary-Rate-Limiter, Subnet-Guard, IPv6-Rate-Limiter, and HONEYPOT-PROBE-VALVE");
		assertEquals("Primary-Rate-Limiter", overview.valves().getFirst().monitorName());
		assertEquals("Subnet-Guard", overview.valves().get(1).monitorName());
		assertEquals("IPv6-Rate-Limiter", overview.valves().get(2).monitorName());
		assertEquals("HONEYPOT-PROBE-VALVE", overview.valves().get(3).monitorName());

		// Fetch details JSON via MockMvc
		String detailsJson = mockMvc.perform(get("/mock-valve/api-gateway/antidos-status")
						.header("Authorization", "Bearer demo-token")
						.param("view", "details")
						.param("valve", "API-DoS-Shield")
						.param("slot", "previous"))
				.andExpect(status().isOk())
				.andReturn()
				.getResponse()
				.getContentAsString();

		// Verify that ValveStatusClient can deserialize it into ValveDetailsDto
		ValveDetailsDto details = objectMapper.readValue(detailsJson, ValveDetailsDto.class);
		assertNotNull(details);
		assertEquals("API-DoS-Shield", details.valve().monitorName());
		assertNotNull(details.selectedSlot());
		assertFalse(details.blockedClients().isEmpty(), "API Gateway details should include blocked attacker IPs");
		assertTrue(details.blockedClients().stream().anyMatch(c -> c.sampleMethod() != null && c.sampleUri() != null),
				"Simulated API Gateway attackers should include sample request probe snapshots");
	}

	@Test
	void testMockSimulatorOverviewAndDetails() {
		ValveOverviewDto overview = simulator.buildOverview("edge-eu", null);
		assertNotNull(overview);
		assertNotNull(overview.serverTime());
		assertEquals(4, overview.valves().size(), "Edge node should provide 4 valves");

		ValveOverviewDto.ValveSummaryDto primary = overview.valves().getFirst();
		assertEquals("Primary-Rate-Limiter", primary.monitorName());
		assertEquals("BLOCKING", primary.monitorMode());
		assertEquals(120, primary.allowedRequestsPerSlot());
		assertEquals(10, primary.slotLength());

		ValveDetailsDto details = simulator.buildDetails("edge-eu", "Primary-Rate-Limiter", "previous", "all");
		assertNotNull(details);
		assertNotNull(details.valve());
		assertNotNull(details.selectedSlot());
		assertEquals("previous", details.selectedSlot().type());

		ValveDetailsDto subnetDetails = simulator.buildDetails("edge-eu", "Subnet-Guard", "previous", "all");
		assertNotNull(subnetDetails);
		assertNotNull(subnetDetails.selectedSlot());
		assertTrue(subnetDetails.blockedClients().stream().anyMatch(c -> c.key().contains("/24")),
				"Subnet-Guard should produce /24 subnet blocks");

		ValveDetailsDto ipv6Details = simulator.buildDetails("edge-eu", "IPv6-Rate-Limiter", "previous", "all");
		assertNotNull(ipv6Details);
		assertNotNull(ipv6Details.selectedSlot());
		assertTrue(ipv6Details.blockedClients().stream().anyMatch(c -> c.key().contains(":")),
				"IPv6-Rate-Limiter should produce IPv6 client blocks");

		ValveOverviewDto.ValveSummaryDto honeypotSummary = overview.valves().get(3);
		assertEquals("HONEYPOT-PROBE-VALVE", honeypotSummary.monitorName());
		assertEquals(0, honeypotSummary.allowedRequestsPerSlot(), "Honeypot should have allowedRequestsPerSlot = 0");
		assertTrue(honeypotSummary.serverWideBlocking(), "Honeypot should enforce server-wide blocking");

		ValveDetailsDto honeypotDetails = simulator.buildDetails("edge-eu", "HONEYPOT-PROBE-VALVE", "previous", "all");
		assertNotNull(honeypotDetails);
		assertNotNull(honeypotDetails.selectedSlot());
		assertFalse(honeypotDetails.blockedClients().isEmpty(), "HONEYPOT-PROBE-VALVE should produce blocked probers");
		assertEquals("HONEYPOT-PROBE-VALVE", honeypotDetails.valve().monitorName());

		ValveDetailsDto apiDetails = simulator.buildDetails("api-gateway", "API-DoS-Shield", "previous", "all");
		assertNotNull(apiDetails);
		assertFalse(apiDetails.blockedClients().isEmpty(), "API gateway under attack should list blocked clients");
	}

	@Test
	void testMockControllerAuthentication() throws Exception {
		// 1. Without Token -> 401
		String unauthorizedResponse = mockMvc.perform(get("/mock-valve/edge-eu/antidos-status"))
				.andExpect(status().isUnauthorized())
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertTrue(unauthorizedResponse.contains("Unauthorized"));

		// 2. With Wrong Token -> 401
		mockMvc.perform(get("/mock-valve/edge-eu/antidos-status")
						.header("Authorization", "Bearer invalid-token"))
				.andExpect(status().isUnauthorized());

		// 3. With Valid Token -> 200 OK Overview
		String validResponse = mockMvc.perform(get("/mock-valve/edge-eu/antidos-status")
						.header("Authorization", "Bearer demo-token"))
				.andExpect(status().isOk())
				.andReturn()
				.getResponse()
				.getContentAsString();
		ValveOverviewDto overview = objectMapper.readValue(validResponse, ValveOverviewDto.class);
		assertEquals(4, overview.valves().size());
		assertEquals("Primary-Rate-Limiter", overview.valves().getFirst().monitorName());
	}

	@Test
	void testDashboardRendersDemoBanner() throws Exception {
		String html = mockMvc.perform(get("/"))
				.andExpect(status().isOk())
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertTrue(html.contains("DEMO MODE ACTIVE"));
		assertTrue(html.contains("antidos-collector-demo.db"));
		assertTrue(html.contains("simulated Anti-DoS Valve endpoints"));
	}

	@Test
	void testDemoDataSeederPopulates7DayHistory() throws Exception {
		java.time.Instant now = java.time.Instant.now();
		java.time.Instant since24h = now.minus(24, java.time.temporal.ChronoUnit.HOURS);
		java.time.Instant since7d = now.minus(7, java.time.temporal.ChronoUnit.DAYS);

		// 1. Verify Slot Snapshots Seeding
		long totalReqs24h = slotSnapshotRepository.sumRequestsSince(since24h);
		assertTrue(totalReqs24h > 100_000L, "24h requests should be well populated (>100k) from seeder");

		long totalBlocked24h = slotSnapshotRepository.sumBlockedRequestsSince(since24h);
		assertTrue(totalBlocked24h > 10L, "24h blocked requests should reflect attacks");

		// 2. Verify Top Offenders Seeding
		var offenders24h = clientEventRepository.findTopOffenders(since24h, 10);
		assertFalse(offenders24h.isEmpty(), "Top offenders (24h) should be populated");
		assertTrue(offenders24h.getFirst().totalBlockedRequests() > 100, "Top offender should have substantial request count");

		var offenders7d = clientEventRepository.findTopOffenders(since7d, 20);
		assertTrue(offenders7d.size() >= offenders24h.size(), "7d offenders list should contain multi-day attack waves");

		// 3. Verify Heartbeats
		var heartbeats = heartbeatRepository.findAll();
		assertEquals(3, heartbeats.size(), "3 demo endpoints should have seeded heartbeats");

		// 4. Verify Poll Audit Logs
		long successLogs = pollEventLogRepository.countByStatusSince("SUCCESS", since24h);
		long warnLogs = pollEventLogRepository.countByStatusSince("WARNING", since24h);
		long errorLogs = pollEventLogRepository.countByStatusSince("ERROR", since24h);

		assertTrue(successLogs > 10, "Should have regular success poll logs");
		assertTrue(warnLogs > 0, "Should have seeded slow-poll warning logs");
		assertTrue(errorLogs > 0, "Should have seeded simulated error logs");

		// 5. Verify Dashboard UI displays non-zero 24h stats
		String dashboardHtml = mockMvc.perform(get("/"))
				.andExpect(status().isOk())
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertTrue(dashboardHtml.contains("Demo-Edge-EU"));
		assertTrue(dashboardHtml.contains("Demo-API-Gateway"));

		// 6. Verify IPv6 and Subnet-Aggregated events are seeded
		var ipv6Events = clientEventRepository.findRecentEventsFiltered(
				java.util.List.of("Demo-Edge-EU"), java.util.List.of("IPv6-Rate-Limiter"), null, null, null, 10, 0);
		assertFalse(ipv6Events.isEmpty(), "Should have seeded IPv6 events for IPv6-Rate-Limiter");
		assertEquals(6, ipv6Events.getFirst().ipVersion(), "Event should be categorized as IPv6");

		var subnetEvents = clientEventRepository.findRecentEventsFiltered(
				java.util.List.of("Demo-Edge-EU"), java.util.List.of("Subnet-Guard"), null, null, null, 10, 0);
		assertFalse(subnetEvents.isEmpty(), "Should have seeded Subnet-Guard /24 aggregated events");
		assertTrue(subnetEvents.stream().anyMatch(e -> e.cidrPrefix() == 24), "Event should be categorized as /24 CIDR prefix");

		// 7. Verify Subnet Rollup groups IPv6 into /64 and IPv4 into /24
		var rollup = clientEventRepository.findTopOffendersFiltered(
				null, null, since7d, now, null, "SUBNET", 30);
		assertTrue(rollup.stream().anyMatch(o -> o.clientKey().contains("/64")),
				"Subnet rollup should group rotating IPv6 clients into canonical /64 prefix");
		assertTrue(rollup.stream().anyMatch(o -> o.clientKey().contains("/24")),
				"Subnet rollup should contain /24 subnets");

		// 8. Verify Honeypot events are seeded
		var honeypotEvents = clientEventRepository.findRecentEventsFiltered(
				java.util.List.of("Demo-Edge-EU"), java.util.List.of("HONEYPOT-PROBE-VALVE"), null, null, null, 10, 0);
		assertFalse(honeypotEvents.isEmpty(), "Should have seeded Honeypot events for HONEYPOT-PROBE-VALVE");
		assertTrue(honeypotEvents.getFirst().isHoneypot(), "Event should be recognized as Honeypot event");
		assertEquals(1, honeypotEvents.getFirst().requestCount(), "Honeypot events should record individual probe hits");
		assertTrue(honeypotEvents.stream().anyMatch(e -> e.hasSample()), "Honeypot demo events should include sample probe snapshots");
	}

	@Test
	void testDemoFleetScalingEndpointGeneration() {
		// When fleet instance count = 1
		var singleEndpoints = DemoModeService.createDemoEndpoints(8090, 1);
		assertEquals(3, singleEndpoints.size());
		assertEquals("Demo-Edge-EU", singleEndpoints.get(0).getName());
		assertEquals("Demo-API-Gateway", singleEndpoints.get(1).getName());
		assertEquals("Demo-Staging-Node", singleEndpoints.get(2).getName());

		// When fleet instance count = 3 (3 instances per type = 9 total servers)
		var fleetEndpoints = DemoModeService.createDemoEndpoints(8090, 3);
		assertEquals(9, fleetEndpoints.size());

		assertEquals("Demo-Edge-EU A", fleetEndpoints.get(0).getName());
		assertEquals("http://localhost:8090/mock-valve/edge-eu-a/antidos-status", fleetEndpoints.get(0).getUrl());

		assertEquals("Demo-API-Gateway A", fleetEndpoints.get(1).getName());
		assertEquals("http://localhost:8090/mock-valve/api-gateway-a/antidos-status", fleetEndpoints.get(1).getUrl());

		assertEquals("Demo-Staging-Node A", fleetEndpoints.get(2).getName());
		assertEquals("http://localhost:8090/mock-valve/staging-node-a/antidos-status", fleetEndpoints.get(2).getUrl());

		assertEquals("Demo-Edge-EU B", fleetEndpoints.get(3).getName());
		assertEquals("http://localhost:8090/mock-valve/edge-eu-b/antidos-status", fleetEndpoints.get(3).getUrl());

		assertEquals("Demo-API-Gateway B", fleetEndpoints.get(4).getName());
		assertEquals("http://localhost:8090/mock-valve/api-gateway-b/antidos-status", fleetEndpoints.get(4).getUrl());

		assertEquals("Demo-Staging-Node B", fleetEndpoints.get(5).getName());
		assertEquals("http://localhost:8090/mock-valve/staging-node-b/antidos-status", fleetEndpoints.get(5).getUrl());

		assertEquals("Demo-Edge-EU C", fleetEndpoints.get(6).getName());
		assertEquals("Demo-API-Gateway C", fleetEndpoints.get(7).getName());
		assertEquals("Demo-Staging-Node C", fleetEndpoints.get(8).getName());
	}

	@Test
	void testFleetMockControllerResponses() throws Exception {
		// Query instance B of Edge EU
		mockMvc.perform(get("/mock-valve/edge-eu-b/antidos-status")
						.header("Authorization", "Bearer demo-token"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Primary-Rate-Limiter")));

		// Query instance C of API Gateway
		mockMvc.perform(get("/mock-valve/api-gateway-c/antidos-status")
						.header("Authorization", "Bearer demo-token"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("API-DoS-Shield")));
	}

	@Test
	void testDemoSubnetProfilesAndAnomalyPatterns() {
		assertNotNull(subnetProfileService, "SubnetProfileService should be available");
		long count = subnetProfileService.countProfilesFiltered("ALL", null, null, null, null, null);
		assertTrue(count > 0, "Demo database should have generated subnet profiles");

		// Verify SURGE pattern matches
		long surgeCount = subnetProfileService.countProfilesFiltered("SURGE", null, null, null, null, null);
		assertTrue(surgeCount > 0, "Demo mode should include high surge profiles");

		// Verify PROXY_POOL pattern matches (185.246.221.0/24)
		long proxyPoolCount = subnetProfileService.countProfilesFiltered("PROXY_POOL", null, null, null, null, null);
		assertTrue(proxyPoolCount > 0, "Demo mode should include residential proxy pool rotation profile");

		// Verify DORMANT pattern matches (91.240.118.0/24)
		long dormantCount = subnetProfileService.countProfilesFiltered("DORMANT", null, null, null, null, null);
		assertTrue(dormantCount > 0, "Demo mode should include dormancy breakout profile");

		// Verify NEW pattern matches (195.181.168.0/24)
		long newCount = subnetProfileService.countProfilesFiltered("NEW", null, null, null, null, null);
		assertTrue(newCount > 0, "Demo mode should include new subnet profile");
	}

	@Test
	void testDemoSubnetScatterplotPointsSpread() {
		assertNotNull(analyticsService, "AnalyticsService should be available");
		var dto = analyticsService.getDashboardAnalytics(24, null, null);
		assertNotNull(dto);
		assertFalse(dto.scatterPoints().isEmpty(), "Scatter points should be populated in demo mode");

		long countDistinctClientsGt1 = dto.scatterPoints().stream()
				.filter(p -> p.distinctClients() > 1)
				.count();
		assertTrue(countDistinctClientsGt1 >= 10,
				"At least 10 subnet clusters should have distinct client IPs > 1 to avoid stacking on the X=1 axis, found: " + countDistinctClientsGt1);

		long countXAtLeast10 = dto.scatterPoints().stream()
				.filter(p -> p.distinctClients() >= 10)
				.count();
		assertTrue(countXAtLeast10 >= 5,
				"Should have multiple large/residential clusters with distinct IPs >= 10, found: " + countXAtLeast10);

		// Verify residential proxy evasion swarms are identified (high X, low Y, residential/heuristic)
		long residentialEvasions = dto.scatterPoints().stream()
				.filter(p -> "HIGH_RISK_RESIDENTIAL".equals(p.classification()))
				.count();
		assertTrue(residentialEvasions >= 2,
				"Should have multiple residential proxy evasion swarms, found: " + residentialEvasions);

		// Verify diverse classifications appear in scatter points
		java.util.Set<String> classifications = dto.scatterPoints().stream()
				.map(org.henbru.antidos.collector.model.SubnetScatterPoint::classification)
				.collect(java.util.stream.Collectors.toSet());
		assertTrue(classifications.contains("HIGH_RISK_RESIDENTIAL"), "Should include residential proxy evasion");
		assertTrue(classifications.contains("DATACENTER_CLUSTER"), "Should include datacenter scrapers");
		assertTrue(classifications.contains("VERIFIED_BOT"), "Should include verified search/AI crawlers");

		// Verify forensic notes appear on scatter points with verdicts
		long withNotes = dto.scatterPoints().stream()
				.filter(org.henbru.antidos.collector.model.SubnetScatterPoint::hasNote)
				.count();
		assertTrue(withNotes >= 3, "Should have multiple annotated subnets with forensic notes");
	}
}
