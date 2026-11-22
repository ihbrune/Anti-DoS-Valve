package org.henbru.antidos.collector.aggregation;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.EndpointRollup;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.EndpointRollupRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class EndpointAnalyticsServiceTest {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private EndpointRollupRepository endpointRollupRepository;

	@Autowired
	private ClientEventRepository clientEventRepository;

	@Autowired
	private EndpointAnalyticsService endpointAnalyticsService;

	@Autowired
	private RollupAggregationService rollupAggregationService;

	@Autowired
	private CollectorProperties properties;

	private final String testServer = "EP-TEST-SERVER";
	private final String testValve = "EP-TEST-VALVE";

	@BeforeEach
	void setUp() {
		cleanupData();
	}

	@AfterEach
	void tearDown() {
		cleanupData();
	}

	private void cleanupData() {
		jdbcTemplate.update("DELETE FROM client_events WHERE server_id = ?", testServer);
		jdbcTemplate.update("DELETE FROM endpoint_rollups WHERE server_id = ?", testServer);
	}

	@Test
	void testNormalizeUri() {
		assertEquals("/", EndpointRollup.normalizeUri(null));
		assertEquals("/", EndpointRollup.normalizeUri(""));
		assertEquals("/", EndpointRollup.normalizeUri("   "));
		assertEquals("/portal/course/catalog", EndpointRollup.normalizeUri("/portal/course/catalog"));
		assertEquals("/portal/course/catalog", EndpointRollup.normalizeUri("/portal/course/catalog/"));
		assertEquals("/portal/course/catalog", EndpointRollup.normalizeUri("/portal/course/catalog?semester=2026&dept=cs"));
		assertEquals("/portal/course/catalog", EndpointRollup.normalizeUri("/portal/course/catalog;jsessionid=ABC123DEF"));
		assertEquals("/portal/course/catalog", EndpointRollup.normalizeUri("portal/course/catalog"));
		assertEquals("/api/v1/search", EndpointRollup.normalizeUri("/api/v1/search?q=test;foo=bar"));
	}

	@Test
	void testIsAutomatedServicePath() {
		assertTrue(endpointAnalyticsService.isAutomatedServicePath("/display/status"));
		assertTrue(endpointAnalyticsService.isAutomatedServicePath("/api/room/tablet-1"));
		assertTrue(endpointAnalyticsService.isAutomatedServicePath("/sync/catalog"));
		assertTrue(endpointAnalyticsService.isAutomatedServicePath("/health"));
		assertTrue(endpointAnalyticsService.isAutomatedServicePath("/healthz"));
		assertTrue(endpointAnalyticsService.isAutomatedServicePath("/actuator/health"));
		assertTrue(endpointAnalyticsService.isAutomatedServicePath("/ping"));
		assertFalse(endpointAnalyticsService.isAutomatedServicePath("/portal/course/catalog"));
		assertFalse(endpointAnalyticsService.isAutomatedServicePath("/login"));
		assertFalse(endpointAnalyticsService.isAutomatedServicePath("/api/v1/search"));
	}

	@Test
	void testCustomConfiguredPrefixesInProperties() {
		List<String> original = properties.getEndpointAnalytics().getExcludedPrefixes();
		try {
			properties.getEndpointAnalytics().setExcludedPrefixes(List.of("/custom-iot", "/internal-sync/v2"));
			assertTrue(endpointAnalyticsService.isAutomatedServicePath("/custom-iot/sensor-1"));
			assertTrue(endpointAnalyticsService.isAutomatedServicePath("/internal-sync/v2/delta"));
			assertFalse(endpointAnalyticsService.isAutomatedServicePath("/portal/course/catalog"));
		} finally {
			properties.getEndpointAnalytics().setExcludedPrefixes(original);
		}
	}

	@Test
	void testGetEndpointAnalyticsWithFilters() {
		Instant now = Instant.now();
		Instant slotTime = now.minus(30, ChronoUnit.MINUTES);

		// Event 1: Public course catalog target - 500 requests, 500 blocked
		ClientEvent ev1 = new ClientEvent(
				null, testServer, testValve, 1L, slotTime, "198.51.100.5",
				4, 32, 3325256709L, 3325256709L, null, null, "198.51.100.0/24",
				500, 0, true, ClientEvent.STATUS_BLOCKED, true, now,
				64512L, "Cloud Host", "US", ClientType.DATACENTER,
				org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED, null,
				1, 1, 0, 0, 0,
				"GET", "/portal/course/catalog?dept=math", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				false, false
		);

		// Event 2: Public course catalog target from different IP with cookie - 200 requests, ACTIVE
		ClientEvent ev2 = new ClientEvent(
				null, testServer, testValve, 1L, slotTime, "198.51.100.20",
				4, 32, 3325256724L, 3325256724L, null, null, "198.51.100.0/24",
				200, 0, false, ClientEvent.STATUS_ACTIVE, true, now,
				64512L, "Cloud Host", "US", ClientType.DATACENTER,
				org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED, null,
				1, 1, 50, 50, 0,
				"GET", "/portal/course/catalog;jsessionid=XYZ", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				true, true
		);

		// Event 3: Door display internal automation - 1000 requests, ACTIVE, internal RFC 1918
		ClientEvent ev3 = new ClientEvent(
				null, testServer, testValve, 1L, slotTime, "10.0.50.12",
				4, 32, 167784972L, 167784972L, null, null, "10.0.50.0/24",
				1000, 0, false, ClientEvent.STATUS_ACTIVE, true, now,
				null, "Campus LAN", null, ClientType.INTERNAL_NETWORK,
				org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED, null,
				1, 1, 0, 0, 0,
				"GET", "/display/status", "IoT-RoomSign/1.0",
				false, false
		);

		clientEventRepository.batchUpsert(List.of(ev1, ev2, ev3));

		// Query unfiltered: Should contain both "/portal/course/catalog" and "/display/status"
		var allAnalytics = endpointAnalyticsService.getEndpointAnalytics(
				1, List.of(testServer), List.of(testValve), false, false, "ALL", 10);
		assertEquals(2, allAnalytics.endpoints().size());
		assertEquals(1700L, allAnalytics.totalSampledRequests());
		assertEquals(1000L, allAnalytics.totalInternalRequests());
		assertEquals(500L, allAnalytics.totalBlockedRequests());

		// Query excluding automated background services: Should filter out "/display/status"
		var noAutomated = endpointAnalyticsService.getEndpointAnalytics(
				1, List.of(testServer), List.of(testValve), false, true, "ALL", 10);
		assertEquals(1, noAutomated.endpoints().size());
		assertEquals("/portal/course/catalog", noAutomated.endpoints().get(0).cleanEndpoint());
		assertEquals(700L, noAutomated.endpoints().get(0).totalRequests());
		assertEquals(500L, noAutomated.endpoints().get(0).blockedRequests());
		assertEquals(200L, noAutomated.endpoints().get(0).activeRequests());
		assertEquals(1, noAutomated.endpoints().get(0).returningSamples());
		assertEquals(1, noAutomated.endpoints().get(0).authSamples());

		// Query BLOCKED only: Should only return "/portal/course/catalog"
		var blockedOnly = endpointAnalyticsService.getEndpointAnalytics(
				1, List.of(testServer), List.of(testValve), false, false, "BLOCKED", 10);
		assertEquals(1, blockedOnly.endpoints().size());
		assertEquals("/portal/course/catalog", blockedOnly.endpoints().get(0).cleanEndpoint());
	}

	@Test
	void testEndpointDrilldown() {
		Instant now = Instant.now();
		Instant slotTime = now.minus(15, ChronoUnit.MINUTES);

		ClientEvent ev1 = new ClientEvent(
				null, testServer, testValve, 1L, slotTime, "198.51.100.10",
				4, 32, 3325256714L, 3325256714L, null, null, "198.51.100.0/24",
				300, 0, true, ClientEvent.STATUS_BLOCKED, true, now,
				64512L, "Hosting Provider", "DE", ClientType.DATACENTER,
				org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED, null,
				1, 1, 0, 0, 0,
				"GET", "/portal/course/catalog?id=42", "ScraperBot/2.0",
				false, false
		);
		clientEventRepository.batchUpsert(List.of(ev1));

		var drilldown = endpointAnalyticsService.getEndpointDrilldown(
				"/portal/course/catalog", "GET", 1, List.of(testServer), List.of(testValve));

		assertNotNull(drilldown);
		assertEquals("/portal/course/catalog", drilldown.cleanEndpoint());
		assertEquals("GET", drilldown.sampleMethod());
		assertEquals(300L, drilldown.totalRequests());
		assertEquals(300L, drilldown.blockedRequests());
		assertFalse(drilldown.topSubnets().isEmpty());
		assertEquals("198.51.100.0/24", drilldown.topSubnets().get(0).subnetGroup());
		assertEquals(64512L, drilldown.topSubnets().get(0).asn());
		assertFalse(drilldown.topUserAgents().isEmpty());
		assertEquals("ScraperBot/2.0", drilldown.topUserAgents().get(0).userAgent());
	}

	@Test
	void testRollupAggregationServicePersistsEndpointRollups() {
		Instant now = Instant.now().truncatedTo(ChronoUnit.HOURS);
		Instant bucketStart = now.minus(2, ChronoUnit.HOURS);
		Instant bucketEnd = bucketStart.plus(1, ChronoUnit.HOURS);

		ClientEvent ev = new ClientEvent(
				null, testServer, testValve, 1L, bucketStart.plus(10, ChronoUnit.MINUTES), "198.51.100.100",
				4, 32, 3325256804L, 3325256804L, null, null, "198.51.100.0/24",
				400, 0, false, ClientEvent.STATUS_ACTIVE, true, now,
				64512L, "Hosting Provider", "DE", ClientType.DATACENTER,
				org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED, null,
				1, 1, 50, 50, 0,
				"GET", "/api/v1/search?term=testing", "SearchClient/1.0",
				true, true
		);
		clientEventRepository.batchUpsert(List.of(ev));

		int persisted = rollupAggregationService.aggregateEndpointsWindow(bucketStart, bucketEnd);
		assertTrue(persisted > 0);

		List<EndpointRollupRepository.EndpointSummary> top = endpointRollupRepository.findTopEndpoints(
				bucketStart.minusSeconds(1), bucketEnd.plusSeconds(1), List.of(testServer), List.of(testValve), false, "ALL", 10);
		assertEquals(1, top.size());
		assertEquals("/api/v1/search", top.get(0).cleanEndpoint());
		assertEquals("GET", top.get(0).sampleMethod());
		assertEquals(400L, top.get(0).totalRequests());
	}
}
