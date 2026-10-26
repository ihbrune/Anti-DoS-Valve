package org.henbru.antidos.collector;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@SuppressWarnings("null")
class DashboardControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private org.henbru.antidos.collector.storage.SlotSnapshotRepository slotSnapshotRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.ClientEventRepository clientEventRepository;

	@Autowired
	private org.henbru.antidos.collector.storage.MonitoredValveRepository monitoredValveRepository;

	@Autowired
	private org.henbru.antidos.collector.annotation.NetworkAnnotationService annotationService;

	@Autowired
	private org.henbru.antidos.collector.storage.PollEventLogRepository pollEventLogRepository;

	@Test
	void testIndexPageLoads() throws Exception {
		mockMvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Anti-DoS Fleet Manager")))
				.andExpect(content().string(containsString("Monitored Server Nodes")))
				.andExpect(content().string(containsString("/js/htmx.min.js")))
				.andExpect(content().string(not(containsString("unpkg.com"))))
				.andExpect(content().string(containsString("hx-target=\"#stats-overview\" hx-swap=\"outerHTML\"")))
				.andExpect(content().string(containsString("hx-target=\"#fleet-container\" hx-swap=\"outerHTML\"")))
				.andExpect(content().string(containsString("id=\"note-modal-container\"")));
	}

	@Test
	void testLocalHtmxStaticAssetServed() throws Exception {
		mockMvc.perform(get("/js/htmx.min.js"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("htmx")));
	}

	@Test
	void testStatsOverviewFragment() throws Exception {
		mockMvc.perform(get("/fragments/stats-overview"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("stats-overview")))
				.andExpect(content().string(containsString("Total Requests (24h)")));
	}

	@Test
	void testFleetFragment() throws Exception {
		mockMvc.perform(get("/fragments/fleet"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("endpoint-grid")));
	}

	@Test
	void testTopOffendersFragment() throws Exception {
		mockMvc.perform(get("/fragments/top-offenders").param("hours", "24"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("offender-container")))
				.andExpect(content().string(containsString("annotationChanged from:body")));
	}

	@Test
	void testRecentEventsFragment() throws Exception {
		mockMvc.perform(get("/fragments/recent-events"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("events-container")))
				.andExpect(content().string(containsString("annotationChanged from:body")));
	}

	@Test
	void testFleetJsonApi() throws Exception {
		mockMvc.perform(get("/api/v1/fleet"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.summary").exists())
				.andExpect(jsonPath("$.endpoints").isArray());
	}

	@Test
	void testBlockedIpReputationExportTextAndJson() throws Exception {
		mockMvc.perform(get("/api/v1/reputation/blocked-ips").param("format", "text"))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith("text/plain"));

		mockMvc.perform(get("/api/v1/reputation/blocked-ips").param("format", "json"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.blockedIps").isArray());
	}

	@Test
	void testPollLogPageLoads() throws Exception {
		mockMvc.perform(get("/poll-log"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Collector Polling Events")))
				.andExpect(content().string(containsString("Total Polls (24h)")))
				.andExpect(content().string(containsString("Poll Timestamp")));
	}

	@Test
	void testPollLogFragmentLoads() throws Exception {
		pollEventLogRepository.insert(new org.henbru.antidos.collector.model.PollEventLog(
				null, "TEST-LOG-NODE", "http://test:8080/antidos-status",
				Instant.now(), "SUCCESS", 200, 45L, 2, 2, 105, 5,
				"Polled 2 valve(s), 2 slot(s), 105 event(s) (5 blocked, 100 active)", null
		));

		mockMvc.perform(get("/fragments/poll-log").param("status", "ALL"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("TEST-LOG-NODE")))
				.andExpect(content().string(containsString("5 blocked")))
				.andExpect(content().string(containsString("100 active")))
				.andExpect(content().string(not(containsString("105 blocked"))));
	}

	@Test
	void testPollLogJsonApi() throws Exception {
		mockMvc.perform(get("/api/v1/poll-log"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$").isArray());
	}

	@Test
	void testEventsPageAndFragment() throws Exception {
		mockMvc.perform(get("/events"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Multi-Server Incident Explorer")))
				.andExpect(content().string(containsString("events-filter-form")));

		mockMvc.perform(get("/events")
						.param("clientTypes", "PRIVATE_NETWORK")
						.param("asn", "3320"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Multi-Server Incident Explorer")));

		mockMvc.perform(get("/events")
						.param("clientTypes", "TOR_EXIT_NODE"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Tor Exit Node")));

		mockMvc.perform(get("/events")
						.param("asn", "Cloudflare"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Multi-Server Incident Explorer")));

		mockMvc.perform(get("/fragments/events-table")
						.param("clientQuery", "198.51.100.")
						.param("clientTypes", "TOR_EXIT_NODE")
						.param("asn", "AS3320")
						.param("limit", "25"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("events-table-container")));
	}

	@Test
	void testOffendersPageAndFragment() throws Exception {
		mockMvc.perform(get("/offenders"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Top Offender Analytics &amp; Subnet Rollup")))
				.andExpect(content().string(containsString("Subnet Rollup (/24 &amp; /64)")));

		mockMvc.perform(get("/offenders")
						.param("groupBy", "ASN")
						.param("clientTypes", "DATACENTER")
						.param("asn", "8075"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("ASN Rollup (Fleet Autonomous System)")));

		mockMvc.perform(get("/offenders")
						.param("asn", "Amazon"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Top Offender Analytics &amp; Subnet Rollup")));

		mockMvc.perform(get("/fragments/offenders-table")
						.param("groupBy", "SUBNET")
						.param("limit", "25"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("offenders-table-container")));

		mockMvc.perform(get("/fragments/offenders-table")
						.param("groupBy", "ASN")
						.param("clientTypes", "PRIVATE_NETWORK")
						.param("limit", "25"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("offenders-table-container")));
	}

	@Test
	void testOffendersAsnRollupNoteIntegration() throws Exception {
		annotationService.saveAnnotation(null,
				org.henbru.antidos.collector.model.AnnotationTargetType.ASN,
				"AS24940",
				org.henbru.antidos.collector.model.AnnotationVerdict.SUSPICIOUS,
				"Hetzner Scanners");

		mockMvc.perform(get("/fragments/offenders-table")
						.param("groupBy", "ASN")
						.param("limit", "25"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("AS24940")))
				.andExpect(content().string(containsString("targetType=ASN")))
				.andExpect(content().string(containsString("targetKey=AS24940")))
				.andExpect(content().string(containsString("ASN Note: Suspicious")))
				.andExpect(content().string(containsString("href=\"/events?asn=24940\"")));
	}

	@Test
	void testServerDetailsPageLoads() throws Exception {
		java.time.Instant now = java.time.Instant.now();
		slotSnapshotRepository.upsert(new org.henbru.antidos.collector.model.SlotSnapshot(
				null, "Demo-Server", "TEST-VALVE", 55555L,
				now.minusSeconds(60), now, 1250L, 10, 2, true, now
		));

		clientEventRepository.batchUpsert(List.of(
				new org.henbru.antidos.collector.model.ClientEvent(
						null, "Demo-Server", "TEST-VALVE", 55555L,
						now.minusSeconds(60), "198.51.100.42",
						4, 32, null, null, null, null, "198.51.100.0/24",
						15, 0, false, org.henbru.antidos.collector.model.ClientEvent.STATUS_BLOCKED, true, now,
						8075L, "OpenAI / Microsoft", "US",
						org.henbru.antidos.collector.model.ClientType.AI_CRAWLER,
						org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
				),
				new org.henbru.antidos.collector.model.ClientEvent(
						null, "Demo-Server", "TEST-VALVE", 55555L,
						now.minusSeconds(60), "198.51.100.99",
						4, 32, null, null, null, null, "198.51.100.0/24",
						5, 0, false, org.henbru.antidos.collector.model.ClientEvent.STATUS_ACTIVE, true, now,
						8075L, "OpenAI / Microsoft", "US",
						org.henbru.antidos.collector.model.ClientType.AI_CRAWLER,
						org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
				)
		));

		monitoredValveRepository.upsert(new org.henbru.antidos.collector.model.MonitoredValve(
				"Demo-Server", "TEST-VALVE", "Primary edge rate limiter", 1,
				"BLOCKING", false, false, 429,
				100, 60, 5, 0.8f,
				32, 64, 10000, 5000,
				"/api/*", "*.css", "127.0.0.1", "198.51.100.0/24",
				"/antidos-status", "127.0.0.1", now, 12345
		));

		mockMvc.perform(get("/server/Demo-Server"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Demo-Server")))
				.andExpect(content().string(containsString("Node Incidents")))
				.andExpect(content().string(containsString("Monitored Valves &amp; Active Tracking Configuration")))
				.andExpect(content().string(containsString("Global Default")))
				.andExpect(content().string(containsString("Client Traffic &amp; Incidents on this Server")))
				.andExpect(content().string(containsString("All Traffic")))
				.andExpect(content().string(containsString("Blocked Only")))
				.andExpect(content().string(containsString("Active Monitored")))
				.andExpect(content().string(containsString("55555")))
				.andExpect(content().string(containsString("TEST-VALVE")))
				.andExpect(content().string(containsString("AI Bot")))
				.andExpect(content().string(containsString("AS8075")))
				.andExpect(content().string(containsString("198.51.100.42")))
				.andExpect(content().string(containsString("198.51.100.99")))
				.andExpect(content().string(containsString("View Incidents &rarr;")))
				.andExpect(content().string(containsString("Discovered Valve Runtime Configurations")))
				.andExpect(content().string(containsString("Primary edge rate limiter")))
				.andExpect(content().string(containsString("COLLECTOR: AUTO")))
				.andExpect(content().string(containsString("COOKIE: OFF")))
				.andExpect(content().string(containsString("Visitor Tracking &amp; Cookies")))
				.andExpect(content().string(containsString("Collector Integration")))
				.andExpect(content().string(containsString("/32 (IPv4) &bull; /64 (IPv6)")))
				.andExpect(content().string(containsString("100 req / 60s")))
				.andExpect(content().string(containsString("Window: 300s (5 x 60s)")))
				.andExpect(content().string(containsString("Decay: 80%")))
				.andExpect(content().string(containsString("/js/htmx.min.js")))
				.andExpect(content().string(containsString("/js/htmx-lite.js")))
				.andExpect(content().string(containsString("id=\"note-modal-container\"")))
				.andExpect(content().string(containsString("targetType=ASN")));

		// BLOCKED filter
		mockMvc.perform(get("/server/Demo-Server").param("status", "BLOCKED"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Blocked Client Incidents on this Server")))
				.andExpect(content().string(containsString("198.51.100.42")))
				.andExpect(content().string(containsString("count-blocked")))
				.andExpect(content().string(not(containsString("count-active"))))
				.andExpect(content().string(not(containsString("198.51.100.99"))));

		// ACTIVE filter
		mockMvc.perform(get("/server/Demo-Server").param("status", "ACTIVE"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Active Monitored Clients on this Server")))
				.andExpect(content().string(containsString("198.51.100.99")))
				.andExpect(content().string(containsString("count-active")))
				.andExpect(content().string(not(containsString("count-blocked"))));
	}

	@Test
	void testServerDetailsPageValveFiltering() throws Exception {
		java.time.Instant now = java.time.Instant.now();
		monitoredValveRepository.upsert(new org.henbru.antidos.collector.model.MonitoredValve(
				"Demo-Server", "FILTERED-VALVE-A", "Valve A description", 1,
				"BLOCKING", false, false, 429,
				100, 60, 5, 0.8f,
				32, 64, 10000, 5000,
				"/api/*", null, null, null,
				"/antidos-status", null, "true", now, 111
		));
		monitoredValveRepository.upsert(new org.henbru.antidos.collector.model.MonitoredValve(
				"Demo-Server", "FILTERED-VALVE-B", "Valve B description", 2,
				"MARKING", true, false, 429,
				200, 30, 10, 0.5f,
				24, 48, 10000, 5000,
				null, null, null, null,
				"/antidos-status", null, "false", now, 222
		));

		// 1. Unfiltered request: both valve configurations displayed
		mockMvc.perform(get("/server/Demo-Server"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Valve A description")))
				.andExpect(content().string(containsString("Valve B description")))
				.andExpect(content().string(containsString("COLLECTOR: ALWAYS ON")))
				.andExpect(content().string(containsString("COLLECTOR: DISABLED")))
				.andExpect(content().string(not(containsString("(Filtered:"))));

		// 2. Filtered request for VALVE-A: only VALVE-A shown in runtime configuration section
		mockMvc.perform(get("/server/Demo-Server").param("valve", "FILTERED-VALVE-A"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("(Filtered: FILTERED-VALVE-A)")))
				.andExpect(content().string(containsString("Valve A description")))
				.andExpect(content().string(not(containsString("Valve B description"))));

		// 3. Filtered request for non-existing valve: empty state shown
		mockMvc.perform(get("/server/Demo-Server").param("valve", "NON-EXISTENT"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("(Filtered: NON-EXISTENT)")))
				.andExpect(content().string(containsString("No live runtime configuration discovered yet for valve '<span>NON-EXISTENT</span>'.")));
	}

	@Test
	void testHelpPageLoadsUiGuideByDefault() throws Exception {
		mockMvc.perform(get("/help"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Anti-DoS Fleet Manager")))
				.andExpect(content().string(containsString("Documentation &amp; Forensics Guide")))
				.andExpect(content().string(containsString("Contents &amp; Topics")))
				.andExpect(content().string(containsString("Dashboard &amp; Forensics Guide")))
				.andExpect(content().string(containsString("Setup &amp; Operations Reference")))
				.andExpect(content().string(containsString("id=\"fleet-overview-dashboard\"")))
				.andExpect(content().string(containsString("id=\"system-status--configuration\"")));
	}

	@Test
	void testHelpPageLoadsSetupGuide() throws Exception {
		mockMvc.perform(get("/help").param("doc", "setup"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Anti-DoS Fleet Manager")))
				.andExpect(content().string(containsString("Production Setup")))
				.andExpect(content().string(containsString("Database Configuration")))
				.andExpect(content().string(containsString("id=\"zero-configuration-demo-mode\"")));
	}

	@Test
	void testHelpFragmentWithSectionReturnsDrawerSection() throws Exception {
		mockMvc.perform(get("/fragments/help").param("doc", "ui").param("section", "system-status-configuration"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("System Status &amp; Configuration")))
				.andExpect(content().string(containsString("Runtime &amp; Database Telemetry")))
				.andExpect(content().string(containsString("Operational Maintenance Triggers")));
	}

	@Test
	void testHelpFragmentWithServerDetailsSectionReturnsDrawerSection() throws Exception {
		mockMvc.perform(get("/fragments/help").param("doc", "ui").param("section", "server-node-detail-view"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Server Node Detail View")))
				.andExpect(content().string(containsString("Discovered Valve Runtime Configurations")))
				.andExpect(content().string(containsString("Rate Limit Threshold Card")));
	}

	@Test
	void testOffendersPageWithRollupModeLoads() throws Exception {
		mockMvc.perform(get("/offenders").param("groupBy", "ROLLUP"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Top Offender Analytics &amp; Subnet Rollup")))
				.andExpect(content().string(containsString("Subnet Time Rollups (Long-Term)")));
	}

	@Test
	void testOffendersFragmentWithRollupMode() throws Exception {
		mockMvc.perform(get("/fragments/offenders-table").param("groupBy", "ROLLUP"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("id=\"offenders-table-container\"")));
	}

	@Test
	void testApiRollupEndpoints() throws Exception {
		mockMvc.perform(get("/api/v1/rollups/subnets"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.totalCount").exists())
				.andExpect(jsonPath("$.rollups").isArray());

		mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/v1/rollups/subnets/aggregate").param("hours", "1"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("SUCCESS"));
	}

	@Test
	void testStaticChartAssetsServed() throws Exception {
		mockMvc.perform(get("/js/chart.umd.min.js"))
				.andExpect(status().isOk());

		mockMvc.perform(get("/js/collector-charts.js"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("AntiDoSCharts")));
	}

	@Test
	void testAnalyticsOverviewFragmentLoads() throws Exception {
		mockMvc.perform(get("/fragments/analytics-overview").param("hours", "24"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("analytics-container")))
				.andExpect(content().string(containsString("Visual Telemetry &amp; Attack Forensics")))
				.andExpect(content().string(containsString("id=\"analytics-data-payload\">{\"")))
				.andExpect(content().string(not(containsString("id=\"analytics-data-payload\">{&quot;"))));

		mockMvc.perform(get("/analytics"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("analytics-container")))
				.andExpect(content().string(containsString("id=\"analytics-data-payload\">{\"")))
				.andExpect(content().string(not(containsString("id=\"analytics-data-payload\">{&quot;"))));
	}

	@Test
	void testAnalyticsApiEndpoints() throws Exception {
		mockMvc.perform(get("/api/v1/analytics/overview").param("hours", "24"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.timeline").isArray())
				.andExpect(jsonPath("$.composition").isArray())
				.andExpect(jsonPath("$.scatterPoints").isArray());
	}

	@Test
	void testOffendersPageWithProfilesModeLoads() throws Exception {
		mockMvc.perform(get("/offenders").param("groupBy", "PROFILES").param("activityPattern", "SURGE"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Subnet Baselines &amp; Surge Radar")))
				.andExpect(content().string(containsString("Subnet Activity &amp; Anomaly Filter")));
	}

	@Test
	void testOffendersFragmentWithProfilesMode() throws Exception {
		mockMvc.perform(get("/fragments/offenders-table").param("groupBy", "PROFILES"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("id=\"offenders-table-container\"")));
	}

	@Test
	void testApiSubnetProfileEndpoints() throws Exception {
		mockMvc.perform(get("/api/v1/rollups/subnets/profiles"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.total").exists())
				.andExpect(jsonPath("$.profiles").isArray());

		mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/v1/rollups/subnets/profiles/refresh"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("SUCCESS"));
	}

	@Test
	void testOffendersAutoPivotToProfilesWhenPatternProvided() throws Exception {
		mockMvc.perform(get("/fragments/offenders-table")
						.param("groupBy", "CLIENT")
						.param("activityPattern", "SURGE"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("id=\"offenders-table-container\"")))
				.andExpect(content().string(containsString("Subnet &amp; Provider")));
	}

	@Test
	void testOffendersFragmentWithSubnetModeAndPattern() throws Exception {
		mockMvc.perform(get("/fragments/offenders-table")
						.param("groupBy", "SUBNET")
						.param("activityPattern", "DORMANT"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("id=\"offenders-table-container\"")));
	}

	@Test
	void testOffendersFragmentWithRollupModeAndPattern() throws Exception {
		mockMvc.perform(get("/fragments/offenders-table")
						.param("groupBy", "ROLLUP")
						.param("activityPattern", "PROXY_POOL"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("id=\"offenders-table-container\"")));
	}

	@Test
	void testProfilesPageLoads() throws Exception {
		mockMvc.perform(get("/profiles"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Subnet Profiles &amp; Baseline Radar")))
				.andExpect(content().string(containsString("Total Subnets Tracked")))
				.andExpect(content().string(containsString("id=\"profiles-table-container\"")))
				.andExpect(content().string(containsString("id=\"profiles-filter-form\"")));
	}

	@Test
	void testProfilesTableFragmentLoads() throws Exception {
		mockMvc.perform(get("/fragments/profiles-table")
						.param("activityPattern", "ALL")
						.param("sortBy", "SURGE"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("id=\"profiles-table-container\"")));
	}

	@Test
	void testProfilesTableFragmentWithPatternAndSearch() throws Exception {
		mockMvc.perform(get("/fragments/profiles-table")
						.param("activityPattern", "SURGE")
						.param("clientQuery", "195.181.168.")
						.param("sortBy", "REQUESTS"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("id=\"profiles-table-container\"")));
	}

	@Test
	void testHelpFragmentWithSubnetProfilesSection() throws Exception {
		mockMvc.perform(get("/fragments/help")
						.param("doc", "ui")
						.param("section", "subnet-profiles"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Subnet Profiles &amp; Baseline Radar")))
				.andExpect(content().string(containsString("Real-Time KPI Summary Cards")));
	}
}

