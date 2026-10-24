package org.henbru.antidos.collector;

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

	@Test
	void testIndexPageLoads() throws Exception {
		mockMvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Anti-DoS Fleet Manager")))
				.andExpect(content().string(containsString("Monitored Server Nodes")))
				.andExpect(content().string(containsString("/js/htmx.min.js")))
				.andExpect(content().string(not(containsString("unpkg.com"))))
				.andExpect(content().string(containsString("hx-target=\"#stats-overview\" hx-swap=\"outerHTML\"")))
				.andExpect(content().string(containsString("hx-target=\"#fleet-container\" hx-swap=\"outerHTML\"")));
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
				.andExpect(content().string(containsString("offender-container")));
	}

	@Test
	void testRecentEventsFragment() throws Exception {
		mockMvc.perform(get("/fragments/recent-events"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("events-container")));
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
		mockMvc.perform(get("/fragments/poll-log").param("status", "ALL"))
				.andExpect(status().isOk());
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
	void testServerDetailsPageLoads() throws Exception {
		java.time.Instant now = java.time.Instant.now();
		slotSnapshotRepository.upsert(new org.henbru.antidos.collector.model.SlotSnapshot(
				null, "Demo-Server", "TEST-VALVE", 55555L,
				now.minusSeconds(60), now, 1250L, 10, 2, true, now
		));

		clientEventRepository.batchUpsert(List.of(new org.henbru.antidos.collector.model.ClientEvent(
				null, "Demo-Server", "TEST-VALVE", 55555L,
				now.minusSeconds(60), "198.51.100.42",
				4, 32, null, null, null, null, "198.51.100.0/24",
				15, 0, false, org.henbru.antidos.collector.model.ClientEvent.STATUS_BLOCKED, true, now,
				8075L, "OpenAI / Microsoft", "US",
				org.henbru.antidos.collector.model.ClientType.AI_CRAWLER,
				org.henbru.antidos.collector.model.EnrichmentStatus.ENRICHED
		)));

		mockMvc.perform(get("/server/Demo-Server"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Demo-Server")))
				.andExpect(content().string(containsString("Node Incidents")))
				.andExpect(content().string(containsString("Monitored Valves &amp; Active Tracking Configuration")))
				.andExpect(content().string(containsString("Global Default")))
				.andExpect(content().string(containsString("Blocked Client Incidents on this Server")))
				.andExpect(content().string(containsString("55555")))
				.andExpect(content().string(containsString("TEST-VALVE")))
				.andExpect(content().string(containsString("AI Bot")))
				.andExpect(content().string(containsString("AS8075")))
				.andExpect(content().string(containsString("View Incidents &rarr;")));
	}

	@Test
	void testHelpPageLoads() throws Exception {
		mockMvc.perform(get("/help"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Anti-DoS Fleet Manager")))
				.andExpect(content().string(containsString("Documentation &amp; Forensics Guide")))
				.andExpect(content().string(containsString("Contents &amp; Topics")))
				.andExpect(content().string(containsString("Release Embedded Manual")))
				.andExpect(content().string(containsString("100% Offline &amp; Air-Gap Ready")))
				.andExpect(content().string(containsString("Zero-Configuration Demo Mode")))
				.andExpect(content().string(containsString("id=\"zero-configuration-demo-mode\"")));
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
}

