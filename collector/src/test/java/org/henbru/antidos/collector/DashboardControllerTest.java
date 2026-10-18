package org.henbru.antidos.collector;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@SuppressWarnings("null")
class DashboardControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void testIndexPageLoads() throws Exception {
		mockMvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Anti-DoS Fleet Manager")))
				.andExpect(content().string(containsString("Monitored Server Nodes")))
				.andExpect(content().string(containsString("hx-target=\"#fleet-container\" hx-swap=\"outerHTML\"")));
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

		mockMvc.perform(get("/fragments/events-table")
						.param("clientQuery", "198.51.100.")
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

		mockMvc.perform(get("/fragments/offenders-table")
						.param("groupBy", "SUBNET")
						.param("limit", "25"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("offenders-table-container")));
	}

	@Test
	void testServerDetailsPageLoads() throws Exception {
		mockMvc.perform(get("/server/Demo-Server"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Demo-Server")))
				.andExpect(content().string(containsString("Node Incidents")))
				.andExpect(content().string(containsString("Blocked Client Incidents on this Server")));
	}
}
