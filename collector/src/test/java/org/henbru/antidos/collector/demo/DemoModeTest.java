package org.henbru.antidos.collector.demo;

import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.model.ValveDetailsDto;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
		"collector.demo-mode=true",
		"spring.datasource.url=jdbc:sqlite:target/demo-test.db"
})
@SuppressWarnings("null")
class DemoModeTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private MockValveSimulator simulator;

	@Autowired
	private CollectorProperties properties;

	@Autowired
	private com.fasterxml.jackson.databind.ObjectMapper objectMapper;

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
		assertEquals(2, overview.valves().size());
		assertEquals("Primary-Rate-Limiter", overview.valves().getFirst().monitorName());

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
	}

	@Test
	void testMockSimulatorOverviewAndDetails() {
		ValveOverviewDto overview = simulator.buildOverview("edge-eu", null);
		assertNotNull(overview);
		assertNotNull(overview.serverTime());
		assertEquals(2, overview.valves().size(), "Edge node should provide 2 valves");

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

		ValveDetailsDto apiDetails = simulator.buildDetails("api-gateway", "API-DoS-Shield", "previous", "all");
		assertNotNull(apiDetails);
		assertFalse(apiDetails.blockedClients().isEmpty(), "API gateway under attack should list blocked clients");
	}

	@Test
	void testMockControllerAuthentication() throws Exception {
		// 1. Without Token -> 401
		mockMvc.perform(get("/mock-valve/edge-eu/antidos-status"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error", containsString("Unauthorized")));

		// 2. With Wrong Token -> 401
		mockMvc.perform(get("/mock-valve/edge-eu/antidos-status")
						.header("Authorization", "Bearer invalid-token"))
				.andExpect(status().isUnauthorized());

		// 3. With Valid Token -> 200 OK Overview
		mockMvc.perform(get("/mock-valve/edge-eu/antidos-status")
						.header("Authorization", "Bearer demo-token"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.valves", hasSize(2)))
				.andExpect(jsonPath("$.valves[0].monitorName", is("Primary-Rate-Limiter")));
	}

	@Test
	void testDashboardRendersDemoBanner() throws Exception {
		mockMvc.perform(get("/"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("DEMO MODE ACTIVE")))
				.andExpect(content().string(containsString("antidos-collector-demo.db")))
				.andExpect(content().string(containsString("simulated Anti-DoS Valve endpoints")));
	}
}
