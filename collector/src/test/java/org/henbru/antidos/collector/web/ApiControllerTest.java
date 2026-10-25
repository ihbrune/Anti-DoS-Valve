package org.henbru.antidos.collector.web;

import java.time.Instant;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@SuppressWarnings("null")
class ApiControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private MonitoredValveRepository monitoredValveRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@BeforeEach
	void setUp() {
		jdbcTemplate.update("DELETE FROM monitored_valves");
	}

	@Test
	void testGetValvesApi() throws Exception {
		Instant now = Instant.now();
		MonitoredValve v1 = new MonitoredValve(
				"SERVER-ALPHA",
				"Edge-Limiter",
				"Alpha Edge Limiter",
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
				"*.css",
				"127.0.0.1",
				null,
				"/antidos-status",
				"127.0.0.1",
				now,
				11111
		);
		MonitoredValve v2 = new MonitoredValve(
				"SERVER-BETA",
				"Backend-Limiter",
				"Beta Backend Limiter",
				1,
				"MARKING",
				true,
				false,
				429,
				200,
				60,
				5,
				0.75f,
				24,
				48,
				20000,
				10000,
				null,
				null,
				null,
				null,
				"/antidos-status",
				null,
				"true",
				now,
				22222
		);
		monitoredValveRepository.upsert(v1);
		monitoredValveRepository.upsert(v2);

		// 1. List all valves
		mockMvc.perform(get("/api/v1/valves"))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$", hasSize(2)))
				.andExpect(jsonPath("$[0].serverId", is("SERVER-ALPHA")))
				.andExpect(jsonPath("$[0].valveName", is("Edge-Limiter")))
				.andExpect(jsonPath("$[0].allowedRequestsPerSlot", is(100)))
				.andExpect(jsonPath("$[0].collectorIntegration", is("auto")))
				.andExpect(jsonPath("$[1].serverId", is("SERVER-BETA")))
				.andExpect(jsonPath("$[1].valveName", is("Backend-Limiter")))
				.andExpect(jsonPath("$[1].monitorMode", is("MARKING")))
				.andExpect(jsonPath("$[1].collectorIntegration", is("true")));

		// 2. Filter by serverId
		mockMvc.perform(get("/api/v1/valves?serverId=SERVER-ALPHA"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$", hasSize(1)))
				.andExpect(jsonPath("$[0].serverId", is("SERVER-ALPHA")))
				.andExpect(jsonPath("$[0].relevantPaths", is("/api/*")));

		// 3. Get single valve
		mockMvc.perform(get("/api/v1/valves/Edge-Limiter?serverId=SERVER-ALPHA"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.serverId", is("SERVER-ALPHA")))
				.andExpect(jsonPath("$.valveName", is("Edge-Limiter")))
				.andExpect(jsonPath("$.ipv4SubnetMask", is(32)))
				.andExpect(jsonPath("$.ipv6SubnetMask", is(64)));

		// 4. Get non-existent valve
		mockMvc.perform(get("/api/v1/valves/Non-Existent?serverId=SERVER-ALPHA"))
				.andExpect(status().isNotFound());
	}
}
