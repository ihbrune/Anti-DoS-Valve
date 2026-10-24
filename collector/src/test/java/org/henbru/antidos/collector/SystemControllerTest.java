package org.henbru.antidos.collector;

import org.henbru.antidos.collector.system.SystemStatusDto;
import org.henbru.antidos.collector.system.SystemStatusService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@SuppressWarnings("null")
class SystemControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private SystemStatusService systemStatusService;

	@Test
	void testSystemPageLoadsSuccessfully() throws Exception {
		mockMvc.perform(get("/system"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("System Status &amp; Configuration")))
				.andExpect(content().string(containsString("Data Retention &amp; Housekeeping")))
				.andExpect(content().string(containsString("Database Storage &amp; Internals")))
				.andExpect(content().string(containsString("Fleet &amp; Polling Configuration")))
				.andExpect(content().string(containsString("Telemetry &amp; Active Tracking (3-Tier Cascade)")))
				.andExpect(content().string(containsString("Threat Intelligence &amp; Enrichment State")))
				.andExpect(content().string(containsString("Runtime &amp; Environment")))
				.andExpect(content().string(containsString("Run Retention Cleanup Now")))
				.andExpect(content().string(containsString("Catch Up Subnet Rollups")))
				.andExpect(content().string(containsString("Clear Resolver Cache")));
	}

	@Test
	void testSettingsAliasLoadsSuccessfully() throws Exception {
		mockMvc.perform(get("/settings"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("System Status &amp; Configuration")));
	}

	@Test
	void testRetentionCleanupTrigger() throws Exception {
		mockMvc.perform(post("/system/retention-cleanup"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Retention cleanup executed successfully")));
	}

	@Test
	void testRollupCatchUpTrigger() throws Exception {
		mockMvc.perform(post("/system/rollup-catchup"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Subnet rollup catch-up executed successfully")));
	}

	@Test
	void testClearCacheTrigger() throws Exception {
		mockMvc.perform(post("/system/clear-cache"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Entity resolution in-memory cache cleared successfully")));
	}

	@Test
	void testSystemStatusServiceDiagnostics() {
		SystemStatusDto dto = systemStatusService.getSystemStatus();
		assertNotNull(dto);
		assertNotNull(dto.config());
		assertNotNull(dto.database());
		assertNotNull(dto.schedulers());
		assertNotNull(dto.intel());
		assertNotNull(dto.runtime());
		assertNotNull(dto.fleetHealth());

		assertTrue(dto.config().pollIntervalSeconds() > 0);
		assertTrue(dto.config().retentionDays() > 0);
		assertNotNull(dto.intel().asnMmdb());
		assertNotNull(dto.intel().countryMmdb());
		assertTrue(dto.database().tableCounts().containsKey("slot_snapshots"));
		assertTrue(dto.database().tableCounts().containsKey("client_events"));
		assertTrue(dto.database().tableCounts().containsKey("client_subnet_rollups"));
		assertNotNull(dto.runtime().javaVersion());
		assertTrue(dto.runtime().availableProcessors() > 0);

		assertEquals("500 B", SystemStatusService.formatBytes(500));
		assertEquals("1.5 KB", SystemStatusService.formatBytes(1536));
		assertEquals("10.0 MB", SystemStatusService.formatBytes(10 * 1024 * 1024));
		assertEquals("2.00 GB", SystemStatusService.formatBytes(2L * 1024 * 1024 * 1024));

		assertEquals("45s", SystemStatusService.formatDuration(45));
		assertEquals("2m 30s", SystemStatusService.formatDuration(150));
		assertEquals("1h 15m 0s", SystemStatusService.formatDuration(4500));
		assertEquals("2d 3h 0m", SystemStatusService.formatDuration(183600));
	}
}
