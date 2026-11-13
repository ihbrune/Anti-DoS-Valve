package org.henbru.antidos.collector.web;

import org.henbru.antidos.collector.mitigation.MitigationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@SuppressWarnings("null")
class MitigationControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private MitigationService mitigationService;

	@AfterEach
	void tearDown() {
		mitigationService.revokeAll("Test teardown", "admin");
	}

	@Test
	void testGetMitigationPageDefaultActiveTabEmpty() throws Exception {
		mockMvc.perform(get("/mitigation"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Active Dynamic CIDR Mitigations")))
				.andExpect(content().string(containsString("No dynamic CIDR blocks are currently active.")))
				.andExpect(content().string(containsString("Recently Expired &amp; Revoked")))
				.andExpect(content().string(containsString("Open Full Audit Trail")));
	}

	@Test
	void testGetMitigationPageWithActiveRules() throws Exception {
		mitigationService.createOrUpdateBlock("198.51.100.0/24", 60, "MANUAL", "TEST-BATCH", "Test Attack Block", "admin");

		mockMvc.perform(get("/mitigation"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Active Dynamic CIDR Mitigations")))
				.andExpect(content().string(containsString("active-rules-search")))
				.andExpect(content().string(containsString("Still Attacking")))
				.andExpect(content().string(containsString("Blocked Traffic &gt; 0")))
				.andExpect(content().string(containsString("198.51.100.0/24")));
	}

	@Test
	void testGetMitigationHistoryTab() throws Exception {
		mockMvc.perform(get("/mitigation?tab=history"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Historical Mitigation Rules Explorer")))
				.andExpect(content().string(containsString("historySearch")))
				.andExpect(content().string(containsString("historyStatus")))
				.andExpect(content().string(containsString("historyLimit")));
	}

	@Test
	void testGetMitigationAuditTab() throws Exception {
		mockMvc.perform(get("/mitigation?tab=audit"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Mitigation Audit Trail &amp; Lifecycle Events")))
				.andExpect(content().string(containsString("auditSearch")))
				.andExpect(content().string(containsString("auditAction")))
				.andExpect(content().string(containsString("auditActor")));
	}

	@Test
	void testGetMitigationContentFragment() throws Exception {
		mockMvc.perform(get("/fragments/mitigation-content?tab=history&historySearch=192.168"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Historical Mitigation Rules Explorer")));

		mockMvc.perform(get("/fragments/mitigation-content?tab=audit&auditAction=AUTO_BLOCK"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Mitigation Audit Trail &amp; Lifecycle Events")));

		mockMvc.perform(get("/fragments/mitigation-content?tab=audit&auditAction=DRY_RUN_SIMULATION"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("DRY_RUN_SIMULATION")));
	}
}

