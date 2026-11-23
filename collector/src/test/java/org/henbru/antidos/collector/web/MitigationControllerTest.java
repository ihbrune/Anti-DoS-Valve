package org.henbru.antidos.collector.web;

import org.henbru.antidos.collector.mitigation.MitigationService;
import org.henbru.antidos.collector.model.MitigationUaRule;
import org.henbru.antidos.collector.storage.MitigationUaRuleRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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

	@Autowired
	private MitigationUaRuleRepository uaRuleRepository;

	@AfterEach
	void tearDown() {
		mitigationService.revokeAll("Test teardown", "admin");
		mitigationService.revokeAllUaBlocks("Test teardown", "admin");
		mitigationService.resetUaAutoSettingsToDefaults("admin");
	}

	@Test
	void testGetMitigationPageDefaultActiveTabEmpty() throws Exception {
		// Default start tab is Fleet Overview
		mockMvc.perform(get("/mitigation"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Fleet Overview")))
				.andExpect(content().string(containsString("Active Dynamic CIDR Blocks")))
				.andExpect(content().string(containsString("Active Dynamic UA Blocks")))
				.andExpect(content().string(containsString("Mitigation-Capable Fleet Valves")))
				.andExpect(content().string(containsString("Recently Expired &amp; Revoked")))
				.andExpect(content().string(containsString("Open Full Audit Trail")));

		// CIDR & ASN Defense tab holds active CIDR rules and settings without repeating Fleet Overview cards
		mockMvc.perform(get("/mitigation").param("tab", "active"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Active Dynamic CIDR Mitigations")))
				.andExpect(content().string(containsString("No dynamic CIDR blocks are currently active.")));
	}

	@Test
	void testGetMitigationPageWithActiveRules() throws Exception {
		mitigationService.createOrUpdateBlock("198.51.100.0/24", 60, "MANUAL", "TEST-BATCH", "Test Attack Block", "admin");

		mockMvc.perform(get("/mitigation"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Fleet Overview")))
				.andExpect(content().string(containsString("Active Dynamic CIDR Blocks")))
				.andExpect(content().string(containsString("Active Dynamic UA Blocks")));

		mockMvc.perform(get("/mitigation").param("tab", "active"))
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

	@Test
	void testUserAgentDefenseTabManualLifecycleAndAuditFilter() throws Exception {
		String testUa = "Mozilla/5.0 Chrome/151.0.0.0 ExampleScraper";

		// Tab 1 explicitly labeled CIDR & ASN Defense; Tab 2 User-Agent Defense rendered cleanly
		mockMvc.perform(get("/mitigation"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("CIDR &amp; ASN Defense")))
				.andExpect(content().string(containsString("User-Agent Defense")));

		mockMvc.perform(get("/mitigation").param("tab", "useragents").param("prefillUa", testUa))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Autonomous User-Agent Defense Engine")))
				.andExpect(content().string(containsString("Create Dynamic User-Agent Block")))
				.andExpect(content().string(containsString("Chrome/151.0.0.0 ExampleScraper")));

		// Pre-flight HTMX check
		mockMvc.perform(post("/mitigation/ua/preflight").param("uaInput", testUa))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Pre-Flight Safety Check Passed")))
				.andExpect(content().string(containsString("32-bit FNV-1a:")));

		// Manual block via controller
		mockMvc.perform(post("/mitigation/ua/block")
						.param("uaInput", testUa)
						.param("ttlMinutes", "120")
						.param("reason", "Manual UA defense verification"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Dynamic User-Agent block active")))
				.andExpect(content().string(containsString("ExampleScraper")));

		MitigationUaRule rule = uaRuleRepository.findByRawUserAgent(testUa, "ALL").orElseThrow();

		// Active Dynamic UA Blocks and Pre-Flight must use consistent 32-bit FNV-1a hex + UA:<int>, with no SHA-256 label
		mockMvc.perform(get("/fragments/mitigation-content").param("tab", "useragents"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString(rule.hexHash32())))
				.andExpect(content().string(containsString("UA:" + rule.uaHash32())))
				.andExpect(content().string(not(containsString("SHA-256:"))));

		mockMvc.perform(post("/mitigation/ua/preflight").param("uaInput", testUa))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString(rule.hexHash32())))
				.andExpect(content().string(containsString("(UA:" + rule.uaHash32() + ")")));

		// Extend & revoke via controller
		mockMvc.perform(post("/mitigation/ua/" + rule.id() + "/extend").param("additionalMinutes", "60"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Extended User-Agent rule")));

		mockMvc.perform(post("/mitigation/ua/" + rule.id() + "/revoke").param("reason", "Done testing"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Revoked dynamic User-Agent block")));

		// Toggle UA auto defense settings
		mockMvc.perform(post("/mitigation/ua/auto/toggle").param("property", "enabled"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("DRY-RUN SIMULATION")));

		// Unified Audit Trail target filter
		mockMvc.perform(get("/fragments/mitigation-content")
						.param("tab", "audit")
						.param("auditTargetType", "USER_AGENT"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("UA_BLOCK")))
				.andExpect(content().string(containsString("UA_EXTEND")))
				.andExpect(content().string(containsString("UA_REVOKE")))
				.andExpect(content().string(containsString("/mitigation?tab=useragents")))
				.andExpect(content().string(containsString("prefillUa=")))
				.andExpect(content().string(containsString("/analytics/user-agent-drilldown")))
				.andExpect(content().string(org.hamcrest.Matchers.not(containsString("/offenders?clientQuery=UA"))));


		assertEquals(0, mitigationService.getActiveUaRules().size());
	}
}

