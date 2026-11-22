package org.henbru.antidos.collector.diagnosis;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.henbru.antidos.collector.diagnosis.BlockDiagnosisReport.VerdictLevel;
import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.ClientSubnetRollup;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.EnrichmentStatus;
import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.MitigationUaRule;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.MitigationRuleRepository;
import org.henbru.antidos.collector.storage.MitigationUaRuleRepository;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.henbru.antidos.collector.storage.SubnetRollupRepository;
import org.henbru.antidos.collector.storage.UserAgentMemoryRepository;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest
class BlockDiagnosisServiceTest {

	@Autowired
	private BlockDiagnosisService blockDiagnosisService;

	@Autowired
	private MonitoredValveRepository monitoredValveRepository;

	@Autowired
	private MitigationRuleRepository mitigationRuleRepository;

	@Autowired
	private MitigationUaRuleRepository mitigationUaRuleRepository;

	@Autowired
	private ClientEventRepository clientEventRepository;

	@Autowired
	private SubnetRollupRepository subnetRollupRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@AfterEach
	void cleanup() {
		jdbcTemplate.update("DELETE FROM client_events WHERE server_id LIKE 'DIAG-%'");
		jdbcTemplate.update("DELETE FROM client_subnet_rollups WHERE server_id LIKE 'DIAG-%'");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id LIKE 'DIAG-%'");
		jdbcTemplate.update("DELETE FROM mitigation_rules WHERE batch_id LIKE 'DIAG-%'");
		jdbcTemplate.update("DELETE FROM mitigation_ua_rules WHERE batch_id LIKE 'DIAG-%'");
		jdbcTemplate.update("DELETE FROM mitigation_audit_log WHERE batch_id LIKE 'DIAG-%'");
	}

	@Test
	void testInvalidInputAndNoEvidence() {
		Instant now = Instant.now();

		BlockDiagnosisReport emptyReport = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				null, "   ", "", now.minus(1, ChronoUnit.HOURS), now, null, List.of(), List.of(), false, false));
		assertEquals(VerdictLevel.INVALID_INPUT, emptyReport.verdictLevel());

		BlockDiagnosisReport badIpReport = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"not-a-valid-ip", null, null, now.minus(1, ChronoUnit.HOURS), now, null, List.of(), List.of(), false, false));
		assertEquals(VerdictLevel.INVALID_INPUT, badIpReport.verdictLevel());

		BlockDiagnosisReport noneReport = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"192.0.2.77", "DiagUnknownAgent/1.0", "/portal/unmatched",
				now.minus(1, ChronoUnit.HOURS), now, null, List.of("DIAG-NONEXISTENT"), List.of(), false, false));
		assertEquals(VerdictLevel.NO_EVIDENCE, noneReport.verdictLevel());
	}

	@Test
	void testAlwaysForbiddenOverridesPrivateAndMitigationBypass() {
		Instant now = Instant.now();
		MonitoredValve valve = buildValve(
				"DIAG-SRV-1", "EdgeValve", "BLOCKING", false, false, 100,
				"/portal/.*", null, null, true, "^10\\.20\\.30\\.40$",
				"ALL", true, true, null, now);
		monitoredValveRepository.upsert(valve);

		BlockDiagnosisReport report = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"10.20.30.40", null, "/portal/course/catalog",
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-1"), List.of(), true, true));

		assertEquals(VerdictLevel.LIKELY_BLOCKED, report.verdictLevel());
		assertNotNull(report.networkContext());
		assertTrue(report.networkContext().privateOrLocal());
		assertTrue(report.findings().stream().anyMatch(f -> f.category().contains("Static IP List")));
		assertEquals("FORBIDDEN (alwaysForbiddenIPs)", report.valveEvaluations().getFirst().staticIpVerdict());
	}

	@Test
	void testDynamicCidrRuleAndMitigationBypass() {
		Instant now = Instant.now();
		MonitoredValve enforcedValve = buildValve(
				"DIAG-SRV-ENF", "EnforcingValve", "BLOCKING", false, false, 100,
				"/portal/.*", null, null, false, null,
				"ALL", true, true, "^198\\.51\\.100\\.250$", now);
		MonitoredValve bypassedValve = buildValve(
				"DIAG-SRV-BYP", "BypassingValve", "BLOCKING", false, false, 100,
				"/portal/.*", null, null, false, null,
				"ALL", true, true, "^198\\.51\\.100\\.(42|250)$", now);
		monitoredValveRepository.upsert(enforcedValve);
		monitoredValveRepository.upsert(bypassedValve);

		mitigationRuleRepository.upsertRule(new MitigationRule(
				null, "198.51.100.0/24", 4, 24, "ALL", MitigationRule.STATUS_ACTIVE,
				MitigationRule.SOURCE_MANUAL, "DIAG-CIDR-1", "Botnet flood in test block",
				64512L, "Example Transit AS",
				now.minus(30, ChronoUnit.MINUTES), now, now.plus(30, ChronoUnit.MINUTES),
				null, null, 250L, 40, now, MitigationRule.DETERRENCE_PERSISTENT));

		// On EnforcingValve only: 198.51.100.42 is NOT in mitigationBypassIPs -> LIKELY_BLOCKED
		BlockDiagnosisReport blockedReport = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"198.51.100.42", null, null,
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-ENF"), List.of(), false, false));
		assertEquals(VerdictLevel.LIKELY_BLOCKED, blockedReport.verdictLevel());
		assertEquals(1, blockedReport.dynamicCidrMatches().size());
		assertFalse(blockedReport.dynamicCidrMatches().getFirst().enforcedOnValves().isEmpty());

		// On BypassingValve only: 198.51.100.42 matches mitigationBypassIPs -> BYPASSED_OR_ALLOWED
		BlockDiagnosisReport bypassedReport = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"198.51.100.42", null, null,
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-BYP"), List.of(), false, false));
		assertEquals(VerdictLevel.BYPASSED_OR_ALLOWED, bypassedReport.verdictLevel());
		assertEquals(1, bypassedReport.dynamicCidrMatches().size());
		assertTrue(bypassedReport.dynamicCidrMatches().getFirst().enforcedOnValves().isEmpty());
		assertFalse(bypassedReport.dynamicCidrMatches().getFirst().bypassedOnValves().isEmpty());
		assertEquals("BYPASSED (mitigationBypassIPs)", bypassedReport.valveEvaluations().getFirst().mitigationBypassVerdict());
	}

	@Test
	void testDynamicUaRuleExactSubstringAndContextBypasses() {
		Instant now = Instant.now();
		MonitoredValve valve = buildValve(
				"DIAG-SRV-UA", "UaValve", "BLOCKING", false, false, 100,
				"/portal/.*", null, null, true, null,
				"ALL", true, true, "^203\\.0\\.113\\.99$", now);
		monitoredValveRepository.upsert(valve);

		String rawUa = "DiagBadBot/4.1 (headless)";
		int uaHash32 = UserAgentMemoryRepository.computeUaHash32(rawUa);
		mitigationUaRuleRepository.upsertRule(new MitigationUaRule(
				null, "diag-sha256-hash", uaHash32, rawUa, "SCRAPER", "ALL",
				MitigationUaRule.STATUS_ACTIVE, MitigationUaRule.SOURCE_AUTO_UA,
				"DIAG-UA-1", "Distributed headless scraping",
				now.minus(20, ChronoUnit.MINUTES), now, now.plus(40, ChronoUnit.MINUTES),
				null, null, 180L, 12L, now));

		// 1. Anonymous exact UA match from public IP -> LIKELY_BLOCKED
		BlockDiagnosisReport blockedUa = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"203.0.113.55", rawUa, null,
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-UA"), List.of(), false, false));
		assertEquals(VerdictLevel.LIKELY_BLOCKED, blockedUa.verdictLevel());
		assertEquals(1, blockedUa.dynamicUaMatches().size());
		assertTrue(blockedUa.dynamicUaMatches().getFirst().exactHashMatch());
		assertFalse(blockedUa.dynamicUaMatches().getFirst().bypassedByContext());

		// 2. Authenticated user bypasses UA rule -> BYPASSED_OR_ALLOWED
		BlockDiagnosisReport authBypassUa = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"203.0.113.55", rawUa, null,
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-UA"), List.of(), true, false));
		assertEquals(VerdictLevel.BYPASSED_OR_ALLOWED, authBypassUa.verdictLevel());
		assertTrue(authBypassUa.dynamicUaMatches().getFirst().bypassedByContext());

		// 3. Returning visitor bypasses UA rule -> BYPASSED_OR_ALLOWED
		BlockDiagnosisReport rvBypassUa = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"203.0.113.55", rawUa, null,
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-UA"), List.of(), false, true));
		assertEquals(VerdictLevel.BYPASSED_OR_ALLOWED, rvBypassUa.verdictLevel());
		assertTrue(rvBypassUa.dynamicUaMatches().getFirst().bypassedByContext());

		// 4. mitigationBypassIPs regex bypasses UA rule -> BYPASSED_OR_ALLOWED
		BlockDiagnosisReport ipBypassUa = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"203.0.113.99", rawUa, null,
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-UA"), List.of(), false, false));
		assertEquals(VerdictLevel.BYPASSED_OR_ALLOWED, ipBypassUa.verdictLevel());
		assertTrue(ipBypassUa.dynamicUaMatches().getFirst().bypassedByContext());

		// 5. Partial UA substring lookup -> POSSIBLE_BLOCK (not exactHashMatch)
		BlockDiagnosisReport partialUa = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				null, "DiagBadBot", null,
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-UA"), List.of(), false, false));
		assertEquals(VerdictLevel.POSSIBLE_BLOCK, partialUa.verdictLevel());
		assertEquals(1, partialUa.dynamicUaMatches().size());
		assertFalse(partialUa.dynamicUaMatches().getFirst().exactHashMatch());
	}

	@Test
	void testObservedSubnetCollateralEventWithDifferingSampleUriAndPrefixIsolation() {
		Instant now = Instant.now();
		IpNetworkInfo subnetInfo = IpNetworkUtil.parse("198.51.100.0/24");
		IpNetworkInfo otherHostInfo = IpNetworkUtil.parse("198.51.100.42");

		clientEventRepository.batchUpsert(List.of(
				// Shared /24 subnet rate-limit event with a different sample URI
				new ClientEvent(
						null, "DIAG-SRV-EV", "SubnetValve", 3001L,
						now.minus(10, ChronoUnit.MINUTES), "198.51.100.0/24",
						subnetInfo.version(), subnetInfo.prefix(),
						subnetInfo.v4Start(), subnetInfo.v4End(), null, null, subnetInfo.subnetGroup(),
						320, 40, true, ClientEvent.STATUS_BLOCKED, true, now,
						64512L, "Example Residential ISP", "DE", ClientType.UNKNOWN,
						EnrichmentStatus.ENRICHED, null, 12, 3, 0, 0, 0,
						"GET", "/api/v1/search", "DiagBrowser/1.0", false, false
				),
				// Concrete .42 event used to verify .4 query does not false-match .42 via SQL LIKE
				new ClientEvent(
						null, "DIAG-SRV-EV-42", "HostValve", 3002L,
						now.minus(8, ChronoUnit.MINUTES), "198.51.100.42",
						otherHostInfo.version(), otherHostInfo.prefix(),
						otherHostInfo.v4Start(), otherHostInfo.v4End(), null, null, otherHostInfo.subnetGroup(),
						95, 10, true, ClientEvent.STATUS_BLOCKED, true, now,
						64512L, "Example Residential ISP", "DE", ClientType.UNKNOWN,
						EnrichmentStatus.ENRICHED, null, 1, 1, 0, 0, 0,
						"GET", "/portal/login", "OtherBot/1.0", false, false
				)
		));

		// Query .55 inside 198.51.100.0/24 with a full URL + query parameters
		BlockDiagnosisReport report = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"198.51.100.55:54321", null, "https://example.com/portal/course/catalog?term=winter",
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-EV"), List.of(), false, false));

		assertEquals(VerdictLevel.LIKELY_BLOCKED, report.verdictLevel());
		assertEquals("198.51.100.55", report.normalizedIp());
		assertEquals("/portal/course/catalog", report.normalizedUrlPath());
		assertTrue(report.subnetCollateralDetected());
		assertEquals(1, report.blockedOrMarkedEvents().size());
		assertTrue(report.blockedOrMarkedEvents().getFirst().subnetCollateralMatch());
		assertFalse(report.blockedOrMarkedEvents().getFirst().sampleUriMatches());
		assertTrue(report.transparencyNotes().stream().anyMatch(n -> n.contains("AntiDoSCounter retains only one representative sample request")));
		assertTrue(report.transparencyNotes().stream().anyMatch(n -> n.contains("Query string")));

		// Verify querying 198.51.100.4 on DIAG-SRV-EV-42 does NOT false-match 198.51.100.42!
		BlockDiagnosisReport isolationReport = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"198.51.100.4", null, null,
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-EV-42"), List.of(), false, false));
		assertEquals(VerdictLevel.NO_EVIDENCE, isolationReport.verdictLevel());
		assertTrue(isolationReport.blockedOrMarkedEvents().isEmpty());
	}

	@Test
	void testHistoricalRollupFallbackWhenDetailedEventsAbsent() {
		Instant now = Instant.now();
		subnetRollupRepository.batchUpsert(List.of(new ClientSubnetRollup(
				null,
				now.minus(5, ChronoUnit.DAYS),
				now.minus(5, ChronoUnit.DAYS).plus(1, ChronoUnit.HOURS),
				60,
				"DIAG-SRV-ROLLUP",
				"HistoryValve",
				"203.0.113.0/24",
				400L, 120L, 280L, 0L,
				8, 2, 10, 90, 4,
				64513L, "Example Cloud Hosting", "DE", ClientType.DATACENTER,
				now, 0L, 0L, 0L, 0L, 0L
		)));

		BlockDiagnosisReport report = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"203.0.113.7", null, null,
				now.minus(7, ChronoUnit.DAYS), now, null,
				List.of("DIAG-SRV-ROLLUP"), List.of(), false, false));

		assertEquals(VerdictLevel.POSSIBLE_BLOCK, report.verdictLevel());
		assertEquals(1, report.matchedRollups().size());
		assertTrue(report.transparencyNotes().stream().anyMatch(n -> n.contains("hourly subnet rollups remain available")));
	}

	@Test
	void testNonRelevantPathExclusionAndHoneypotPipelineEvaluation() {
		Instant now = Instant.now();
		MonitoredValve mainValve = buildValve(
				"DIAG-SRV-PIPE", "MainValve", "BLOCKING", false, false, 100,
				"/portal/.*", "^/assets/.*", null, false, null,
				"ALL", false, false, null, now);
		MonitoredValve honeypotValve = buildValve(
				"DIAG-SRV-HP", "HoneypotValve", "BLOCKING", false, false, 0,
				"/admin/trap\\.php", null, null, false, null,
				"ALL", false, false, null, now);
		monitoredValveRepository.upsert(mainValve);
		monitoredValveRepository.upsert(honeypotValve);

		BlockDiagnosisReport excludedReport = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"198.51.100.88", null, "/assets/logo.png",
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-PIPE"), List.of(), false, false));
		assertEquals(VerdictLevel.BYPASSED_OR_ALLOWED, excludedReport.verdictLevel());
		assertEquals("EXCLUDED (nonRelevantPaths)", excludedReport.valveEvaluations().getFirst().urlMatchVerdict());

		BlockDiagnosisReport honeypotReport = blockDiagnosisService.diagnose(new BlockDiagnosisRequest(
				"198.51.100.88", null, "/admin/trap.php",
				now.minus(1, ChronoUnit.HOURS), now, null,
				List.of("DIAG-SRV-HP"), List.of(), false, false));
		assertEquals(VerdictLevel.LIKELY_BLOCKED, honeypotReport.verdictLevel());
		assertTrue(honeypotReport.valveEvaluations().getFirst().honeypot());
		assertEquals("HONEYPOT_INSTANT_BLOCK", honeypotReport.valveEvaluations().getFirst().effectiveOutcome());
	}

	private static MonitoredValve buildValve(
			String serverId,
			String valveName,
			String monitorMode,
			boolean simulationMode,
			boolean serverWideBlocking,
			int allowedRequestsPerSlot,
			String relevantPaths,
			String nonRelevantPaths,
			String alwaysAllowedIPs,
			boolean alwaysAllowPrivateIPs,
			String alwaysForbiddenIPs,
			String relevantAuthScope,
			boolean dynamicMitigationEnabled,
			boolean mitigationBypassPrivateIPs,
			String mitigationBypassIPs,
			Instant updatedAt) {
		return new MonitoredValve(
				serverId, valveName, "Diagnosis test valve", 1,
				monitorMode, simulationMode, serverWideBlocking, 429,
				allowedRequestsPerSlot, 60, 5, 0.8f,
				32, 64, 10000, 5000,
				relevantPaths, nonRelevantPaths,
				alwaysAllowedIPs, alwaysAllowPrivateIPs, alwaysForbiddenIPs,
				"/antidos-status", "127.0.0.1", "auto",
				false, "_rv", false, "OFF", null, null, 900, 10000,
				relevantAuthScope, 0,
				dynamicMitigationEnabled, "/antidos-mitigation",
				0, 0L, 0L, 1, 24, 64, 86400, 5000,
				0, 0L, 0L, 0L,
				mitigationBypassPrivateIPs, mitigationBypassIPs,
				updatedAt, 99999, true);
	}
}
