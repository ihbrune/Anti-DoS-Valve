package org.henbru.antidos.collector.mitigation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.poller.ValveStatusClient;
import org.henbru.antidos.collector.storage.MitigationRuleRepository;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

class MitigationServiceTest {

	@TempDir
	Path tempDir;

	private JdbcTemplate jdbcTemplate;
	private MitigationRuleRepository ruleRepository;
	private MonitoredValveRepository valveRepository;
	private MitigationService mitigationService;

	@BeforeEach
	void setUp() {
		String dbUrl = "jdbc:sqlite:" + tempDir.resolve("mitigation-test.db").toAbsolutePath();
		SingleConnectionDataSource ds = new SingleConnectionDataSource(dbUrl, true);
		Flyway.configure()
				.dataSource(ds)
				.locations("classpath:db/migration/sqlite")
				.load()
				.migrate();

		this.jdbcTemplate = new JdbcTemplate(ds);
		this.ruleRepository = new MitigationRuleRepository(jdbcTemplate);
		this.valveRepository = new MonitoredValveRepository(jdbcTemplate);
		CollectorProperties props = new CollectorProperties();
		props.setDefaultMitigationTtlMinutes(60);
		props.setMitigationToken("secret-mitigation-token");
		this.mitigationService = new MitigationService(
				props,
				ruleRepository,
				valveRepository,
				new ValveStatusClient(new com.fasterxml.jackson.databind.ObjectMapper()),
				null,
				jdbcTemplate
		);
	}

	@Test
	void testNormalizeCidrAndPrefixGuardrails() {
		MitigationService.NormalizedCidr v4 = MitigationService.normalizeAndValidateCidr("198.51.100.77/24");
		assertEquals("198.51.100.0/24", v4.canonicalCidr());
		assertEquals(4, v4.ipVersion());
		assertEquals(24, v4.prefixLength());

		MitigationService.NormalizedCidr hostV4 = MitigationService.normalizeAndValidateCidr("203.0.113.14");
		assertEquals("203.0.113.14/32", hostV4.canonicalCidr());

		MitigationService.NormalizedCidr v6 = MitigationService.normalizeAndValidateCidr("2001:db8:abcd:1234::99/48");
		assertEquals("2001:db8:abcd:0:0:0:0:0/48", v6.canonicalCidr());
		assertEquals(6, v6.ipVersion());
		assertEquals(48, v6.prefixLength());

		// Overly broad prefixes (< /16 for IPv4, < /32 for IPv6) must be rejected
		assertThrows(IllegalArgumentException.class, () -> MitigationService.normalizeAndValidateCidr("198.0.0.0/8"));
		assertThrows(IllegalArgumentException.class, () -> MitigationService.normalizeAndValidateCidr("0.0.0.0/0"));
		assertThrows(IllegalArgumentException.class, () -> MitigationService.normalizeAndValidateCidr("2001:db8::/16"));
	}

	@Test
	void testPreflightCheckDetectsAuthenticatedAndPrivateSubnets() {
		Instant now = Instant.now();
		// Insert rollup with authenticated traffic for 198.51.100.0/24
		jdbcTemplate.update("""
				INSERT INTO client_subnet_rollups (
				    bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
				    asn, as_org, country_code, client_type, total_requests, active_requests,
				    blocked_requests, marked_requests, distinct_clients, min_requests_per_client,
				    max_requests_per_client, returning_requests,
				    returning_tracked_requests, authenticated_requests
				) VALUES (?, ?, 60, 'Pub01', 'FUER ALLE', '198.51.100.0/24', 64500, 'Customer ISP', 'DE',
				          'RESIDENTIAL_ISP', 500, 500, 0, 0, 12, 10, 80, 400, 500, 45)
				""", Timestamp.from(now.minus(Duration.ofMinutes(30))), Timestamp.from(now));

		// 1. Subnet with authenticated users -> CRITICAL warning
		MitigationService.PreflightCheckResult resAuth = mitigationService.evaluatePreflight(List.of("198.51.100.99/24"));
		assertFalse(resAuth.safeToProceedWithoutOverride());
		assertTrue(resAuth.hasCriticalWarnings());
		assertEquals(45L, resAuth.totalAuthenticatedRequests24h());

		// 2. Private network -> CRITICAL warning
		MitigationService.PreflightCheckResult resPriv = mitigationService.evaluatePreflight(List.of("10.77.25.0/24"));
		assertFalse(resPriv.safeToProceedWithoutOverride());
		assertTrue(resPriv.hasCriticalWarnings());

		// 3. Clean attacking subnet -> Safe
		MitigationService.PreflightCheckResult resClean = mitigationService.evaluatePreflight(List.of("203.0.113.0/24"));
		assertTrue(resClean.safeToProceedWithoutOverride());
		assertFalse(resClean.hasCriticalWarnings());
	}

	@Test
	void testAsnBatchExpansionExcludesAuthenticatedSubnetsAndSupportsBatchRevoke() {
		Instant now = Instant.now().minus(Duration.ofMinutes(20));
		// Insert 3 unauthenticated attacking subnets and 1 authenticated subnet for ASN 64496
		String[] attackSubnets = {"198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24"};
		for (String sub : attackSubnets) {
			jdbcTemplate.update("""
					INSERT INTO client_subnet_rollups (
					    bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
					    asn, as_org, country_code, client_type, total_requests, active_requests,
					    blocked_requests, marked_requests, distinct_clients, min_requests_per_client,
					    max_requests_per_client, returning_requests,
					    returning_tracked_requests, authenticated_requests
					) VALUES (?, ?, 60, 'Pub01', 'FUER ALLE', ?, 64496, 'Example Hosting Corp.', 'US',
					          'DATACENTER', 2000, 2000, 0, 0, 40, 20, 80, 0, 2000, 0)
					""", Timestamp.from(now), Timestamp.from(now.plus(Duration.ofMinutes(60))), sub);
		}
		// Subnet with 5 authenticated requests (must be excluded automatically!)
		jdbcTemplate.update("""
				INSERT INTO client_subnet_rollups (
				    bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
				    asn, as_org, country_code, client_type, total_requests, active_requests,
				    blocked_requests, marked_requests, distinct_clients, min_requests_per_client,
				    max_requests_per_client, returning_requests,
				    returning_tracked_requests, authenticated_requests
				) VALUES (?, ?, 60, 'Pub01', 'FUER ALLE', '198.51.101.0/24', 64496, 'Example Hosting Corp.', 'US',
				          'DATACENTER', 300, 300, 0, 0, 4, 20, 80, 200, 300, 5)
				""", Timestamp.from(now), Timestamp.from(now.plus(Duration.ofMinutes(60))));

		MitigationService.AsnBatchPreview preview = mitigationService.previewAsnBatch(64496L, 24);
		assertEquals(3, preview.candidates().size());
		assertEquals(1, preview.skippedAuthenticatedSubnets());
		assertEquals(6000L, preview.totalCandidateRequests());

		List<MitigationRule> created = mitigationService.blockAsnSubnets(64496L, 24, 60, "ASN 64496 Carpet Attack", "ADMIN");
		assertEquals(3, created.size());
		String batchId = created.getFirst().batchId();
		assertNotNull(batchId);
		assertTrue(batchId.startsWith("ASN-64496-"));

		List<MitigationRule> active = mitigationService.getActiveRules();
		assertEquals(3, active.size());

		// Revoke the entire batch in one operation
		int revokedCount = mitigationService.revokeBatch(batchId, "Incident resolved", "ADMIN");
		assertEquals(3, revokedCount);
		assertEquals(0, mitigationService.getActiveRules().size());

		List<MitigationAuditEntry> audits = mitigationService.getRecentAuditEntries(10);
		assertFalse(audits.isEmpty());
	}

	@Test
	void testEmergencyFlushRevokesAllActiveRules() {
		mitigationService.createOrUpdateBlock("198.51.100.0/24", 60, "Attack 1", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
		mitigationService.createOrUpdateBlock("203.0.113.0/24", 60, "Attack 2", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
		mitigationService.createOrUpdateBlock("2001:db8:1234::/48", 60, "Attack 3", MitigationRule.SOURCE_MANUAL, null, "ADMIN");

		assertEquals(3, mitigationService.getActiveRules().size());

		int flushedCount = mitigationService.revokeAll("Emergency operator override", "ADMIN");
		assertEquals(3, flushedCount);
		assertEquals(0, mitigationService.getActiveRules().size());

		List<MitigationAuditEntry> audits = mitigationService.getRecentAuditEntries(10);
		MitigationAuditEntry latest = audits.getFirst();
		assertEquals("EMERGENCY_FLUSH", latest.action());
		assertTrue(latest.details().contains("3 active rule(s) revoked"));
	}

	@Test
	void testDeterrenceTrackingTransitionsFromObservingToPersistent() {
		MitigationRule rule = mitigationService.createOrUpdateBlock(
				"198.51.100.0/24", 60, "Carpet attack", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
		assertEquals(MitigationRule.DETERRENCE_OBSERVING, rule.deterrenceState());

		// Simulate Valve reporting a blocked counter keyed by the matched CIDR ("198.51.100.0/24")
		Instant hitTime = Instant.now();
		jdbcTemplate.update("""
				INSERT INTO client_events (
				    server_id, valve_name, slot_key, slot_time, client_key, request_count,
				    retained_count, is_locked, status, is_completed, last_updated_at,
				    distinct_clients, distinct_user_agents, sample_method, sample_uri, sample_user_agent
				) VALUES ('Pub01', 'MITIGATION-VALVE', 1001, ?, '198.51.100.0/24', 185,
				          0, 1, 'BLOCKED', 1, ?, 14, 6, 'GET', '/search?q=1', 'Mozilla/5.0')
				""", Timestamp.from(hitTime), Timestamp.from(hitTime));

		mitigationService.refreshDeterrenceMetrics();

		MitigationRule updated = mitigationService.getActiveRules().getFirst();
		assertEquals(185L, updated.totalBlockedHits());
		assertEquals(14, updated.peakDistinctIps());
		assertEquals(MitigationRule.DETERRENCE_PERSISTENT, updated.deterrenceState());
	}

	@Test
	void testMitigationControllerEndpointsAndSpringElGetters() {
		CollectorProperties props = new CollectorProperties();
		props.setDefaultMitigationTtlMinutes(60);
		org.henbru.antidos.collector.storage.SystemSettingsRepository settingsRepo =
				new org.henbru.antidos.collector.storage.SystemSettingsRepository(jdbcTemplate);
		AutoMitigationService autoMitigationService =
				new AutoMitigationService(props, settingsRepo, mitigationService, jdbcTemplate);
		org.henbru.antidos.collector.web.MitigationController controller =
				new org.henbru.antidos.collector.web.MitigationController(mitigationService, autoMitigationService, props);

		org.springframework.ui.ExtendedModelMap model = new org.springframework.ui.ExtendedModelMap();
		String preflightView = controller.evaluatePreflight("198.51.100.42/24", model);
		assertEquals("fragments/mitigation-content :: preflightBox", preflightView);
		MitigationService.PreflightCheckResult preflight =
				(MitigationService.PreflightCheckResult) model.getAttribute("preflightResult");
		assertNotNull(preflight);
		assertEquals(List.of("198.51.100.0/24"), preflight.getValidCidrs());
		assertTrue(preflight.getInvalidInputs().isEmpty());
		assertNotNull(model.getAttribute("preflightCheckedAt"));

		// Test empty ASN preview returns error message
		org.springframework.ui.ExtendedModelMap asnEmptyModel = new org.springframework.ui.ExtendedModelMap();
		String asnEmptyView = controller.previewAsn(null, 24, asnEmptyModel);
		assertEquals("fragments/mitigation-content :: asnPreviewBox", asnEmptyView);
		assertNotNull(asnEmptyModel.getAttribute("asnPreviewError"));

		// Test valid ASN preview returns AsnBatchPreview with JavaBean getters
		org.springframework.ui.ExtendedModelMap asnValidModel = new org.springframework.ui.ExtendedModelMap();
		String asnValidView = controller.previewAsn(64496L, 24, asnValidModel);
		assertEquals("fragments/mitigation-content :: asnPreviewBox", asnValidView);
		MitigationService.AsnBatchPreview preview =
				(MitigationService.AsnBatchPreview) asnValidModel.getAttribute("asnPreview");
		assertNotNull(preview);
		assertEquals(64496L, preview.getAsn());
		assertEquals(24, preview.getHours());
	}

	@Test
	void testFleetGuardrailsDynamicPrefixEnforcement() {
		// Insert an active valve requiring minimum /24 for IPv4 and /48 for IPv6
		org.henbru.antidos.collector.model.MonitoredValve valve = new org.henbru.antidos.collector.model.MonitoredValve(
				"Srv1", "VALVE1", "Description", 1, "BLOCKING", false, false, 429,
				50, 30, 10, 0.0f, 32, 64, 1000, 1000,
				"/api/.*", null, null, null, "/antidos-status", null, "auto",
				false, "_adv", false, "OFF", null, null, 900, 50000, "ALL", 0,
				true, "/antidos-mitigate", 0, 0L, 0L,
				24, 48, 86400, 5000,
				Instant.now(), 12345, true
		);
		valveRepository.upsert(valve);

		assertEquals(24, mitigationService.getEffectiveMinIpv4Prefix());
		assertEquals(48, mitigationService.getEffectiveMinIpv6Prefix());

		// /20 is broader than /24 -> evaluatePreflight must reject it
		MitigationService.PreflightCheckResult preflightBroad =
				mitigationService.evaluatePreflight(List.of("198.51.96.0/20"));
		assertFalse(preflightBroad.isSafeToProceedWithoutOverride());
		assertEquals(1, preflightBroad.getInvalidInputs().size());
		assertTrue(preflightBroad.getInvalidInputs().getFirst().contains("between /24 and /32"));

		// /24 is valid
		MitigationService.PreflightCheckResult preflightOk =
				mitigationService.evaluatePreflight(List.of("198.51.100.0/24"));
		assertTrue(preflightOk.getInvalidInputs().isEmpty());
		assertEquals(List.of("198.51.100.0/24"), preflightOk.getValidCidrs());
	}

	@Test
	void testFleetGuardrailsMaxTtlCapping() {
		// Insert an active valve with max TTL of 1 hour (3600 seconds)
		org.henbru.antidos.collector.model.MonitoredValve valve = new org.henbru.antidos.collector.model.MonitoredValve(
				"Srv1", "VALVE1", "Description", 1, "BLOCKING", false, false, 429,
				50, 30, 10, 0.0f, 32, 64, 1000, 1000,
				"/api/.*", null, null, null, "/antidos-status", null, "auto",
				false, "_adv", false, "OFF", null, null, 900, 50000, "ALL", 0,
				true, "/antidos-mitigate", 0, 0L, 0L,
				16, 32, 3600, 5000,
				Instant.now(), 12345, true
		);
		valveRepository.upsert(valve);

		assertEquals(3600, mitigationService.getEffectiveMaxTtlSeconds());

		// Request a block for 180 minutes (3 hours)
		Instant before = Instant.now();
		MitigationRule rule = mitigationService.createOrUpdateBlock(
				"198.51.100.0/24", 180, "TTL test", MitigationRule.SOURCE_MANUAL, null, "ADMIN");

		// Stored rule expiresAt must be capped to at most 60 minutes
		long remainingSec = Duration.between(before, rule.expiresAt()).toSeconds();
		assertTrue(remainingSec <= 3605 && remainingSec >= 3590,
				"Requested 180m must be capped to fleet max of 60m (3600s), got " + remainingSec + "s");
	}

	@Test
	void testFleetGuardrailsCapacityLimitPreflightWarning() {
		// Insert an active valve with capacity of 2 active blocks
		org.henbru.antidos.collector.model.MonitoredValve valve = new org.henbru.antidos.collector.model.MonitoredValve(
				"Srv1", "VALVE1", "Description", 1, "BLOCKING", false, false, 429,
				50, 30, 10, 0.0f, 32, 64, 1000, 1000,
				"/api/.*", null, null, null, "/antidos-status", null, "auto",
				false, "_adv", false, "OFF", null, null, 900, 50000, "ALL", 0,
				true, "/antidos-mitigate", 0, 0L, 0L,
				16, 32, 86400, 2,
				Instant.now(), 12345, true
		);
		valveRepository.upsert(valve);

		assertEquals(2, mitigationService.getEffectiveMaxActiveBlocks());

		// Fill capacity with 2 blocks
		mitigationService.createOrUpdateBlock("198.51.100.0/24", 60, "R1", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
		mitigationService.createOrUpdateBlock("198.51.101.0/24", 60, "R2", MitigationRule.SOURCE_MANUAL, null, "ADMIN");

		// Evaluate preflight for a 3rd new block
		MitigationService.PreflightCheckResult preflight =
				mitigationService.evaluatePreflight(List.of("198.51.102.0/24"));

		assertTrue(preflight.hasCriticalWarnings());
		boolean hasCapacityWarning = preflight.getWarnings().stream()
				.anyMatch(w -> "FLEET_CAPACITY".equalsIgnoreCase(w.getCidr()) && w.getMessage().contains("Fleet capacity limit exceeded"));
		assertTrue(hasCapacityWarning, "Must raise FLEET_CAPACITY critical preflight warning");
	}

	@Test
	void testAlertNotificationEndpointAndRepository() {
		CollectorProperties props = new CollectorProperties();
		org.henbru.antidos.collector.storage.SystemSettingsRepository settingsRepo =
				new org.henbru.antidos.collector.storage.SystemSettingsRepository(jdbcTemplate);
		AutoMitigationService autoMitigationService =
				new AutoMitigationService(props, settingsRepo, mitigationService, jdbcTemplate);
		org.henbru.antidos.collector.web.MitigationController controller =
				new org.henbru.antidos.collector.web.MitigationController(mitigationService, autoMitigationService, props);

		long idBefore = mitigationService.getLatestAlertAuditId();

		// Record an autonomous alert
		mitigationService.recordAudit(null, "198.51.100.0/24", "AUTO_BLOCK", "Carpet attack", 3600, "AUTO_ENGINE");

		long idAfter = mitigationService.getLatestAlertAuditId();
		assertTrue(idAfter > idBefore);

		List<MitigationAuditEntry> alerts = mitigationService.getAlertEntriesSince(idBefore, 10);
		assertEquals(1, alerts.size());
		assertEquals("AUTO_BLOCK", alerts.getFirst().getAction());
		assertEquals("198.51.100.0/24", alerts.getFirst().getCidr());

		// Initial poll with sinceId < 0 must return 0 alerts to avoid historical flood
		var initResp = controller.apiGetAlerts(-1L);
		assertEquals(200, initResp.getStatusCode().value());
		assertEquals(false, initResp.getBody().get("hasNewAlerts"));
		assertEquals(List.of(), initResp.getBody().get("alerts"));
		assertEquals(idAfter, initResp.getBody().get("latestId"));

		// Subsequent poll with sinceId = idBefore must return the new alert
		var pollResp = controller.apiGetAlerts(idBefore);
		assertEquals(200, pollResp.getStatusCode().value());
		assertEquals(true, pollResp.getBody().get("hasNewAlerts"));
		List<?> polled = (List<?>) pollResp.getBody().get("alerts");
		assertEquals(1, polled.size());
	}
}
