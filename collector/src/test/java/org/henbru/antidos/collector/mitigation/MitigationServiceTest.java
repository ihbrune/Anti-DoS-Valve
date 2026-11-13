package org.henbru.antidos.collector.mitigation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.ValveOverviewDto;
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

	@Test
	void testPreflightWarnsOnTrafficFromUnauthenticatedOnlyValve() {
		Instant now = Instant.now();
		// Register a valve configured as UNAUTHENTICATED_ONLY
		org.henbru.antidos.collector.model.MonitoredValve anonValve = new org.henbru.antidos.collector.model.MonitoredValve(
				"Node-Anon", "ANON_VALVE", "Anon-only valve", 1, "BLOCKING",
				false, true, 429, 60, 60, 5, 0.8f, 24, 64,
				1000, 1000, null, null, null, null,
				"/antidos-status", null, "auto", false, "_adv",
				false, "OFF", null, null, 900, 50000,
				"UNAUTHENTICATED_ONLY", 0, false, null, 0, 0L, 0L,
				now, 12345, true
		);
		valveRepository.upsert(anonValve);
		assertTrue(anonValve.isUnauthenticatedOnly());
		assertFalse(anonValve.isAuthenticatedOnly());
		assertEquals("ANON ONLY", anonValve.relevantAuthScopeLabel());

		// Insert rollup telemetry from ANON_VALVE with 0 authenticated requests
		jdbcTemplate.update("""
				INSERT INTO client_subnet_rollups (
				    bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
				    asn, as_org, country_code, client_type, total_requests, active_requests,
				    blocked_requests, marked_requests, distinct_clients, min_requests_per_client,
				    max_requests_per_client, returning_requests,
				    returning_tracked_requests, authenticated_requests
				) VALUES (?, ?, 60, 'Node-Anon', 'ANON_VALVE', '198.51.200.0/24', 64512, 'Anon Target Corp.', 'DE',
				          'DATACENTER', 1500, 1500, 0, 0, 25, 10, 80, 0, 1500, 0)
				""", Timestamp.from(now.minus(Duration.ofMinutes(30))), Timestamp.from(now));

		// Evaluate preflight: 0 authenticated requests, but valve is UNAUTHENTICATED_ONLY
		MitigationService.PreflightCheckResult res = mitigationService.evaluatePreflight(List.of("198.51.200.0/24"));
		// Must remain safe to proceed without override (WARNING, not CRITICAL)
		assertTrue(res.safeToProceedWithoutOverride());
		assertFalse(res.hasCriticalWarnings());
		assertEquals(0L, res.totalAuthenticatedRequests24h());
		assertEquals(1500L, res.totalObservedRequests24h());

		// Must contain the explanatory Auth Scope Notice warning
		boolean foundAuthScopeNotice = res.warnings().stream()
				.anyMatch(w -> "WARNING".equalsIgnoreCase(w.severity())
						&& w.message().contains("Auth Scope Notice")
						&& w.message().contains("UNAUTHENTICATED_ONLY"));
		assertTrue(foundAuthScopeNotice, "Expected Auth Scope Notice warning in preflight result: " + res.warnings());

		// ASN preview must flag the candidate subnet as anonOnlyScope = true
		MitigationService.AsnBatchPreview preview = mitigationService.previewAsnBatch(64512, 24);
		assertEquals(1, preview.candidates().size());
		assertTrue(preview.candidates().getFirst().isAnonOnlyScope(), "Candidate must be flagged as anonOnlyScope = true");
	}

	@Test
	void testMitigationAuditEntryExtractsAsn() {
		// 1. From cidr ASN-17621
		MitigationAuditEntry entry1 = new MitigationAuditEntry(
				1L, null, "ASN-17621", null, "AUTO_BLOCK", "AUTO_ENGINE", 3600, "Blocked ASN", Instant.now());
		assertEquals(17621L, entry1.getAsn());

		// 2. From batchId AUTO-ASN-7922-123456
		MitigationAuditEntry entry2 = new MitigationAuditEntry(
				2L, 10L, "198.51.100.0/24", "AUTO-ASN-7922-123456", "CREATE", "admin", 3600, "Manual Block", Instant.now());
		assertEquals(7922L, entry2.getAsn());

		// 3. From details "Carpet attack from ASN 64496 (Hosting Corp)"
		MitigationAuditEntry entry3 = new MitigationAuditEntry(
				3L, null, "ALL", null, "AUTO_WOULD_BLOCK", "AUTO_ENGINE", 3600, "Carpet attack from ASN 64496 (Hosting Corp)", Instant.now());
		assertEquals(64496L, entry3.getAsn());

		// 4. No ASN present
		MitigationAuditEntry entry4 = new MitigationAuditEntry(
				4L, 11L, "203.0.113.0/24", null, "CREATE", "admin", 1800, "Single subnet block", Instant.now());
		org.junit.jupiter.api.Assertions.assertNull(entry4.getAsn());
	}

	@Test
	void testCircuitBreakerPreventsInfiniteSyncLoopOnRevisionMismatch() throws Exception {
		Instant now = Instant.now();
		ValveStatusClient mockClient = mock(ValveStatusClient.class);
		CollectorProperties props = new CollectorProperties();
		MitigationService testService = new MitigationService(
				props, ruleRepository, valveRepository, mockClient, null, jdbcTemplate);

		// 1. Add active rule
		ruleRepository.upsertRule(new MitigationRule(
				null, "198.51.100.0/24", 4, 24, "ALL", "ACTIVE", "MANUAL", null,
				"Test Block", null, null, now, now, now.plusSeconds(3600), null, null,
				0L, 0, null, "OBSERVING"
		));
		long expectedRevision = testService.getExpectedRevision(now);
		assertTrue(expectedRevision > 0L);

		EndpointConfig ep = new EndpointConfig();
		ep.setName("test-node");
		ep.setUrl("http://localhost:8080/antidos-status");

		ValveOverviewDto.ValveSummaryDto valveSummary = new ValveOverviewDto.ValveSummaryDto(
				"ROOT", "Root Valve", 1, "BLOCKING", false, true,
				429, 60, 60, 5, 0.8f, 24, 64, 1000, 1000,
				null, null, null, null, "/antidos-status", null, "auto",
				false, "_adv", false, "OFF", null, null, 900, 50000,
				0, "ALL", null, true, "/antidos-mitigate", null,
				0, 0L, 99999L, 16, 32, 86400, 5000,
				0L, 0, 0, 0L, 0L, 0L, 0L, 0L, 0L, 0, 0, 0, true, true
		);
		assertEquals(1, valveSummary.dynamicRulesHashVersionOrDefault());

		// Mock valve returning divergent revision 99999L (does not match expectedRevision)
		when(mockClient.sendMitigationCommand(any(), any(), eq("ROOT"), eq("replace"), any(), any(), any(), any()))
				.thenReturn(new ValveStatusClient.MitigationCommandResponse(
						"OK", "ROOT", "replace", 1, 99999L, 1, 0L, 0, 86400, 5000));

		// Call 1: Must trigger sync, detect mismatch, and trip circuit breaker
		testService.syncValveIfNeeded(ep, valveSummary, now);
		verify(mockClient, times(1)).sendMitigationCommand(any(), any(), eq("ROOT"), eq("replace"), any(), any(), any(), any());
		assertTrue(testService.isValveSyncSuppressed("test-node", "ROOT", expectedRevision, now),
				"Circuit breaker must suppress future syncs for this unchanged expectedRevision");

		// Check audit log for SYNC_CIRCUIT_BREAKER
		List<MitigationAuditEntry> audits = ruleRepository.findRecentAuditEntries(5);
		assertTrue(audits.stream().anyMatch(a -> "SYNC_CIRCUIT_BREAKER".equals(a.getAction())),
				"Must record SYNC_CIRCUIT_BREAKER audit event");

		// Call 2 (simulating next 15s poll cycle): Rule set is unchanged -> MUST BE SUPPRESSED!
		testService.syncValveIfNeeded(ep, valveSummary, now.plusSeconds(15));
		verify(mockClient, times(1)).sendMitigationCommand(any(), any(), eq("ROOT"), eq("replace"), any(), any(), any(), any());

		// 2. Add second rule -> expectedRevision changes -> Circuit breaker must IMMEDIATELY RESET!
		ruleRepository.upsertRule(new MitigationRule(
				null, "203.0.113.0/24", 4, 24, "ALL", "ACTIVE", "MANUAL", null,
				"Second Block", null, null, now, now, now.plusSeconds(3600), null, null,
				0L, 0, null, "OBSERVING"
		));
		long newExpectedRevision = testService.getExpectedRevision(now);
		assertFalse(expectedRevision == newExpectedRevision);
		assertFalse(testService.isValveSyncSuppressed("test-node", "ROOT", newExpectedRevision, now),
				"Circuit breaker must immediately clear when expectedRevision changes");

		// Mock valve now converging to newExpectedRevision
		when(mockClient.sendMitigationCommand(any(), any(), eq("ROOT"), eq("replace"), any(), any(), any(), any()))
				.thenReturn(new ValveStatusClient.MitigationCommandResponse(
						"OK", "ROOT", "replace", 2, newExpectedRevision, 1, 0L, 0, 86400, 5000));

		// Call 3: Sync is allowed and converges
		testService.syncValveIfNeeded(ep, valveSummary, now.plusSeconds(30));
		verify(mockClient, times(2)).sendMitigationCommand(any(), any(), eq("ROOT"), eq("replace"), any(), any(), any(), any());
		assertFalse(testService.isValveSyncSuppressed("test-node", "ROOT", newExpectedRevision, now.plusSeconds(30)));
	}

	@Test
	void testHashVersionFallbackAndIncompatibility() throws Exception {
		Instant now = Instant.now();
		ValveStatusClient mockClient = mock(ValveStatusClient.class);
		CollectorProperties props = new CollectorProperties();
		MitigationService testService = new MitigationService(
				props, ruleRepository, valveRepository, mockClient, null, jdbcTemplate);

		// Add rule
		ruleRepository.upsertRule(new MitigationRule(
				null, "198.51.100.0/24", 4, 24, "ALL", "ACTIVE", "MANUAL", null,
				"Test Block", null, null, now, now, now.plusSeconds(3600), null, null,
				0L, 0, null, "OBSERVING"
		));

		EndpointConfig ep = new EndpointConfig();
		ep.setName("test-node-incompatible");
		ep.setUrl("http://localhost:8080/antidos-status");

		// Valve reporting incompatible future hash version 2
		ValveOverviewDto.ValveSummaryDto v2Summary = new ValveOverviewDto.ValveSummaryDto(
				"V2_MONITOR", "Future Valve", 1, "BLOCKING", false, true,
				429, 60, 60, 5, 0.8f, 24, 64, 1000, 1000,
				null, null, null, null, "/antidos-status", null, "auto",
				false, "_adv", false, "OFF", null, null, 900, 50000,
				0, "ALL", null, true, "/antidos-mitigate", null,
				0, 0L, 77777L,
				2, // dynamicRulesHashVersion = 2 (incompatible with Collector's v1)
				16, 32, 86400, 5000,
				0L, 0, 0, 0L, 0L, 0L, 0L, 0L, 0L, 0, 0, 0, true, true
		);
		assertEquals(2, v2Summary.dynamicRulesHashVersionOrDefault());

		testService.syncValveIfNeeded(ep, v2Summary, now);
		// Incompatible version must NOT send mitigation command
		verify(mockClient, times(0)).sendMitigationCommand(any(), any(), any(), any(), any(), any(), any(), any());

		// Verify audit entry for SYNC_VERSION_MISMATCH
		List<MitigationAuditEntry> audits = ruleRepository.findRecentAuditEntries(5);
		assertTrue(audits.stream().anyMatch(a -> "SYNC_VERSION_MISMATCH".equals(a.getAction())),
				"Must record SYNC_VERSION_MISMATCH audit event when hash version is incompatible");
	}

	@Test
	void testFilterAuditEntriesByAutoEngine() {
		mitigationService.recordAudit(null, "198.51.210.0/24", "AUTO_BLOCK", "Test auto block", 3600, "AUTO_ENGINE");
		mitigationService.recordAudit(null, "198.51.211.0/24", "CREATE", "Test manual block", 3600, "ADMIN");

		List<MitigationAuditEntry> autoEntries = mitigationService.getAuditEntriesFiltered(null, "ALL", "AUTO_ENGINE", 0, 10);
		assertTrue(autoEntries.stream().anyMatch(e -> "AUTO_ENGINE".equals(e.actor())));
		assertFalse(autoEntries.stream().anyMatch(e -> "ADMIN".equals(e.actor())));

		long count = mitigationService.countAuditEntriesFiltered(null, "ALL", "AUTO_ENGINE");
		assertTrue(count >= 1);
	}
}
