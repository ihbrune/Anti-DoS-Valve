package org.henbru.antidos.collector.mitigation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.poller.ValveStatusClient;
import org.henbru.antidos.collector.storage.MitigationRuleRepository;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.henbru.antidos.collector.storage.SystemSettingsRepository;
import org.henbru.antidos.collector.web.MitigationController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.ui.ExtendedModelMap;

class AutoMitigationServiceTest {

	@TempDir
	Path tempDir;

	private JdbcTemplate jdbcTemplate;
	private SystemSettingsRepository settingsRepo;
	private MitigationRuleRepository ruleRepository;
	private MonitoredValveRepository valveRepository;
	private MitigationService mitigationService;
	private AutoMitigationService autoMitigationService;
	private CollectorProperties properties;

	@BeforeEach
	void setUp() {
		String dbUrl = "jdbc:sqlite:" + tempDir.resolve("auto-mitigation-test.db").toAbsolutePath();
		SingleConnectionDataSource ds = new SingleConnectionDataSource(dbUrl, true);
		Flyway.configure()
				.dataSource(ds)
				.locations("classpath:db/migration/sqlite")
				.load()
				.migrate();

		this.jdbcTemplate = new JdbcTemplate(ds);
		this.settingsRepo = new SystemSettingsRepository(jdbcTemplate);
		this.ruleRepository = new MitigationRuleRepository(jdbcTemplate);
		this.valveRepository = new MonitoredValveRepository(jdbcTemplate);

		this.properties = new CollectorProperties();
		this.properties.setDefaultMitigationTtlMinutes(60);
		this.properties.setMitigationToken("secret-test-token");
		this.properties.getAutoMitigation().setEnabled(false);
		this.properties.getAutoMitigation().setDryRun(true);
		this.properties.getAutoMitigation().setCarpetMinSubnets(3);
		this.properties.getAutoMitigation().setCarpetMinRequests(5000);
		this.properties.getAutoMitigation().setMaxReturningRatioPct(5.0);
		this.properties.getAutoMitigation().setMaxActiveRules(50);
		this.properties.getAutoMitigation().setDefaultTtlMinutes(60);
		this.properties.getAutoMitigation().setAutoExtendPersistent(false);
		this.properties.getAutoMitigation().setMaxExtensionHours(24);

		this.mitigationService = new MitigationService(
				properties,
				ruleRepository,
				valveRepository,
				new ValveStatusClient(new com.fasterxml.jackson.databind.ObjectMapper()),
				null,
				jdbcTemplate
		);

		this.autoMitigationService = new AutoMitigationService(
				properties,
				settingsRepo,
				mitigationService,
				jdbcTemplate
		);
	}

	@Test
	void testEffectiveSettingsAndDatabasePrecedence() {
		// 1. Initial defaults match YAML
		AutoMitigationService.EffectiveAutoSettings s1 = autoMitigationService.getEffectiveSettings();
		assertFalse(s1.isEnabled());
		assertTrue(s1.isDryRun());
		assertEquals(3, s1.getCarpetMinSubnets());
		assertEquals(5000L, s1.getCarpetMinRequests());
		assertEquals(1, s1.getCarpetWindowHours());
		assertTrue(s1.getProtectedAsnSet().contains(8075L));
		assertEquals(5.0, s1.getMaxReturningRatioPct(), 0.001);
		assertEquals(50, s1.getMaxActiveRules());
		assertFalse(s1.isHasDatabaseOverrides());

		// 2. Update settings via database overrides
		autoMitigationService.updateSettings(true, false, 5, 10000L, 3, "8075,16509", 2.5, 30, 90, true, 48, "OPERATOR-ALICE");
		AutoMitigationService.EffectiveAutoSettings s2 = autoMitigationService.getEffectiveSettings();
		assertTrue(s2.isEnabled());
		assertFalse(s2.isDryRun());
		assertEquals(5, s2.getCarpetMinSubnets());
		assertEquals(10000L, s2.getCarpetMinRequests());
		assertEquals(3, s2.getCarpetWindowHours());
		assertEquals("8075,16509", s2.getProtectedAsns());
		assertTrue(s2.getProtectedAsnSet().contains(8075L));
		assertTrue(s2.getProtectedAsnSet().contains(16509L));
		assertEquals(2.5, s2.getMaxReturningRatioPct(), 0.001);
		assertEquals(30, s2.getMaxActiveRules());
		assertEquals(90, s2.getDefaultTtlMinutes());
		assertTrue(s2.isAutoExtendPersistent());
		assertEquals(48, s2.getMaxExtensionHours());
		assertTrue(s2.isHasDatabaseOverrides());

		// 2b. Verify arbitrary / low values are supported without artificial step/min clamping
		autoMitigationService.updateSettings(false, true, 1, 50L, 1, "AS8075", 0.25, 1, 60, false, 2, "OPERATOR-BOB");
		AutoMitigationService.EffectiveAutoSettings s2b = autoMitigationService.getEffectiveSettings();
		assertEquals(1, s2b.getCarpetMinSubnets());
		assertEquals(50L, s2b.getCarpetMinRequests());
		assertEquals(1, s2b.getCarpetWindowHours());
		assertTrue(s2b.getProtectedAsnSet().contains(8075L));
		assertEquals(0.25, s2b.getMaxReturningRatioPct(), 0.001);
		assertEquals(1, s2b.getMaxActiveRules());
		assertEquals(60, s2b.getDefaultTtlMinutes());
		assertEquals(2, s2b.getMaxExtensionHours());

		// 3. Reset settings deletes overrides and falls back to YAML
		autoMitigationService.resetToDefaults("OPERATOR-ALICE");
		AutoMitigationService.EffectiveAutoSettings s3 = autoMitigationService.getEffectiveSettings();
		assertFalse(s3.isEnabled());
		assertTrue(s3.isDryRun());
		assertEquals(3, s3.getCarpetMinSubnets());
		assertEquals(5000L, s3.getCarpetMinRequests());
		assertEquals(1, s3.getCarpetWindowHours());
		assertEquals(5.0, s3.getMaxReturningRatioPct(), 0.001);
		assertFalse(s3.isHasDatabaseOverrides());
	}

	@Test
	void testCarpetAttackCandidateDetectionAndSafetyGuardrails() {
		Instant now = Instant.now();

		// ASN 64496: Carpet attack across 4 subnets, 8,000 reqs, 100 returning (1.25% <= 5%), 0 auth -> ELIGIBLE
		for (int i = 1; i <= 4; i++) {
			insertSubnetRollup("198.51.10" + i + ".0/24", 64496L, "Attacking Hosting AS",
					2000, 25, 0, now.minus(Duration.ofMinutes(15)));
		}

		// ASN 64497: Carpet attack across 3 subnets, 6,000 reqs, BUT 2,400 returning (40% > 5%) -> REJECTED (Collateral risk)
		for (int i = 1; i <= 3; i++) {
			insertSubnetRollup("203.0.11" + i + ".0/24", 64497L, "Residential ISP Corp",
					2000, 800, 0, now.minus(Duration.ofMinutes(15)));
		}

		// ASN 64498: 3 subnets, but 1 subnet has authenticated requests -> Only 2 eligible subnets left (< min 3) -> REJECTED
		insertSubnetRollup("192.0.2.0/24", 64498L, "Mixed Transit", 2000, 10, 0, now.minus(Duration.ofMinutes(15)));
		insertSubnetRollup("192.0.3.0/24", 64498L, "Mixed Transit", 2000, 10, 0, now.minus(Duration.ofMinutes(15)));
		insertSubnetRollup("192.0.4.0/24", 64498L, "Mixed Transit", 2000, 10, 5, now.minus(Duration.ofMinutes(15))); // 5 auth reqs

		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, true, 3, 5000L, 2, "8075", 5.0, 50, 60, false, 24, false);

		List<AutoMitigationService.CarpetAttackCandidate> candidates = autoMitigationService.findCarpetAttackCandidates(config, 2);
		assertEquals(1, candidates.size());

		AutoMitigationService.CarpetAttackCandidate c = candidates.getFirst();
		assertEquals(64496L, c.asn());
		assertEquals("Attacking Hosting AS", c.asOrg());
		assertEquals(4, c.activeSubnets());
		assertEquals(8000L, c.totalRequests());
		assertEquals(100L, c.returningRequests());
		assertEquals(1.25, c.returningRatioPct(), 0.01);
		assertEquals(4, c.eligibleSubnets().size());
	}

	@Test
	void testDryRunEvaluationCreatesAuditWithoutActiveRules() {
		Instant now = Instant.now();
		for (int i = 1; i <= 3; i++) {
			insertSubnetRollup("198.51.10" + i + ".0/24", 64496L, "Attacking Hosting AS",
					2000, 20, 0, now.minus(Duration.ofMinutes(15)));
		}

		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, true, 3, 5000L, 2, "8075", 5.0, 50, 60, false, 24, false); // dryRun = true

		List<AutoMitigationService.CarpetAttackCandidate> candidates = autoMitigationService.evaluateAndEnforce(config);
		assertEquals(1, candidates.size());

		// In dry-run mode, no active rules are inserted into mitigation_rules
		List<MitigationRule> activeRules = mitigationService.getActiveRules();
		assertTrue(activeRules.isEmpty());

		// But an audit entry with action AUTO_WOULD_BLOCK must be recorded
		List<MitigationAuditEntry> audits = mitigationService.getRecentAuditEntries(10);
		assertFalse(audits.isEmpty());
		MitigationAuditEntry dryRunAudit = audits.getFirst();
		assertEquals("AUTO_WOULD_BLOCK", dryRunAudit.getAction());
		assertTrue(dryRunAudit.getDetails().contains("[DRY-RUN SIMULATION]"));
		assertTrue(dryRunAudit.getDetails().contains("Would block 3 subnets"));
	}

	@Test
	void testLiveEvaluationCreatesFleetBlocksAndAudit() {
		Instant now = Instant.now();
		for (int i = 1; i <= 3; i++) {
			insertSubnetRollup("198.51.10" + i + ".0/24", 64496L, "Attacking Hosting AS",
					2000, 20, 0, now.minus(Duration.ofMinutes(15)));
		}

		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 2, "8075", 5.0, 50, 60, false, 24, false); // dryRun = false

		List<AutoMitigationService.CarpetAttackCandidate> candidates = autoMitigationService.evaluateAndEnforce(config);
		assertEquals(1, candidates.size());

		// In live mode, 3 active rules are created
		List<MitigationRule> activeRules = mitigationService.getActiveRules();
		assertEquals(3, activeRules.size());
		for (MitigationRule r : activeRules) {
			assertEquals(MitigationRule.SOURCE_AUTO_CARPET, r.source());
			assertNotNull(r.batchId());
			assertTrue(r.batchId().startsWith("AUTO-ASN-64496"));
			assertEquals(64496L, r.asn());
			assertEquals("Attacking Hosting AS", r.asnOrganization());
		}

		// Audit entries with AUTO_BLOCK must be recorded
		List<MitigationAuditEntry> audits = mitigationService.getRecentAuditEntries(10);
		assertTrue(audits.stream().anyMatch(a -> "AUTO_BLOCK".equals(a.getAction())));
	}

	@Test
	void testCircuitBreakerEnforcement() {
		Instant now = Instant.now();
		for (int i = 1; i <= 5; i++) {
			insertSubnetRollup("198.51.10" + i + ".0/24", 64496L, "Attacking Hosting AS",
					2000, 20, 0, now.minus(Duration.ofMinutes(15)));
		}

		// Cap at 2 max active rules
		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 2, "8075", 5.0, 2, 60, false, 24, false);

		autoMitigationService.evaluateAndEnforce(config);
		List<MitigationRule> active = mitigationService.getActiveRules();
		assertEquals(2, active.size(), "Circuit breaker must cap active rules at 2");

		// Run again: circuit breaker limit reached
		autoMitigationService.evaluateAndEnforce(config);
		List<MitigationAuditEntry> audits = mitigationService.getRecentAuditEntries(10);
		assertTrue(audits.stream().anyMatch(a -> "AUTO_CIRCUIT_BREAKER".equals(a.getAction())));
	}

	@Test
	void testAutoExtensionForPersistentAttackers() {
		Instant now = Instant.now();
		// Create an active rule with source AUTO_CARPET
		MitigationRule r = mitigationService.createOrUpdateBlock(
				"198.51.100.0/24", 60, "Auto carpet attack", MitigationRule.SOURCE_AUTO_CARPET, null, "AUTO_ENGINE");

		// Simulate persistent attacker near expiration (10 min left) by updating DB
		jdbcTemplate.update("""
				UPDATE mitigation_rules
				SET deterrence_state = ?, total_blocked_hits = ?, last_hit_at = ?, expires_at = ?
				WHERE id = ?
				""",
				MitigationRule.DETERRENCE_PERSISTENT, 500, Timestamp.from(now),
				Timestamp.from(now.plus(Duration.ofMinutes(10))), r.id());

		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 2, "8075", 5.0, 50, 60, true, 24, false); // autoExtend = true

		int extended = autoMitigationService.evaluateExtensions(config);
		assertEquals(1, extended);

		MitigationRule updated = ruleRepository.findById(r.id()).orElseThrow();
		assertTrue(updated.expiresAt().isAfter(now.plus(Duration.ofMinutes(65))));

		// Dry-run mode for extensions: reset expires_at to 10m left
		jdbcTemplate.update("UPDATE mitigation_rules SET expires_at = ? WHERE id = ?",
				Timestamp.from(now.plus(Duration.ofMinutes(10))), r.id());
		AutoMitigationService.EffectiveAutoSettings dryRunConfig = new AutoMitigationService.EffectiveAutoSettings(
				true, true, 3, 5000L, 2, "8075", 5.0, 50, 60, true, 24, false);
		int dryExtended = autoMitigationService.evaluateExtensions(dryRunConfig);
		assertEquals(0, dryExtended, "Dry run does not increment actual extendedCount");

		List<MitigationAuditEntry> audits = mitigationService.getRecentAuditEntries(10);
		assertTrue(audits.stream().anyMatch(a -> "AUTO_WOULD_EXTEND".equals(a.getAction())));
	}

	@Test
	void testMitigationControllerAutoEndpoints() {
		MitigationController controller = new MitigationController(mitigationService, autoMitigationService, properties);

		ExtendedModelMap model = new ExtendedModelMap();

		// 1. Toggle master switch
		String view1 = controller.toggleAutoMitigationSetting("enabled", model);
		assertEquals("fragments/mitigation-content :: mitigationDashboard", view1);
		AutoMitigationService.EffectiveAutoSettings s1 =
				(AutoMitigationService.EffectiveAutoSettings) model.getAttribute("autoSettings");
		assertNotNull(s1);
		assertTrue(s1.isEnabled());

		// 2. Toggle dryRun
		ExtendedModelMap model2 = new ExtendedModelMap();
		controller.toggleAutoMitigationSetting("dryRun", model2);
		AutoMitigationService.EffectiveAutoSettings s2 =
				(AutoMitigationService.EffectiveAutoSettings) model2.getAttribute("autoSettings");
		assertNotNull(s2);
		assertFalse(s2.isDryRun());

		// 3. Update settings
		ExtendedModelMap model3 = new ExtendedModelMap();
		controller.updateAutoMitigationSettings(true, false, 4, 7500L, 2, "8075,16509", 3.5, 40, 120, true, 36, model3);
		AutoMitigationService.EffectiveAutoSettings s3 =
				(AutoMitigationService.EffectiveAutoSettings) model3.getAttribute("autoSettings");
		assertEquals(4, s3.getCarpetMinSubnets());
		assertEquals(7500L, s3.getCarpetMinRequests());
		assertEquals(2, s3.getCarpetWindowHours());
		assertEquals("8075,16509", s3.getProtectedAsns());
		assertTrue(s3.getProtectedAsnSet().contains(8075L));
		assertEquals(3.5, s3.getMaxReturningRatioPct(), 0.001);

		// 4. Reset to defaults
		ExtendedModelMap model4 = new ExtendedModelMap();
		controller.resetAutoMitigationSettings(model4);
		AutoMitigationService.EffectiveAutoSettings s4 =
				(AutoMitigationService.EffectiveAutoSettings) model4.getAttribute("autoSettings");
		assertFalse(s4.isHasDatabaseOverrides());

		// 5. Trigger manual evaluate
		ExtendedModelMap model5 = new ExtendedModelMap();
		String view5 = controller.triggerAutoEvaluation(model5);
		assertEquals("fragments/mitigation-content :: mitigationDashboard", view5);
		assertNotNull(model5.getAttribute("feedbackSuccess"));
	}

	@Test
	void testProtectedAsnExemptionSkipsAutonomousBlock() {
		Instant now = Instant.now();
		// ASN 8075 (Microsoft): 4 subnets, 10,000 reqs, 0 auth
		for (int i = 1; i <= 4; i++) {
			insertSubnetRollup("20.245.10" + i + ".0/24", 8075L, "Microsoft Corporation",
					2500, 25, 0, now.minus(Duration.ofMinutes(15)));
		}

		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 1, "8075,16509,14618,15169,13335", 5.0, 50, 60, false, 24, false);

		List<AutoMitigationService.CarpetAttackCandidate> candidates = autoMitigationService.evaluateAndEnforce(config);
		assertEquals(1, candidates.size(), "Candidate is detected in telemetry");

		// BUT it must NOT create any active rules because ASN 8075 is protected!
		List<MitigationRule> activeRules = mitigationService.getActiveRules();
		assertTrue(activeRules.isEmpty(), "Active rules must remain empty for protected ASNs");

		// And an audit entry for AUTO_SKIPPED_PROTECTED_ASN must be recorded
		List<MitigationAuditEntry> audits = mitigationService.getRecentAuditEntries(10);
		assertTrue(audits.stream().anyMatch(a -> "AUTO_SKIPPED_PROTECTED_ASN".equals(a.getAction())));
	}

	@Test
	void testAiCrawlerClientTypeIsExcludedFromCarpetDetection() {
		Instant now = Instant.now();
		// Insert rollups for an ASN with client_type = 'AI_CRAWLER'
		for (int i = 1; i <= 4; i++) {
			jdbcTemplate.update("""
					INSERT INTO client_subnet_rollups (
					    bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
					    asn, as_org, country_code, client_type, total_requests, active_requests,
					    blocked_requests, marked_requests, distinct_clients, min_requests_per_client,
					    max_requests_per_client, returning_requests,
					    returning_tracked_requests, authenticated_requests
					) VALUES (?, ?, 60, 'Srv01', 'PRIMARY', ?, 64499, 'OpenAI Bot Range', 'US',
					          'AI_CRAWLER', 3000, 3000, 0, 0, 25, 10, 150, 0, 3000, 0)
					""",
					Timestamp.from(now.minus(Duration.ofMinutes(15))),
					Timestamp.from(now),
					"198.51.20" + i + ".0/24");
		}

		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 1, "8075", 5.0, 50, 60, false, 24, false);

		List<AutoMitigationService.CarpetAttackCandidate> candidates = autoMitigationService.findCarpetAttackCandidates(config, 1);
		assertTrue(candidates.isEmpty(), "AI_CRAWLER rollups must be excluded from carpet attack detection");
	}

	@Test
	void testCarpetRadarEvaluationAndStatusDiscrimination() {
		Instant now = Instant.now();

		// ASN 64496: Qualified candidate (6000 reqs, 3 subnets, 0 auth, 1.6% returning)
		insertSubnetRollup("198.51.10.0/24", 64496L, "Attacking ISP", 2000, 30, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.11.0/24", 64496L, "Attacking ISP", 2000, 30, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.12.0/24", 64496L, "Attacking ISP", 2000, 40, 0, now.minus(Duration.ofMinutes(10)));

		// ASN 64497: Suppressed by returning ratio (6000 reqs, 3 subnets, 0 auth, 33.3% returning)
		insertSubnetRollup("203.0.113.10.0/24", 64497L, "Scraper Network", 2000, 700, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("203.0.113.11.0/24", 64497L, "Scraper Network", 2000, 700, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("203.0.113.12.0/24", 64497L, "Scraper Network", 2000, 600, 0, now.minus(Duration.ofMinutes(10)));

		// ASN 64498: Suppressed by authenticated logins (6000 reqs, 3 subnets, 50 auth, 2% returning)
		insertSubnetRollup("192.0.2.10.0/24", 64498L, "Campus Network", 2000, 40, 20, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("192.0.2.11.0/24", 64498L, "Campus Network", 2000, 40, 20, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("192.0.2.12.0/24", 64498L, "Campus Network", 2000, 40, 10, now.minus(Duration.ofMinutes(10)));

		// ASN 8075: Protected ASN (Microsoft)
		insertSubnetRollup("40.76.0.0/24", 8075L, "Microsoft Azure", 3000, 0, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("40.76.1.0/24", 8075L, "Microsoft Azure", 3000, 0, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("40.76.2.0/24", 8075L, "Microsoft Azure", 3000, 0, 0, now.minus(Duration.ofMinutes(10)));

		List<org.henbru.antidos.collector.model.CarpetRadarEntry> radar = autoMitigationService.getCarpetRadar(1);
		assertFalse(radar.isEmpty());

		// Verify ASN 64496 is QUALIFIED
		org.henbru.antidos.collector.model.CarpetRadarEntry qualified = radar.stream()
				.filter(e -> e.asn() == 64496L)
				.findFirst()
				.orElseThrow();
		assertEquals("QUALIFIED", qualified.status());
		assertEquals("badge-danger", qualified.badgeClass());
		assertTrue(qualified.isQualified());
		assertFalse(qualified.isSuppressed());

		// Verify ASN 64497 is SUPPRESSED_RETURNING_RATIO
		org.henbru.antidos.collector.model.CarpetRadarEntry suppressedReturn = radar.stream()
				.filter(e -> e.asn() == 64497L)
				.findFirst()
				.orElseThrow();
		assertEquals("SUPPRESSED_RETURNING_RATIO", suppressedReturn.status());
		assertEquals("badge-warning", suppressedReturn.badgeClass());
		assertTrue(suppressedReturn.returningRatioPct() > 5.0);
		assertTrue(suppressedReturn.isSuppressed());

		// Verify ASN 64498 is SUPPRESSED_AUTH
		org.henbru.antidos.collector.model.CarpetRadarEntry suppressedAuth = radar.stream()
				.filter(e -> e.asn() == 64498L)
				.findFirst()
				.orElseThrow();
		assertEquals("SUPPRESSED_AUTH", suppressedAuth.status());
		assertEquals(50L, suppressedAuth.authenticatedRequests());
		assertTrue(suppressedAuth.isSuppressed());

		// Verify ASN 8075 is PROTECTED_ASN
		org.henbru.antidos.collector.model.CarpetRadarEntry protectedAsn = radar.stream()
				.filter(e -> e.asn() == 8075L)
				.findFirst()
				.orElseThrow();
		assertEquals("PROTECTED_ASN", protectedAsn.status());
		assertTrue(protectedAsn.isProtectedAsn());
	}

	private void insertSubnetRollup(
			String subnetGroup,
			long asn,
			String asOrg,
			long totalReqs,
			long returningReqs,
			long authReqs,
			Instant bucketTime
	) {
		jdbcTemplate.update("""
				INSERT INTO client_subnet_rollups (
				    bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
				    asn, as_org, country_code, client_type, total_requests, active_requests,
				    blocked_requests, marked_requests, distinct_clients, min_requests_per_client,
				    max_requests_per_client, returning_requests,
				    returning_tracked_requests, authenticated_requests
				) VALUES (?, ?, 60, 'Srv01', 'PRIMARY', ?, ?, ?, 'US',
				          'HOSTING_PROVIDER', ?, ?, 0, 0, 25, 10, 150, ?, ?, ?)
				""",
				Timestamp.from(bucketTime),
				Timestamp.from(bucketTime.plus(Duration.ofMinutes(15))),
				subnetGroup,
				asn,
				asOrg,
				totalReqs,
				totalReqs,
				returningReqs,
				totalReqs,
				authReqs
		);
	}
}
