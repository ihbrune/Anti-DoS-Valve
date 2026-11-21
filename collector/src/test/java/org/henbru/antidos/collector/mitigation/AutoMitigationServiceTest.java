package org.henbru.antidos.collector.mitigation;

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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
		assertEquals(0L, s1.getMaxAuthenticatedRequests());
		assertEquals(20L, s1.getCarpetMinRequestsPerSubnet(), "YAML default for min requests per subnet");
		assertEquals(50, s1.getMaxActiveRules());
		assertFalse(s1.isHasDatabaseOverrides());

		// 1b. New per-subnet threshold is persisted and reset like all other overrides
		autoMitigationService.updateSettings(true, false, 3, 5000L, 2, "8075", 5.0, 0L, 35L, 50, 60, false, 24, "OPERATOR-CAROL");
		assertEquals(35L, autoMitigationService.getEffectiveSettings().getCarpetMinRequestsPerSubnet());
		autoMitigationService.resetToDefaults("OPERATOR-CAROL");
		assertEquals(20L, autoMitigationService.getEffectiveSettings().getCarpetMinRequestsPerSubnet());

		// 2. Update settings via database overrides
		autoMitigationService.updateSettings(true, false, 5, 10000L, 3, "8075,16509", 2.5, 25L, 30, 90, true, 48, "OPERATOR-ALICE");
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
		assertEquals(25L, s2.getMaxAuthenticatedRequests());
		assertEquals(30, s2.getMaxActiveRules());
		assertEquals(90, s2.getDefaultTtlMinutes());
		assertTrue(s2.isAutoExtendPersistent());
		assertEquals(48, s2.getMaxExtensionHours());
		assertTrue(s2.isHasDatabaseOverrides());

		// 2b. Verify arbitrary / low values and backwards-compatible overload
		autoMitigationService.updateSettings(false, true, 1, 50L, 1, "AS8075", 0.25, 1, 60, false, 2, "OPERATOR-BOB");
		AutoMitigationService.EffectiveAutoSettings s2b = autoMitigationService.getEffectiveSettings();
		assertEquals(1, s2b.getCarpetMinSubnets());
		assertEquals(50L, s2b.getCarpetMinRequests());
		assertEquals(1, s2b.getCarpetWindowHours());
		assertTrue(s2b.getProtectedAsnSet().contains(8075L));
		assertEquals(0.25, s2b.getMaxReturningRatioPct(), 0.001);
		assertEquals(0L, s2b.getMaxAuthenticatedRequests());
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
		assertEquals(0L, s3.getMaxAuthenticatedRequests());
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
		controller.updateAutoMitigationSettings(true, false, 4, 7500L, 2, "8075,16509", 3.5, 20L, 40, 120, true, 36, model3);
		AutoMitigationService.EffectiveAutoSettings s3 =
				(AutoMitigationService.EffectiveAutoSettings) model3.getAttribute("autoSettings");
		assertEquals(4, s3.getCarpetMinSubnets());
		assertEquals(7500L, s3.getCarpetMinRequests());
		assertEquals(2, s3.getCarpetWindowHours());
		assertEquals("8075,16509", s3.getProtectedAsns());
		assertTrue(s3.getProtectedAsnSet().contains(8075L));
		assertEquals(3.5, s3.getMaxReturningRatioPct(), 0.001);
		assertEquals(20L, s3.getMaxAuthenticatedRequests());

		// Toggle preserves maxAuthenticatedRequests
		ExtendedModelMap modelToggle = new ExtendedModelMap();
		controller.toggleAutoMitigationSetting("dryRun", modelToggle);
		AutoMitigationService.EffectiveAutoSettings sToggle =
				(AutoMitigationService.EffectiveAutoSettings) modelToggle.getAttribute("autoSettings");
		assertEquals(20L, sToggle.getMaxAuthenticatedRequests());
		assertTrue(sToggle.isDryRun());

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

	@Test
	void testMaxAuthenticatedRequestsThresholdBlocksOnlyUnauthenticatedSubnets() {
		Instant now = Instant.now();

		// ASN 64500: 4 subnets (3 unauthenticated + 1 with 8 authenticated requests)
		insertSubnetRollup("198.51.101.0/24", 64500L, "Mixed Hosting AS", 2000, 20, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.102.0/24", 64500L, "Mixed Hosting AS", 2000, 20, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.103.0/24", 64500L, "Mixed Hosting AS", 2000, 20, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.104.0/24", 64500L, "Mixed Hosting AS", 2000, 20, 8, now.minus(Duration.ofMinutes(10)));

		// ASN 64501: 3 subnets (only 2 unauthenticated + 1 with 5 auth -> < minSubnets=3 eligible)
		insertSubnetRollup("203.0.120.0/24", 64501L, "Small Mixed AS", 2000, 10, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("203.0.121.0/24", 64501L, "Small Mixed AS", 2000, 10, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("203.0.122.0/24", 64501L, "Small Mixed AS", 2000, 10, 5, now.minus(Duration.ofMinutes(10)));

		// 1. Default maxAuthenticatedRequests = 0 -> ASN 64500 is suppressed
		AutoMitigationService.EffectiveAutoSettings zeroAuthConfig = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 2, "8075", 5.0, 0L, 50, 60, false, 24, false);
		assertTrue(autoMitigationService.findCarpetAttackCandidates(zeroAuthConfig, 2).isEmpty());

		List<org.henbru.antidos.collector.model.CarpetRadarEntry> radarZero = autoMitigationService.getCarpetRadar(2);
		org.henbru.antidos.collector.model.CarpetRadarEntry entryZero = radarZero.stream()
				.filter(e -> e.asn() == 64500L)
				.findFirst()
				.orElseThrow();
		assertEquals("SUPPRESSED_AUTH", entryZero.status());
		assertEquals(8L, entryZero.authenticatedRequests());

		// 2. Increase maxAuthenticatedRequests to 10 (persisted for getCarpetRadar as well)
		autoMitigationService.updateSettings(true, false, 3, 5000L, 2, "8075", 5.0, 10L, 50, 60, false, 24, "OPERATOR");
		AutoMitigationService.EffectiveAutoSettings tolerantConfig = autoMitigationService.getEffectiveSettings();
		assertEquals(10L, tolerantConfig.getMaxAuthenticatedRequests());

		// Carpet radar transitions ASN 64500 to QUALIFIED, while ASN 64501 is BELOW_SUBNET_THRESHOLD
		List<org.henbru.antidos.collector.model.CarpetRadarEntry> radarTolerant = autoMitigationService.getCarpetRadar(2);
		org.henbru.antidos.collector.model.CarpetRadarEntry entryTolerant = radarTolerant.stream()
				.filter(e -> e.asn() == 64500L)
				.findFirst()
				.orElseThrow();
		assertEquals("QUALIFIED", entryTolerant.status());

		org.henbru.antidos.collector.model.CarpetRadarEntry smallMixed = radarTolerant.stream()
				.filter(e -> e.asn() == 64501L)
				.findFirst()
				.orElseThrow();
		assertEquals("BELOW_SUBNET_THRESHOLD", smallMixed.status());

		// Candidate detection and enforcement only block the 3 unauthenticated subnets of ASN 64500
		List<AutoMitigationService.CarpetAttackCandidate> candidates = autoMitigationService.evaluateAndEnforce(tolerantConfig);
		assertEquals(1, candidates.size());
		AutoMitigationService.CarpetAttackCandidate candidate = candidates.getFirst();
		assertEquals(64500L, candidate.asn());
		assertEquals(3, candidate.eligibleSubnets().size());
		assertFalse(candidate.eligibleSubnets().contains("198.51.104.0/24"));

		List<String> blockedCidrs = mitigationService.getActiveRules().stream().map(MitigationRule::cidr).toList();
		assertEquals(3, blockedCidrs.size());
		assertTrue(blockedCidrs.contains("198.51.101.0/24"));
		assertTrue(blockedCidrs.contains("198.51.102.0/24"));
		assertTrue(blockedCidrs.contains("198.51.103.0/24"));
		assertFalse(blockedCidrs.contains("198.51.104.0/24"), "Authenticated subnet must NEVER be auto-blocked");
	}

	@Test
	void testMinRequestsPerSubnetFiltersLowVolumeRotatingSubnets() {
		Instant now = Instant.now();
		// ASN 64800: 3 heavy subnets plus 50 rotating proxy subnets with only 5 requests each
		for (int i = 1; i <= 3; i++) {
			insertSubnetRollup("198.51.10" + i + ".0/24", 64800L, "Proxy Botnet ISP", 1000, 10, 0, now.minus(Duration.ofMinutes(10)));
		}
		for (int i = 0; i < 50; i++) {
			insertSubnetRollup("203.0." + (100 + i) + ".0/24", 64800L, "Proxy Botnet ISP", 5, 0, 0, now.minus(Duration.ofMinutes(10)));
		}

		AutoMitigationService.EffectiveAutoSettings noFilter = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 3000L, 2, "8075", 5.0, 0L, 0L, 5000, 60, false, 24, false);
		assertEquals(53, autoMitigationService.findCarpetAttackCandidates(noFilter, 2).getFirst().eligibleSubnets().size());

		AutoMitigationService.EffectiveAutoSettings withFilter = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 3000L, 2, "8075", 5.0, 0L, 20L, 5000, 60, false, 24, false);
		List<AutoMitigationService.CarpetAttackCandidate> candidates = autoMitigationService.findCarpetAttackCandidates(withFilter, 2);
		assertEquals(1, candidates.size());
		assertEquals(3, candidates.getFirst().eligibleSubnets().size(), "Only subnets with >= 20 own requests are eligible");
		assertEquals(1000L, candidates.getFirst().eligibleSubnetRequests().get("198.51.101.0/24"));

		autoMitigationService.evaluateAndEnforce(withFilter);
		assertEquals(3, mitigationService.getActiveRules().size());
	}

	@Test
	void testPriorityAllocatesCapacityToStrongestSubnetsAcrossAsns() {
		Instant now = Instant.now();
		// ASN 64700: larger aggregate volume but weak per subnet (10 x 800 = 8,000)
		for (int i = 0; i < 10; i++) {
			insertSubnetRollup("198.51.2" + i + ".0/24", 64700L, "Wide Weak Network", 800, 5, 0, now.minus(Duration.ofMinutes(10)));
		}
		// ASN 64701: smaller aggregate volume but strong per subnet (3 x 2,500 = 7,500)
		for (int i = 0; i < 3; i++) {
			insertSubnetRollup("203.0.12" + i + ".0/24", 64701L, "Concentrated Scraper", 2500, 5, 0, now.minus(Duration.ofMinutes(10)));
		}

		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 2, "8075", 5.0, 0L, 0L, 3, 60, false, 24, false);
		autoMitigationService.evaluateAndEnforce(config);

		List<MitigationRule> active = mitigationService.getActiveRules();
		assertEquals(3, active.size(), "Cap of 3 rules must be respected");
		assertTrue(active.stream().allMatch(r -> Long.valueOf(64701L).equals(r.asn())),
				"Capacity must go to the strongest subnets, not to the ASN with the largest aggregate volume");
		assertTrue(mitigationService.getRecentAuditEntries(20).stream()
				.anyMatch(a -> "AUTO_CIRCUIT_BREAKER".equals(a.getAction()) && a.getDetails().contains("Skipped 10")));
	}

	@Test
	void testUnusedAutoRulesAreReleasedWhenCapIsReached() {
		Instant now = Instant.now();
		MitigationRule unused1 = mitigationService.createOrUpdateBlock("203.0.113.0/24", 60, "Old carpet", MitigationRule.SOURCE_AUTO_CARPET, "B1", "AUTO_ENGINE");
		MitigationRule unused2 = mitigationService.createOrUpdateBlock("203.0.114.0/24", 60, "Old carpet", MitigationRule.SOURCE_AUTO_CARPET, "B1", "AUTO_ENGINE");
		MitigationRule effective = mitigationService.createOrUpdateBlock("203.0.115.0/24", 60, "Old carpet", MitigationRule.SOURCE_AUTO_CARPET, "B1", "AUTO_ENGINE");
		MitigationRule manual = mitigationService.createOrUpdateBlock("203.0.116.0/24", 60, "Manual block", MitigationRule.SOURCE_MANUAL, "B2", "ADMIN");

		// All rules are past their observation phase; only one has ever blocked traffic
		jdbcTemplate.update("UPDATE mitigation_rules SET created_at = ?", Timestamp.from(now.minus(Duration.ofMinutes(30))));
		jdbcTemplate.update("UPDATE mitigation_rules SET total_blocked_hits = 42, last_hit_at = ?, deterrence_state = ? WHERE id = ?",
				Timestamp.from(now.minus(Duration.ofMinutes(1))), MitigationRule.DETERRENCE_PERSISTENT, effective.id());

		// Candidate ASN with 3 strong subnets while total active rules (3 auto + 1 manual = 4) already fill the cap (4)
		insertSubnetRollup("198.51.101.0/24", 64600L, "New Attacker", 2500, 5, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.102.0/24", 64600L, "New Attacker", 2000, 5, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.103.0/24", 64600L, "New Attacker", 1500, 5, 0, now.minus(Duration.ofMinutes(10)));

		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 2, "8075", 5.0, 0L, 0L, 4, 60, false, 24, false);
		autoMitigationService.evaluateAndEnforce(config);

		assertEquals(MitigationRule.STATUS_REVOKED, ruleRepository.findById(unused1.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_REVOKED, ruleRepository.findById(unused2.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(effective.id()).orElseThrow().status(),
				"Rules that blocked traffic must never be released early");
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(manual.id()).orElseThrow().status(),
				"Manual rules must never be released by the auto engine");

		List<String> newCidrs = mitigationService.getActiveRules().stream()
				.filter(r -> Long.valueOf(64600L).equals(r.asn())).map(MitigationRule::cidr).toList();
		assertEquals(List.of("198.51.101.0/24", "198.51.102.0/24").stream().sorted().toList(), newCidrs.stream().sorted().toList(),
				"The two strongest subnets take the released capacity");

		List<MitigationAuditEntry> audits = mitigationService.getRecentAuditEntries(30);
		assertTrue(audits.stream().anyMatch(a -> "AUTO_RELEASE_UNUSED".equals(a.getAction())));
		assertTrue(audits.stream().anyMatch(a -> "AUTO_CIRCUIT_BREAKER".equals(a.getAction())));
	}

	@Test
	void testFreshRulesAreNotReleasedDuringObservationPhase() {
		Instant now = Instant.now();
		for (int i = 0; i < 3; i++) {
			mitigationService.createOrUpdateBlock("203.0.11" + i + ".0/24", 60, "Fresh carpet", MitigationRule.SOURCE_AUTO_CARPET, "B1", "AUTO_ENGINE");
		}
		for (int i = 1; i <= 3; i++) {
			insertSubnetRollup("198.51.10" + i + ".0/24", 64601L, "Another Attacker", 2000, 5, 0, now.minus(Duration.ofMinutes(10)));
		}
		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 2, "8075", 5.0, 0L, 0L, 3, 60, false, 24, false);
		autoMitigationService.evaluateAndEnforce(config);

		List<MitigationRule> active = mitigationService.getActiveRules();
		assertEquals(3, active.size());
		assertTrue(active.stream().noneMatch(r -> Long.valueOf(64601L).equals(r.asn())));
	}

	@Test
	void testReactivatedRuleStartsFreshLifecycle() {
		MitigationRule first = mitigationService.createOrUpdateBlock("203.0.113.0/24", 60, "First", MitigationRule.SOURCE_AUTO_CARPET, "B1", "AUTO_ENGINE");
		Instant old = Instant.now().minus(Duration.ofDays(3));
		jdbcTemplate.update("UPDATE mitigation_rules SET status = 'EXPIRED', created_at = ?, expires_at = ?, total_blocked_hits = 99, last_hit_at = ? WHERE id = ?",
				Timestamp.from(old), Timestamp.from(old.plus(Duration.ofHours(1))), Timestamp.from(old), first.id());

		MitigationRule again = mitigationService.createOrUpdateBlock("203.0.113.0/24", 60, "Again", MitigationRule.SOURCE_AUTO_CARPET, "B2", "AUTO_ENGINE");
		assertEquals(first.id(), again.id());
		assertTrue(again.createdAt().isAfter(Instant.now().minus(Duration.ofMinutes(1))), "Activation time must be reset");
		assertEquals(0L, again.totalBlockedHits());
		assertEquals(null, again.lastHitAt());

		// Extending an active rule keeps its lifecycle
		jdbcTemplate.update("UPDATE mitigation_rules SET total_blocked_hits = 7 WHERE id = ?", again.id());
		MitigationRule extended = mitigationService.createOrUpdateBlock("203.0.113.0/24", 60, "Extend", MitigationRule.SOURCE_AUTO_CARPET, "B3", "AUTO_ENGINE");
		assertEquals(7L, extended.totalBlockedHits());
	}

	@Test
	void testCompactValveLabelsAreShortAndSafe() {
		Instant exp = Instant.now().plus(Duration.ofMinutes(30));
		MitigationRule auto = new MitigationRule(1L, "198.51.100.0/24", 4, 24, "ALL", MitigationRule.STATUS_ACTIVE,
				MitigationRule.SOURCE_AUTO_CARPET, "B", "Carpet attack from ASN 7922 (Comcast Cable Communications, LLC): 6692 subnets, 16433 reqs",
				7922L, "Comcast", Instant.now(), Instant.now(), exp, null, null, 0L, 0, null, MitigationRule.DETERRENCE_OBSERVING);
		MitigationRule manual = new MitigationRule(2L, "203.0.113.0/24", 4, 24, "ALL", MitigationRule.STATUS_ACTIVE,
				MitigationRule.SOURCE_MANUAL, null, "Scraper; see ticket|42\nsecond line and a very long explanation that goes on and on beyond limits",
				null, null, Instant.now(), Instant.now(), exp, null, null, 0L, 0, null, MitigationRule.DETERRENCE_OBSERVING);

		assertEquals("AUTO_CARPET AS7922", MitigationService.compactValveLabel(auto));
		String manualLabel = MitigationService.compactValveLabel(manual);
		assertTrue(manualLabel.length() <= 64);
		assertFalse(manualLabel.contains(";"), "Valve splits block lines on ';'");
		assertFalse(manualLabel.contains("|"));
		assertFalse(manualLabel.contains("\n"));

		String payload = MitigationService.buildBlocksPayload(List.of(auto, manual));
		assertEquals(2, payload.split("[\\r\\n;]+").length, "Payload must parse into exactly one line per rule on the Valve");
	}

	@Test
	void testDeferredFleetSyncCoalescesPushes() {
		Instant now = Instant.now();
		valveRepository.upsert(new MonitoredValve(
				"SRV-SYNC", "MITIGATION", "Mitigation valve", 1, "BLOCKING", false, false, 429,
				100, 60, 5, 0.8f, 32, 64, 1000, 1000, null, null, null, null,
				"/antidos-status", "127.0.0.1", now, 1));
		valveRepository.updateDynamicMitigationStats("SRV-SYNC", "MITIGATION", true, "/antidos-status", 0, 0L, 0L);

		long before = countAudits("FLEET_SYNC");
		mitigationService.createOrUpdateBlock("203.0.113.0/24", 60, "A", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
		mitigationService.createOrUpdateBlock("203.0.114.0/24", 60, "B", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
		assertEquals(before + 2, countAudits("FLEET_SYNC"), "Without deferral every change pushes the full rule set");

		long mid = countAudits("FLEET_SYNC");
		mitigationService.runWithDeferredFleetSync(() -> {
			mitigationService.createOrUpdateBlock("203.0.115.0/24", 60, "C", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
			mitigationService.createOrUpdateBlock("203.0.116.0/24", 60, "D", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
			mitigationService.runWithDeferredFleetSync(() ->
					mitigationService.createOrUpdateBlock("203.0.117.0/24", 60, "E", MitigationRule.SOURCE_MANUAL, null, "ADMIN"));
		});
		assertEquals(mid + 1, countAudits("FLEET_SYNC"), "Deferred scope must push exactly once");
	}

	@Test
	void testEligibleSubnetsRespect24hSafetyWindowAndRadarCaching() {
		Instant now = Instant.now();
		// 4 subnets active in last 1h from ASN 64900 (2000 reqs each):
		// - .101..103 are cleanly unauthenticated over full 24h
		// - .104 has 0 auth in the 1h carpet window, but had 3 authenticated requests 6 hours ago -> must be excluded!
		// - .105 has 0 auth in 1h, but had SEARCH_ENGINE traffic 6 hours ago -> must be excluded!
		insertSubnetRollup("198.51.101.0/24", 64900L, "Mixed History AS", 2000, 10, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.102.0/24", 64900L, "Mixed History AS", 2000, 10, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.103.0/24", 64900L, "Mixed History AS", 2000, 10, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.104.0/24", 64900L, "Mixed History AS", 2000, 10, 0, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollup("198.51.104.0/24", 64900L, "Mixed History AS", 50, 10, 3, now.minus(Duration.ofHours(6)));
		insertSubnetRollup("198.51.105.0/24", 64900L, "Mixed History AS", 2000, 10, 0, now.minus(Duration.ofMinutes(10)));
		jdbcTemplate.update("""
				INSERT INTO client_subnet_rollups (
				    bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
				    asn, as_org, country_code, client_type, total_requests, active_requests,
				    blocked_requests, marked_requests, distinct_clients, min_requests_per_client,
				    max_requests_per_client, returning_requests,
				    returning_tracked_requests, authenticated_requests
				) VALUES (?, ?, 60, 'Srv01', 'PRIMARY', '198.51.105.0/24', 64900, 'Mixed History AS', 'US',
				          'SEARCH_ENGINE', 50, 50, 0, 0, 1, 1, 50, 0, 50, 0)
				""", Timestamp.from(now.minus(Duration.ofHours(6))), Timestamp.from(now.minus(Duration.ofHours(5))));

		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 1, "8075", 5.0, 0L, 20L, 50, 60, false, 24, false);

		List<AutoMitigationService.CarpetAttackCandidate> candidates = autoMitigationService.findCarpetAttackCandidates(config, 1);
		assertEquals(1, candidates.size());
		List<String> eligible = candidates.getFirst().eligibleSubnets();
		assertEquals(3, eligible.size());
		assertFalse(eligible.contains("198.51.104.0/24"), "Subnet with auth traffic in 24h window must be excluded");
		assertFalse(eligible.contains("198.51.105.0/24"), "Subnet with SEARCH_ENGINE traffic in 24h window must be excluded");

		// Radar cache lifecycle: null before scan -> cached after getCarpetRadar -> null after invalidation
		assertEquals(null, autoMitigationService.getCachedCarpetRadar(1));
		List<org.henbru.antidos.collector.model.CarpetRadarEntry> radar = autoMitigationService.getCarpetRadar(1);
		assertFalse(radar.isEmpty());
		assertNotNull(autoMitigationService.getCachedCarpetRadar(1));
		autoMitigationService.invalidateRadarCache();
		assertEquals(null, autoMitigationService.getCachedCarpetRadar(1));
	}

	@Test
	void testCircuitBreakerCountsManualAndAsnBatchRulesAndPreventsOverCapCreation() {
		Instant now = Instant.now();
		// 2 MANUAL + 2 ASN_BATCH + 1 unused AUTO_CARPET = 5 active rules while cap is 3
		MitigationRule manual1 = mitigationService.createOrUpdateBlock("203.0.110.0/24", 60, "Manual 1", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
		MitigationRule manual2 = mitigationService.createOrUpdateBlock("203.0.111.0/24", 60, "Manual 2", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
		MitigationRule asnBatch1 = mitigationService.createOrUpdateBlock("203.0.112.0/24", 60, "ASN Batch 1", MitigationRule.SOURCE_ASN_BATCH, "ASN-64500", "ADMIN");
		MitigationRule asnBatch2 = mitigationService.createOrUpdateBlock("203.0.113.0/24", 60, "ASN Batch 2", MitigationRule.SOURCE_ASN_BATCH, "ASN-64500", "ADMIN");
		MitigationRule unusedAuto = mitigationService.createOrUpdateBlock("203.0.114.0/24", 60, "Old auto", MitigationRule.SOURCE_AUTO_CARPET, "AUTO-OLD", "AUTO_ENGINE");

		jdbcTemplate.update("UPDATE mitigation_rules SET created_at = ?", Timestamp.from(now.minus(Duration.ofMinutes(30))));

		// New carpet attack candidate ASN 64602 with 3 strong subnets
		for (int i = 1; i <= 3; i++) {
			insertSubnetRollup("198.51.15" + i + ".0/24", 64602L, "Carpet Attacker", 3000, 5, 0, now.minus(Duration.ofMinutes(10)));
		}

		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 2, "8075", 5.0, 0L, 0L, 3, 60, false, 24, false);
		autoMitigationService.evaluateAndEnforce(config);

		List<MitigationRule> active = mitigationService.getActiveRules();
		assertEquals(4, active.size(), "Excess unused auto rule must be released while non-auto rules remain untouched and no new auto rules are added");
		assertTrue(active.stream().noneMatch(r -> Long.valueOf(64602L).equals(r.asn())),
				"Candidate ASN subnets must all be skipped by circuit breaker");
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(manual1.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(manual2.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(asnBatch1.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(asnBatch2.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_REVOKED, ruleRepository.findById(unusedAuto.id()).orElseThrow().status(),
				"Excess unused autonomous rule above cap must be automatically released");

		List<MitigationAuditEntry> audits = mitigationService.getRecentAuditEntries(20);
		assertTrue(audits.stream().anyMatch(a -> "AUTO_CIRCUIT_BREAKER".equals(a.getAction())
				&& a.getDetails().contains("4 manual/other")
				&& a.getDetails().contains("Skipped 3")));
		assertTrue(audits.stream().anyMatch(a -> "AUTO_RELEASE_UNUSED".equals(a.getAction())));
	}

	@Test
	void testExcessUnusedAutoRulesAreReleasedEvenWithoutCandidates() {
		Instant now = Instant.now();
		MitigationRule unusedAuto1 = mitigationService.createOrUpdateBlock("203.0.120.0/24", 60, "Old auto 1", MitigationRule.SOURCE_AUTO_CARPET, "AUTO-1", "AUTO_ENGINE");
		MitigationRule unusedAuto2 = mitigationService.createOrUpdateBlock("203.0.121.0/24", 60, "Old auto 2", MitigationRule.SOURCE_AUTO_CARPET, "AUTO-1", "AUTO_ENGINE");
		MitigationRule manual1 = mitigationService.createOrUpdateBlock("203.0.122.0/24", 60, "Manual 1", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
		jdbcTemplate.update("UPDATE mitigation_rules SET created_at = ?", Timestamp.from(now.minus(Duration.ofMinutes(30))));

		// Lower cap to 2 with no carpet candidates in telemetry -> 1 unused auto rule above cap must be released
		AutoMitigationService.EffectiveAutoSettings config = new AutoMitigationService.EffectiveAutoSettings(
				true, false, 3, 5000L, 2, "8075", 5.0, 0L, 0L, 2, 60, false, 24, false);
		autoMitigationService.evaluateAndEnforce(config);

		assertEquals(2, mitigationService.getActiveRules().size());
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(manual1.id()).orElseThrow().status());
		long activeAutoCount = mitigationService.getActiveRules().stream()
				.filter(r -> MitigationRule.SOURCE_AUTO_CARPET.equals(r.source()))
				.count();
		assertEquals(1L, activeAutoCount);
		assertTrue(ruleRepository.findById(unusedAuto1.id()).orElseThrow().status().equals(MitigationRule.STATUS_REVOKED)
				|| ruleRepository.findById(unusedAuto2.id()).orElseThrow().status().equals(MitigationRule.STATUS_REVOKED));
	}

	@Test
	void testPruneActiveRulesToCapOptimalEvictionOrder() {
		Instant now = Instant.now();
		MitigationRule unusedAuto = mitigationService.createOrUpdateBlock("198.51.10.0/24", 60, "Unused auto", MitigationRule.SOURCE_AUTO_CARPET, "B1", "AUTO_ENGINE");
		MitigationRule unusedManual = mitigationService.createOrUpdateBlock("198.51.11.0/24", 60, "Unused manual", MitigationRule.SOURCE_MANUAL, null, "ADMIN");
		MitigationRule deterredAuto = mitigationService.createOrUpdateBlock("198.51.12.0/24", 60, "Deterred auto", MitigationRule.SOURCE_AUTO_CARPET, "B1", "AUTO_ENGINE");
		MitigationRule deterredAsnBatch = mitigationService.createOrUpdateBlock("198.51.13.0/24", 60, "Deterred batch", MitigationRule.SOURCE_ASN_BATCH, "ASN-64501", "ADMIN");
		MitigationRule observingAuto = mitigationService.createOrUpdateBlock("198.51.14.0/24", 60, "Observing auto", MitigationRule.SOURCE_AUTO_CARPET, "B2", "AUTO_ENGINE");
		MitigationRule persistentWeakAuto = mitigationService.createOrUpdateBlock("198.51.15.0/24", 60, "Persistent weak auto", MitigationRule.SOURCE_AUTO_CARPET, "B2", "AUTO_ENGINE");
		MitigationRule persistentStrongAuto = mitigationService.createOrUpdateBlock("198.51.16.0/24", 60, "Persistent strong auto", MitigationRule.SOURCE_AUTO_CARPET, "B2", "AUTO_ENGINE");
		MitigationRule persistentManual = mitigationService.createOrUpdateBlock("198.51.17.0/24", 60, "Persistent manual", MitigationRule.SOURCE_MANUAL, null, "ADMIN");

		// Age rules appropriately so deterrence states remain deterministic after refreshDeterrenceMetrics()
		jdbcTemplate.update("UPDATE mitigation_rules SET created_at = ? WHERE id IN (?, ?, ?, ?, ?, ?)",
				Timestamp.from(now.minus(Duration.ofMinutes(30))),
				unusedAuto.id(), unusedManual.id(), persistentWeakAuto.id(), persistentStrongAuto.id(), persistentManual.id(), observingAuto.id());
		jdbcTemplate.update("UPDATE mitigation_rules SET created_at = ? WHERE id = ?",
				Timestamp.from(now.minus(Duration.ofMinutes(2))), observingAuto.id());
		jdbcTemplate.update("UPDATE mitigation_rules SET created_at = ?, total_blocked_hits = 50, last_hit_at = ?, deterrence_state = ? WHERE id = ?",
				Timestamp.from(now.minus(Duration.ofMinutes(40))), Timestamp.from(now.minus(Duration.ofMinutes(20))), MitigationRule.DETERRENCE_DETERRED, deterredAuto.id());
		jdbcTemplate.update("UPDATE mitigation_rules SET created_at = ?, total_blocked_hits = 200, last_hit_at = ?, deterrence_state = ? WHERE id = ?",
				Timestamp.from(now.minus(Duration.ofMinutes(40))), Timestamp.from(now.minus(Duration.ofMinutes(15))), MitigationRule.DETERRENCE_DETERRED, deterredAsnBatch.id());
		jdbcTemplate.update("UPDATE mitigation_rules SET total_blocked_hits = 100, last_hit_at = ?, deterrence_state = ? WHERE id = ?",
				Timestamp.from(now.minus(Duration.ofMinutes(1))), MitigationRule.DETERRENCE_PERSISTENT, persistentWeakAuto.id());
		jdbcTemplate.update("UPDATE mitigation_rules SET total_blocked_hits = 5000, last_hit_at = ?, deterrence_state = ? WHERE id = ?",
				Timestamp.from(now.minus(Duration.ofMinutes(1))), MitigationRule.DETERRENCE_PERSISTENT, persistentStrongAuto.id());
		jdbcTemplate.update("UPDATE mitigation_rules SET total_blocked_hits = 100, last_hit_at = ?, deterrence_state = ? WHERE id = ?",
				Timestamp.from(now.minus(Duration.ofMinutes(1))), MitigationRule.DETERRENCE_PERSISTENT, persistentManual.id());

		// 1. Prune 8 active rules down to cap 3 via controller endpoint
		MitigationController controller = new MitigationController(mitigationService, autoMitigationService, properties);
		ExtendedModelMap model = new ExtendedModelMap();
		String view = controller.pruneRulesToCap(3, model);
		assertEquals("fragments/mitigation-content :: mitigationDashboard", view);
		String feedback = (String) model.getAttribute("feedbackSuccess");
		assertNotNull(feedback);
		assertTrue(feedback.contains("8 down to 3"));
		assertTrue(feedback.contains("2 unused, 2 deterred, 1 observing, 0 persistent"));

		List<MitigationRule> remaining3 = mitigationService.getActiveRules();
		assertEquals(3, remaining3.size());
		assertEquals(MitigationRule.STATUS_REVOKED, ruleRepository.findById(unusedAuto.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_REVOKED, ruleRepository.findById(unusedManual.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_REVOKED, ruleRepository.findById(deterredAuto.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_REVOKED, ruleRepository.findById(deterredAsnBatch.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_REVOKED, ruleRepository.findById(observingAuto.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(persistentWeakAuto.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(persistentStrongAuto.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(persistentManual.id()).orElseThrow().status());

		// 2. Prune further from 3 down to 2: AUTO_CARPET (100 hits) must be evicted before MANUAL (100 hits) and AUTO_CARPET (5000 hits)
		MitigationService.PruneToCapResult step2 = mitigationService.pruneActiveRulesToCap(2, "ADMIN");
		assertEquals(3, step2.beforeCount());
		assertEquals(2, step2.afterCount());
		assertEquals(1, step2.revokedCount());
		assertEquals(1, step2.revokedPersistentCount());
		assertEquals(MitigationRule.STATUS_REVOKED, ruleRepository.findById(persistentWeakAuto.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(persistentStrongAuto.id()).orElseThrow().status());
		assertEquals(MitigationRule.STATUS_ACTIVE, ruleRepository.findById(persistentManual.id()).orElseThrow().status());

		List<MitigationAuditEntry> audits = mitigationService.getRecentAuditEntries(20);
		assertTrue(audits.stream().anyMatch(a -> "PRUNE_TO_CAP".equals(a.getAction())
				&& a.getDetails().contains("2 unused, 2 deterred, 1 observing, 0 persistent")));
	}

	private long countAudits(String action) {
		Long c = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM mitigation_audit_log WHERE action = ?", Long.class, action);
		return c != null ? c : 0L;
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
		insertSubnetRollupWithUaMismatch(subnetGroup, asn, asOrg, totalReqs, returningReqs, authReqs, 0L, bucketTime);
	}

	private void insertSubnetRollupWithUaMismatch(
			String subnetGroup,
			long asn,
			String asOrg,
			long totalReqs,
			long returningReqs,
			long authReqs,
			long uaMismatchReqs,
			Instant bucketTime
	) {
		jdbcTemplate.update("""
				INSERT INTO client_subnet_rollups (
				    bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
				    asn, as_org, country_code, client_type, total_requests, active_requests,
				    blocked_requests, marked_requests, distinct_clients, min_requests_per_client,
				    max_requests_per_client, returning_requests,
				    returning_tracked_requests, authenticated_requests, ua_mismatch_requests
				) VALUES (?, ?, 60, 'Srv01', 'PRIMARY', ?, ?, ?, 'US',
				          'HOSTING_PROVIDER', ?, ?, 0, 0, 25, 10, 150, ?, ?, ?, ?)
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
				authReqs,
				uaMismatchReqs
		);
	}

	@Test
	void testUaMismatchDiscountingEnablesCarpetMitigationAndRadarDetection() {
		Instant now = Instant.now();
		long testAsn = 65432L;

		// ASN 65432: 3 subnets, 2000 requests each = 6000 total requests.
		// Apparent returning requests: 700 per subnet (35.0%), which normally exceeds maxReturningRatioPct (5.0%).
		// BUT 680 of those 700 returning requests had User-Agent mismatches (forged/reused bot cookies).
		// Genuine returning: 700 - 680 = 20 per subnet (1.0%), which safely satisfies maxReturningRatioPct <= 5.0%!
		insertSubnetRollupWithUaMismatch("198.51.200.0/24", testAsn, "Reused Cookie Botnet", 2000, 700, 0, 680, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollupWithUaMismatch("198.51.201.0/24", testAsn, "Reused Cookie Botnet", 2000, 700, 0, 680, now.minus(Duration.ofMinutes(10)));
		insertSubnetRollupWithUaMismatch("198.51.202.0/24", testAsn, "Reused Cookie Botnet", 2000, 700, 0, 680, now.minus(Duration.ofMinutes(10)));

		AutoMitigationService.EffectiveAutoSettings config = autoMitigationService.getEffectiveSettings();

		// 1. Candidate Detection: ASN 65432 must be detected as candidate because discounted returningPct = 1.0% <= 5.0%
		List<AutoMitigationService.CarpetAttackCandidate> candidates = autoMitigationService.findCarpetAttackCandidates(config, 1);
		AutoMitigationService.CarpetAttackCandidate candidate = candidates.stream()
				.filter(c -> c.asn() == testAsn)
				.findFirst()
				.orElseThrow(() -> new AssertionError("ASN 65432 must be detected as candidate after discounting UA mismatches"));

		assertEquals(3, candidate.activeSubnets());
		assertEquals(6000L, candidate.totalRequests());
		assertEquals(2100L, candidate.returningRequests());
		assertEquals(1.0, candidate.returningRatioPct(), 0.05, "Returning ratio must discount 2,040 UA mismatches");
		assertEquals(3, candidate.eligibleSubnets().size());

		// 2. Carpet Radar: Must evaluate to QUALIFIED (not SUPPRESSED_RETURNING_RATIO!)
		List<org.henbru.antidos.collector.model.CarpetRadarEntry> radar = autoMitigationService.getCarpetRadar(1);
		org.henbru.antidos.collector.model.CarpetRadarEntry entry = radar.stream()
				.filter(e -> e.asn() == testAsn)
				.findFirst()
				.orElseThrow();

		assertEquals("QUALIFIED", entry.status());
		assertTrue(entry.isQualified());
		assertFalse(entry.isSuppressed());
		assertEquals(2040L, entry.uaMismatchRequests(), "Radar entry must expose total UA mismatch requests");
		assertEquals(1.0, entry.returningRatioPct(), 0.05);
	}
}
