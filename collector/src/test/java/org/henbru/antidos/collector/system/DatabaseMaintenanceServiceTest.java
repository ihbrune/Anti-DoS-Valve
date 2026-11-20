package org.henbru.antidos.collector.system;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.SubnetProfile;
import org.henbru.antidos.collector.poller.CollectorScheduler;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.MitigationRuleRepository;
import org.henbru.antidos.collector.storage.SubnetProfileRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class DatabaseMaintenanceServiceTest {

	@Autowired
	private DatabaseMaintenanceService databaseMaintenanceService;

	@Autowired
	private CollectorProperties properties;

	@Autowired
	private ClientEventRepository clientEventRepository;

	@Autowired
	private CollectorScheduler collectorScheduler;

	@Autowired
	private MitigationRuleRepository mitigationRuleRepository;

	@Autowired
	private SubnetProfileRepository subnetProfileRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Test
	void testSqliteDetectionAndFreelistDiagnostics() {
		assertTrue(databaseMaintenanceService.isSqlite(), "Test database should be detected as SQLite");

		DatabaseMaintenanceService.FreelistInfo info = databaseMaintenanceService.getFreelistInfo();
		assertNotNull(info);
		assertTrue(info.freelistPages() >= 0);
		assertTrue(info.pageSize() > 0);
		assertTrue(info.freeBytes() >= 0);
		assertNotNull(info.formattedBytes());
	}

	@Test
	void testVacuumExecution() {
		DatabaseMaintenanceService.VacuumResult result = databaseMaintenanceService.vacuum();
		assertNotNull(result);
		assertTrue(result.success(), "VACUUM should execute successfully on SQLite");
		assertTrue(result.durationMs() >= 0);
		assertTrue(result.message().contains("compacted successfully"));
	}

	@Test
	void testVacuumThresholdEvaluation() {
		// Freelist should not exceed 10 GB
		boolean vacuumTriggered = databaseMaintenanceService.vacuumIfFreelistExceeds(10L * 1024L * 1024L * 1024L);
		assertFalse(vacuumTriggered, "Should not trigger vacuum when freelist is far below threshold");

		// Threshold 0 bytes should trigger compaction
		boolean zeroTriggered = databaseMaintenanceService.vacuumIfFreelistExceeds(0L);
		assertTrue(zeroTriggered, "Should trigger vacuum when threshold is 0 bytes");
	}

	@Test
	void testDifferentialRetentionAndHourlyActiveCleanup() {
		Instant now = Instant.now();
		Instant twoDaysAgo = now.minus(48, ChronoUnit.HOURS);
		Instant fortyDaysAgo = now.minus(40, ChronoUnit.DAYS);

		ClientEvent oldActiveEvent = new ClientEvent(
				null, "test-server", "IP-Aggregator", 1000L, twoDaysAgo,
				"198.51.100.10", 4, 32, null, null, null, null, "198.51.100.0/24",
				15, 0, false, ClientEvent.STATUS_ACTIVE, true, now,
				null, null, null, null, null, null,
				1, 0, 0, null, null, null
		);

		ClientEvent oldBlockedEvent = new ClientEvent(
				null, "test-server", "IP-Aggregator", 1001L, twoDaysAgo,
				"198.51.100.11", 4, 32, null, null, null, null, "198.51.100.0/24",
				100, 10, true, ClientEvent.STATUS_BLOCKED, true, now,
				null, null, null, null, null, null,
				1, 0, 0, null, null, null
		);

		ClientEvent veryOldBlockedEvent = new ClientEvent(
				null, "test-server", "IP-Aggregator", 1002L, fortyDaysAgo,
				"198.51.100.12", 4, 32, null, null, null, null, "198.51.100.0/24",
				100, 10, true, ClientEvent.STATUS_BLOCKED, true, now,
				null, null, null, null, null, null,
				1, 0, 0, null, null, null
		);

		clientEventRepository.batchUpsert(List.of(oldActiveEvent, oldBlockedEvent, veryOldBlockedEvent));

		// Run hourly active cleanup: should prune oldActiveEvent (48h old > 24h retention), but KEEP oldBlockedEvent (48h old < 30d retention)
		int deletedActive = collectorScheduler.runHourlyActiveEventCleanup();
		assertTrue(deletedActive >= 1, "Hourly active cleanup should have pruned the 48h-old active event");

		// Run full daily retention cleanup: should prune veryOldBlockedEvent (> 30d) and evaluate vacuum
		CollectorScheduler.RetentionCleanupResult cleanupResult = collectorScheduler.runRetentionCleanup();
		assertNotNull(cleanupResult);
		assertTrue(cleanupResult.deletedEvents() >= 1, "Full retention should have pruned the 40d-old blocked event");
	}

	@Test
	void testMitigationAndProfileRetentionCleanup() {
		Instant now = Instant.now();
		Instant fortyDaysAgo = now.minus(40, ChronoUnit.DAYS);
		Instant tenDaysAgo = now.minus(10, ChronoUnit.DAYS);
		Instant twoDaysAgo = now.minus(2, ChronoUnit.DAYS);

		try {
			// 1. Old EXPIRED rule (40d ago -> must be deleted)
			mitigationRuleRepository.upsertRule(new MitigationRule(
					null, "198.51.100.0/24", 4, 24, "ALL",
					MitigationRule.STATUS_EXPIRED, MitigationRule.SOURCE_AUTO_CARPET, "OLD-BATCH", "Old expired rule",
					64496L, "Test AS", fortyDaysAgo, fortyDaysAgo, fortyDaysAgo.plusSeconds(3600),
					null, null, 0L, 0, null, MitigationRule.DETERRENCE_OBSERVING
			));

			// 2. Old REVOKED rule (40d ago -> must be deleted)
			mitigationRuleRepository.upsertRule(new MitigationRule(
					null, "203.0.113.0/24", 4, 24, "ALL",
					MitigationRule.STATUS_REVOKED, MitigationRule.SOURCE_MANUAL, "OLD-REVOKED", "Old revoked rule",
					64496L, "Test AS", fortyDaysAgo, fortyDaysAgo, fortyDaysAgo.plusSeconds(3600),
					fortyDaysAgo, "Admin revoked", 5L, 1, fortyDaysAgo, MitigationRule.DETERRENCE_DETERRED
			));

			// 3. Old ACTIVE rule updated 40d ago with future expires_at -> must NEVER be deleted
			mitigationRuleRepository.upsertRule(new MitigationRule(
					null, "192.0.2.0/24", 4, 24, "ALL",
					MitigationRule.STATUS_ACTIVE, MitigationRule.SOURCE_MANUAL, "STILL-ACTIVE", "Active permanent rule",
					64496L, "Test AS", fortyDaysAgo, fortyDaysAgo, now.plus(30, ChronoUnit.DAYS),
					null, null, 100L, 5, now, MitigationRule.DETERRENCE_PERSISTENT
			));

			// 4. Recent EXPIRED rule (2d ago -> must be retained)
			mitigationRuleRepository.upsertRule(new MitigationRule(
					null, "198.18.0.0/24", 4, 24, "ALL",
					MitigationRule.STATUS_EXPIRED, MitigationRule.SOURCE_AUTO_CARPET, "RECENT-BATCH", "Recent expired rule",
					64496L, "Test AS", twoDaysAgo, twoDaysAgo, twoDaysAgo.plusSeconds(3600),
					null, null, 0L, 0, null, MitigationRule.DETERRENCE_OBSERVING
			));

			// 5. Audit log entries: 1 old (40d -> delete), 1 recent (2d -> keep)
			mitigationRuleRepository.insertAuditEntry(new MitigationAuditEntry(
					null, null, "198.51.100.0/24", "OLD-RET-AUDIT", "AUTO_BLOCK", "AUTO_ENGINE",
					3600, "Old retention test audit", fortyDaysAgo
			));
			mitigationRuleRepository.insertAuditEntry(new MitigationAuditEntry(
					null, null, "198.18.0.0/24", "NEW-RET-AUDIT", "AUTO_BLOCK", "AUTO_ENGINE",
					3600, "Recent retention test audit", twoDaysAgo
			));

			// 6. Subnet profiles: low-activity 10d old (delete), high-volume 10d old (keep), 2d old (keep)
			subnetProfileRepository.batchUpsert(List.of(
					new SubnetProfile("198.51.10.0/24", tenDaysAgo.minusSeconds(3600), tenDaysAgo, 0,
							2L, 2L, 0L, 0L, 0.2, 1, 2L, 0L, 0, 0, 0L, 0L, 0.0,
							64496L, "Low Vol AS", "DE", ClientType.UNKNOWN, tenDaysAgo, 0L, 0L, 0L, 0L),
					new SubnetProfile("198.51.20.0/24", tenDaysAgo.minusSeconds(3600), tenDaysAgo, 0,
							500L, 500L, 0L, 0L, 50.0, 5, 500L, 0L, 0, 0, 0L, 0L, 0.0,
							64496L, "High Vol AS", "DE", ClientType.DATACENTER, tenDaysAgo, 0L, 0L, 0L, 0L),
					new SubnetProfile("198.51.30.0/24", twoDaysAgo.minusSeconds(3600), twoDaysAgo, 0,
							1L, 1L, 0L, 0L, 0.1, 1, 1L, 0L, 0, 0, 0L, 0L, 0.0,
							64496L, "Recent Low AS", "DE", ClientType.UNKNOWN, twoDaysAgo, 0L, 0L, 0L, 0L)
			));

			CollectorScheduler.RetentionCleanupResult result = collectorScheduler.runRetentionCleanup();
			assertNotNull(result);
			assertTrue(result.deletedMitigationRules() >= 2, "Expected old EXPIRED and REVOKED rules to be pruned");
			assertTrue(result.deletedMitigationAudits() >= 1, "Expected old audit entry to be pruned");
			assertTrue(result.deletedProfiles() >= 1, "Expected 10d-old low-activity subnet profile to be pruned");

			assertTrue(mitigationRuleRepository.findByCidrAndScope("198.51.100.0/24", "ALL").isEmpty());
			assertTrue(mitigationRuleRepository.findByCidrAndScope("203.0.113.0/24", "ALL").isEmpty());
			assertTrue(mitigationRuleRepository.findByCidrAndScope("192.0.2.0/24", "ALL").isPresent(), "ACTIVE rule must survive");
			assertTrue(mitigationRuleRepository.findByCidrAndScope("198.18.0.0/24", "ALL").isPresent(), "Recent EXPIRED rule must survive");

			assertEquals(0L, jdbcTemplate.queryForObject(
					"SELECT COUNT(*) FROM mitigation_audit_log WHERE batch_id = 'OLD-RET-AUDIT'", Long.class));
			assertEquals(1L, jdbcTemplate.queryForObject(
					"SELECT COUNT(*) FROM mitigation_audit_log WHERE batch_id = 'NEW-RET-AUDIT'", Long.class));

			assertTrue(subnetProfileRepository.findBySubnetGroup("198.51.10.0/24").isEmpty());
			assertTrue(subnetProfileRepository.findBySubnetGroup("198.51.20.0/24").isPresent());
			assertTrue(subnetProfileRepository.findBySubnetGroup("198.51.30.0/24").isPresent());
		} finally {
			jdbcTemplate.update("DELETE FROM mitigation_audit_log WHERE batch_id IN ('OLD-RET-AUDIT', 'NEW-RET-AUDIT')");
			jdbcTemplate.update("DELETE FROM mitigation_rules WHERE cidr IN ('198.51.100.0/24', '203.0.113.0/24', '192.0.2.0/24', '198.18.0.0/24')");
			jdbcTemplate.update("DELETE FROM subnet_profiles WHERE subnet_group IN ('198.51.10.0/24', '198.51.20.0/24', '198.51.30.0/24')");
		}
	}
}
