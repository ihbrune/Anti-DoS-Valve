package org.henbru.antidos.collector.system;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.poller.CollectorScheduler;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

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
}
