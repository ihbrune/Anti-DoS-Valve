package org.henbru.antidos.collector.report;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import org.henbru.antidos.collector.model.DailyReport;
import org.henbru.antidos.collector.model.DailyReportNote;
import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.model.PollEventLog;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.storage.DailyReportRepository;
import org.henbru.antidos.collector.storage.MitigationRuleRepository;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.henbru.antidos.collector.storage.PollEventLogRepository;
import org.henbru.antidos.collector.storage.SlotSnapshotRepository;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest
class DailyReportServiceTest {

	@Autowired
	private DailyReportService dailyReportService;

	@Autowired
	private DailyReportRepository dailyReportRepository;

	@Autowired
	private SlotSnapshotRepository slotSnapshotRepository;

	@Autowired
	private MonitoredValveRepository monitoredValveRepository;

	@Autowired
	private PollEventLogRepository pollEventLogRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired(required = false)
	private MitigationRuleRepository mitigationRuleRepository;

	private final LocalDate testDate = LocalDate.of(2026, 10, 20);

	@BeforeEach
	void setUp() {
		dailyReportRepository.deleteByReportDate(testDate.toString());
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id IN ('SRV-FAST', 'SRV-SLOW')");
		jdbcTemplate.update("DELETE FROM poll_event_log WHERE server_id IN ('SRV-FAST', 'SRV-SLOW')");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id IN ('SRV-FAST', 'SRV-SLOW')");
	}

	@Test
	void testPeakRateNormalizationAcrossDifferentSlotLengths() {
		ZonedDateTime startDay = testDate.atStartOfDay(ZoneId.systemDefault());
		Instant slotTime1 = startDay.plusHours(10).toInstant();
		Instant slotTime2 = startDay.plusHours(12).toInstant();

		// Configure Valve A (SRV-FAST / FAST-VALVE) with 5-second slots, allowed = 250
		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-FAST", "FAST-VALVE", "High-frequency API protection", 1, "BLOCKING", false, false,
				429, 250, 5, 12, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv", Instant.now(), 1234, true
		));

		// Configure Valve B (SRV-SLOW / SLOW-VALVE) with 60-second slots, allowed = 2000
		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-SLOW", "SLOW-VALVE", "Standard page throttle", 1, "BLOCKING", false, false,
				429, 2000, 60, 5, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv", Instant.now(), 5678, true
		));

		// Snapshot 1: FAST-VALVE records 500 requests in a 5s slot => 100.0 req/s
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-FAST", "FAST-VALVE", 1001L, slotTime1, slotTime1.plus(5, ChronoUnit.SECONDS),
				500L, 50, 10, true, slotTime1.plus(5, ChronoUnit.SECONDS)
		));

		// Snapshot 2: SLOW-VALVE records 1,200 requests in a 60s slot => 20.0 req/s
		// Raw request count is more than double (1200 vs 500), but normalized rate is 5x lower!
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-SLOW", "SLOW-VALVE", 2001L, slotTime2, slotTime2.plus(60, ChronoUnit.SECONDS),
				1200L, 120, 2, true, slotTime2.plus(60, ChronoUnit.SECONDS)
		));

		// Polling logs for the day
		pollEventLogRepository.insert(new PollEventLog(
				null, "SRV-FAST", "http://fast/status", slotTime1, "SUCCESS", 200, 15L, 1, 1, 0, 0, "OK", null
		));
		pollEventLogRepository.insert(new PollEventLog(
				null, "SRV-SLOW", "http://slow/status", slotTime2, "SUCCESS", 200, 65L, 1, 1, 0, 0, "OK", null
		));

		// Generate Daily Report
		DailyReport report = dailyReportService.generateDailyReport(testDate);

		assertNotNull(report);
		assertEquals(testDate.toString(), report.reportDate());
		assertEquals(1700L, report.totalRequests());
		assertEquals(12L, report.totalBlocked());

		// Verify normalization: The peak rate MUST be 100.0 req/s from FAST-VALVE, NOT from SLOW-VALVE!
		assertEquals(100.0, report.peakRequestsPerSec(), 0.01, "FAST-VALVE (500 req / 5s = 100 req/s) must win over SLOW-VALVE (1200 req / 60s = 20 req/s)");
		assertEquals("FAST-VALVE", report.peakValveName());
		assertEquals("SRV-FAST", report.peakServerId());

		// Peak blocked rate: 10 blocks / 5s = 2.0 blocks/s
		assertEquals(2.0, report.peakBlockedPerSec(), 0.01);

		// Verify Markdown contains key elements
		String md = report.reportMarkdown();
		assertNotNull(md);
		assertTrue(md.contains("FAST-VALVE"));
		assertTrue(md.contains("SLOW-VALVE"));
		assertTrue(md.contains("100.0 req/s"));
		assertTrue(md.contains("5s slot on `SRV-FAST`"));
		assertTrue(md.contains("1,700"));

		// Verify report was persisted to DB
		Optional<DailyReport> fromDb = dailyReportRepository.findByReportDate(testDate.toString());
		assertTrue(fromDb.isPresent());
		assertEquals(1700L, fromDb.get().totalRequests());

		// Test HTML rendering
		String html = dailyReportService.renderToHtml(md);
		assertNotNull(html);
		assertTrue(html.contains("<table>"));
		assertTrue(html.contains("SRV-FAST"));
	}

	@Test
	void testEmptyDayGeneratesValidReport() {
		LocalDate emptyDate = LocalDate.of(2026, 1, 1);
		dailyReportRepository.deleteByReportDate(emptyDate.toString());

		DailyReport report = dailyReportService.generateDailyReport(emptyDate);
		assertNotNull(report);
		assertEquals(emptyDate.toString(), report.reportDate());
		assertEquals(0L, report.totalRequests());
		assertEquals(0L, report.totalBlocked());
		assertEquals("NORMAL", report.status());
		assertNotNull(report.reportMarkdown());
	}

	@Test
	void testBlockedRequestsAndSlotRatioReporting() {
		LocalDate ratioDate = LocalDate.of(2026, 10, 21);
		dailyReportRepository.deleteByReportDate(ratioDate.toString());
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id = 'SRV-RATIO'");
		jdbcTemplate.update("DELETE FROM client_events WHERE server_id = 'SRV-RATIO'");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id = 'SRV-RATIO'");

		ZonedDateTime startDay = ratioDate.atStartOfDay(ZoneId.systemDefault());
		Instant baseTime = startDay.plusHours(8).toInstant();

		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-RATIO", "RATIO-VALVE", "Test Ratio Valve", 1, "BLOCKING", false, false,
				429, 500, 10, 10, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv", Instant.now(), 9999, true
		));

		// 1 slot with blocked counters
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-RATIO", "RATIO-VALVE", 5001L, baseTime, baseTime.plus(10, ChronoUnit.SECONDS),
				100L, 20, 5, true, baseTime.plus(10, ChronoUnit.SECONDS)
		));

		// 3 clean slots without blocks
		for (int i = 1; i <= 3; i++) {
			Instant t = baseTime.plus(i * 10, ChronoUnit.SECONDS);
			slotSnapshotRepository.upsert(new SlotSnapshot(
					null, "SRV-RATIO", "RATIO-VALVE", 5001L + i, t, t.plus(10, ChronoUnit.SECONDS),
					100L, 10, 0, true, t.plus(10, ChronoUnit.SECONDS)
			));
		}

		// Insert actual blocked client event with 85 blocked requests
		jdbcTemplate.update("""
				INSERT INTO client_events (
					server_id, valve_name, slot_key, slot_time, client_key, request_count, status, client_type, enrichment_status, last_updated_at
				) VALUES (?, ?, ?, ?, ?, ?, 'BLOCKED', 'DATACENTER', 'ENRICHED', ?)
				""", "SRV-RATIO", "RATIO-VALVE", 5001L, java.sql.Timestamp.from(baseTime), "203.0.113.42", 85L, java.sql.Timestamp.from(baseTime));

		DailyReport report = dailyReportService.generateDailyReport(ratioDate);
		assertNotNull(report);
		assertEquals(400L, report.totalRequests());
		assertEquals(85L, report.totalBlocked(), "Total blocked must come from client_events request_count sum");

		String md = report.reportMarkdown();
		assertNotNull(md);

		// Check Executive Summary contains slot ratio and blocked requests
		assertTrue(md.contains("Affected Incident Slots"), "Markdown should have Affected Incident Slots");
		assertTrue(md.contains("1 of 4 (25.00%)"), "Should show 1 of 4 (25.00%)");
		assertTrue(md.contains("85"), "Should show 85 blocked requests");

		// Check Section 2 Table contains new columns
		assertTrue(md.contains("Blocked Requests"), "Table header should have Blocked Requests");
		assertTrue(md.contains("Affected Slots (Ratio)"), "Table header should have Affected Slots (Ratio)");
		assertTrue(md.contains("1 / 4 (25.00%)"), "Table row should show 1 / 4 (25.00%)");
		assertTrue(md.contains("21.25%"), "Block quote for 85 / 400 should be 21.25%");
	}

	@Test
	void testDailyReportNotesLifecycleAndPreservation() {
		LocalDate noteDate = LocalDate.of(2026, 10, 22);
		dailyReportRepository.deleteByReportDate(noteDate.toString());
		dailyReportService.deleteNote(noteDate.toString());

		// 1. Save note before report exists (e.g. today or in advance)
		dailyReportService.saveNote(noteDate.toString(), "Special note: Planned database migration between 01:00 and 02:00.");

		Optional<DailyReportNote> noteBeforeReport = dailyReportService.getNote(noteDate.toString());
		assertTrue(noteBeforeReport.isPresent());
		assertTrue(noteBeforeReport.get().noteMarkdown().contains("Planned database migration"));
		assertTrue(dailyReportService.getDatesWithNotes().contains(noteDate.toString()));

		// 2. Generate report for that date
		DailyReport report = dailyReportService.generateDailyReport(noteDate);
		assertNotNull(report);
		assertTrue(report.reportMarkdown().contains("Operator Notes & Highlights"));
		assertTrue(report.reportMarkdown().contains("Planned database migration"));

		// 3. Update note after report exists - should immediately sync into existing report
		dailyReportService.saveNote(noteDate.toString(), "Updated note: Migration succeeded without downtime. Minor spike at 01:30.");
		Optional<DailyReport> reloadedReport = dailyReportRepository.findByReportDate(noteDate.toString());
		assertTrue(reloadedReport.isPresent());
		assertTrue(reloadedReport.get().reportMarkdown().contains("Migration succeeded without downtime"));
		assertFalse(reloadedReport.get().reportMarkdown().contains("Planned database migration"));

		// 4. Re-aggregate report - note must NOT be lost!
		DailyReport reaggregated = dailyReportService.generateDailyReport(noteDate);
		assertTrue(reaggregated.reportMarkdown().contains("Migration succeeded without downtime"));

		// 5. Delete note - should remove from notes repository and sync report markdown
		dailyReportService.deleteNote(noteDate.toString());
		assertTrue(dailyReportService.getNote(noteDate.toString()).isEmpty());
		Optional<DailyReport> reportAfterDelete = dailyReportRepository.findByReportDate(noteDate.toString());
		assertTrue(reportAfterDelete.isPresent());
		assertFalse(reportAfterDelete.get().reportMarkdown().contains("Migration succeeded without downtime"));
	}

	@Test
	void testMarkingValveDoesNotTriggerAttackStatusAndReportsMarkedMetrics() {
		LocalDate markDate = LocalDate.of(2026, 10, 23);
		dailyReportRepository.deleteByReportDate(markDate.toString());
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id = 'SRV-MARK'");
		jdbcTemplate.update("DELETE FROM client_events WHERE server_id = 'SRV-MARK'");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id = 'SRV-MARK'");

		ZonedDateTime startDay = markDate.atStartOfDay(ZoneId.systemDefault());
		Instant baseTime = startDay.plusHours(14).toInstant();

		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-MARK", "GEGEN MAILSAMMLER", "Email obfuscation marker", 1, "MARKING", false, false,
				429, 15, 60, 5, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				true, "_adv", Instant.now(), 7777, true
		));

		// Slot with 30 marked counters and 0 blocked counters in 60s => 0.5 marks/s
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-MARK", "GEGEN MAILSAMMLER", 8001L, baseTime, baseTime.plus(60, ChronoUnit.SECONDS),
				1000L, 40, 0, 30, true, baseTime.plus(60, ChronoUnit.SECONDS)
		));

		// Insert 15 marked client events (300 total marked requests)
		for (int i = 1; i <= 15; i++) {
			jdbcTemplate.update("""
					INSERT INTO client_events (
						server_id, valve_name, slot_key, slot_time, client_key, request_count, status, client_type, enrichment_status, last_updated_at
					) VALUES (?, ?, ?, ?, ?, ?, 'MARKED', 'SEARCH_ENGINE', 'ENRICHED', ?)
					""", "SRV-MARK", "GEGEN MAILSAMMLER", 8001L, java.sql.Timestamp.from(baseTime),
					"66.249.66." + i, 20L, java.sql.Timestamp.from(baseTime));
		}

		DailyReport report = dailyReportService.generateDailyReport(markDate);
		assertNotNull(report);
		assertEquals("NORMAL", report.status(), "Soft-marking events must NOT trigger ATTACK_MITIGATED status");
		assertEquals(1000L, report.totalRequests());
		assertEquals(0L, report.totalBlocked());
		assertEquals(300L, report.totalMarked());
		assertEquals(0.0, report.peakBlockedPerSec(), 0.01);
		assertEquals(0.5, report.peakMarkedPerSec(), 0.01);

		String md = report.reportMarkdown();
		assertTrue(md.contains("Marked / Simulated Requests"));
		assertTrue(md.contains("30.00%"));
		assertTrue(md.contains("Top Marked / Monitored Clients (Soft-Marking & Simulation)"));
		assertTrue(md.contains("`MARKING`"));
	}

	@Test
	void testDailyReportWithAuthenticatedTraffic() {
		LocalDate authDate = LocalDate.of(2026, 10, 24);
		dailyReportRepository.deleteByReportDate(authDate.toString());
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id IN ('SRV-AUTH-APP', 'SRV-PUBLIC-API')");
		jdbcTemplate.update("DELETE FROM client_events WHERE server_id IN ('SRV-AUTH-APP', 'SRV-PUBLIC-API')");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id IN ('SRV-AUTH-APP', 'SRV-PUBLIC-API')");

		ZonedDateTime startDay = authDate.atStartOfDay(ZoneId.systemDefault());
		Instant baseTime = startDay.plusHours(10).toInstant();

		// Configure SRV-AUTH-APP with auth tracking enabled
		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-AUTH-APP", "Web-App-Limiter", "Protected Application", 1, "BLOCKING", false, false,
				429, 200, 10, 10, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv",
				true, "COOKIE", "AUTH_COOKIE", "^/trust$", 900, 50000,
				Instant.now(), 9999, true
		));

		// Configure SRV-PUBLIC-API without auth tracking
		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-PUBLIC-API", "Public-Api-Limiter", "Public API Gateway", 1, "BLOCKING", false, false,
				429, 100, 10, 10, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv",
				false, "OFF", null, null, 900, 50000,
				Instant.now(), 9999, true
		));

		// Snapshots
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-AUTH-APP", "Web-App-Limiter", 9001L, baseTime, baseTime.plus(60, ChronoUnit.SECONDS),
				1000L, 50, 0, 0, true, baseTime.plus(60, ChronoUnit.SECONDS)
		));
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-PUBLIC-API", "Public-Api-Limiter", 9002L, baseTime, baseTime.plus(60, ChronoUnit.SECONDS),
				500L, 25, 0, 0, true, baseTime.plus(60, ChronoUnit.SECONDS)
		));

		// Client events on SRV-AUTH-APP with 750 of 1000 requests authenticated
		jdbcTemplate.update("""
				INSERT INTO client_events (
					server_id, valve_name, slot_key, slot_time, client_key, request_count, returning_count, authenticated_count, status, client_type, enrichment_status, last_updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 'RESIDENTIAL', 'ENRICHED', ?)
				""", "SRV-AUTH-APP", "Web-App-Limiter", 9001L, java.sql.Timestamp.from(baseTime),
				"198.51.100.10", 1000L, 800, 750, java.sql.Timestamp.from(baseTime));

		// Client events on SRV-PUBLIC-API without auth tracking (nulls)
		jdbcTemplate.update("""
				INSERT INTO client_events (
					server_id, valve_name, slot_key, slot_time, client_key, request_count, returning_count, authenticated_count, status, client_type, enrichment_status, last_updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 'RESIDENTIAL', 'ENRICHED', ?)
				""", "SRV-PUBLIC-API", "Public-Api-Limiter", 9002L, java.sql.Timestamp.from(baseTime),
				"198.51.100.20", 500L, null, null, java.sql.Timestamp.from(baseTime));

		DailyReport report = dailyReportService.generateDailyReport(authDate);
		assertNotNull(report);
		assertEquals(1500L, report.totalRequests());

		String md = report.reportMarkdown();
		assertNotNull(md);

		// 1. Executive Summary checks
		assertTrue(md.contains("Authenticated Requests"));
		assertTrue(md.contains("750 of 1,000 (75.00%)"));

		// 2. Server Traffic & Authentication Distribution table checks
		assertTrue(md.contains("Fleet Server Traffic & Authentication Distribution"));
		assertTrue(md.contains("`SRV-AUTH-APP`"));
		assertTrue(md.contains("`SRV-PUBLIC-API`"));
		assertTrue(md.contains("66.67%")); // SRV-AUTH-APP share: 1000 / 1500
		assertTrue(md.contains("33.33%")); // SRV-PUBLIC-API share: 500 / 1500
		assertTrue(md.contains("750 of 1,000"));

		// 3. Per-valve table checks
		assertTrue(md.contains("Auth Requests (Ratio)"));
		assertTrue(md.contains("750 (75.0%)"));
	}

	@Test
	void testHasRawTelemetry() {
		LocalDate dateWithData = LocalDate.of(2026, 10, 15);
		LocalDate dateWithoutData = LocalDate.of(2026, 10, 16);
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id = 'SRV-TELEM-TEST'");

		assertFalse(dailyReportService.hasRawTelemetry(dateWithData));
		assertFalse(dailyReportService.hasRawTelemetry(dateWithoutData));

		ZonedDateTime startDay = dateWithData.atStartOfDay(ZoneId.systemDefault());
		Instant slotTime = startDay.plusHours(12).toInstant();
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-TELEM-TEST", "DEFAULT", 12345L, slotTime, slotTime.plus(60, ChronoUnit.SECONDS),
				100L, 10, 0, 0, true, slotTime.plus(60, ChronoUnit.SECONDS)
		));

		assertTrue(dailyReportService.hasRawTelemetry(dateWithData));
		assertTrue(dailyReportService.hasRawTelemetry(dateWithData.toString()));
		assertFalse(dailyReportService.hasRawTelemetry(dateWithoutData));
	}

	@Test
	void testReaggregationRefusedWhenRawTelemetryPruned() {
		LocalDate archiveDate = LocalDate.of(2026, 10, 17);
		dailyReportRepository.deleteByReportDate(archiveDate.toString());
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id = 'SRV-PRUNE-TEST'");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id = 'SRV-PRUNE-TEST'");

		ZonedDateTime startDay = archiveDate.atStartOfDay(ZoneId.systemDefault());
		Instant slotTime = startDay.plusHours(9).toInstant();

		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-PRUNE-TEST", "PROTECTED-APP", "App Valve", 1, "BLOCKING", false, false,
				429, 500, 60, 5, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv", Instant.now(), 5555, true
		));

		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-PRUNE-TEST", "PROTECTED-APP", 77777L, slotTime, slotTime.plus(60, ChronoUnit.SECONDS),
				3500L, 50, 5, 0, true, slotTime.plus(60, ChronoUnit.SECONDS)
		));

		// 1. Initial report generation while raw slots exist
		DailyReport originalReport = dailyReportService.generateDailyReport(archiveDate);
		assertNotNull(originalReport);
		assertEquals(3500L, originalReport.totalRequests());

		// 2. Simulate raw telemetry eviction / data retention cleanup
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id = 'SRV-PRUNE-TEST'");
		assertFalse(dailyReportService.hasRawTelemetry(archiveDate));

		// 3. Re-aggregation attempt MUST throw IllegalStateException to protect archived data
		IllegalStateException ex = assertThrows(IllegalStateException.class, () ->
				dailyReportService.generateDailyReport(archiveDate)
		);
		assertTrue(ex.getMessage().contains("Raw slot telemetry has been pruned by retention policy"));
		assertTrue(ex.getMessage().contains("The existing archived report (3,500 requests) was preserved"));

		// 4. Verify original report in DB is completely intact with original 3,500 requests
		Optional<DailyReport> preservedReport = dailyReportRepository.findByReportDate(archiveDate.toString());
		assertTrue(preservedReport.isPresent());
		assertEquals(3500L, preservedReport.get().totalRequests());
		assertEquals(1, preservedReport.get().serverCount());
	}

	@Test
	void testHourlyTrafficDistributionAndVisualProfile() {
		LocalDate hourlyDate = LocalDate.of(2026, 10, 27);
		dailyReportRepository.deleteByReportDate(hourlyDate.toString());
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id = 'SRV-HOURLY'");
		jdbcTemplate.update("DELETE FROM client_events WHERE server_id = 'SRV-HOURLY'");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id = 'SRV-HOURLY'");

		ZonedDateTime startDay = hourlyDate.atStartOfDay(ZoneId.systemDefault());
		Instant h10 = startDay.plusHours(10).toInstant();
		Instant h14 = startDay.plusHours(14).toInstant();

		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-HOURLY", "HOURLY-VALVE", "Hourly Test Valve", 1, "BLOCKING", false, false,
				429, 1000, 60, 5, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv", Instant.now(), 1111, true
		));

		// Hour 10: Moderate traffic (2,000 requests, 0 blocked, 0 marked)
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-HOURLY", "HOURLY-VALVE", 10001L, h10, h10.plus(60, ChronoUnit.SECONDS),
				2000L, 50, 0, 0, true, h10.plus(60, ChronoUnit.SECONDS)
		));

		// Hour 14: Peak traffic (10,000 requests, 200 blocked, 50 marked)
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-HOURLY", "HOURLY-VALVE", 14001L, h14, h14.plus(60, ChronoUnit.SECONDS),
				10000L, 100, 20, 5, true, h14.plus(60, ChronoUnit.SECONDS)
		));

		// Ingest client events for hour 14
		jdbcTemplate.update("""
				INSERT INTO client_events (
					server_id, valve_name, slot_key, slot_time, client_key, request_count, status, client_type, enrichment_status, last_updated_at
				) VALUES (?, ?, ?, ?, ?, ?, 'BLOCKED', 'DATACENTER', 'ENRICHED', ?)
				""", "SRV-HOURLY", "HOURLY-VALVE", 14001L, java.sql.Timestamp.from(h14), "198.51.100.42", 200L, java.sql.Timestamp.from(h14));

		jdbcTemplate.update("""
				INSERT INTO client_events (
					server_id, valve_name, slot_key, slot_time, client_key, request_count, status, client_type, enrichment_status, last_updated_at
				) VALUES (?, ?, ?, ?, ?, ?, 'MARKED', 'SEARCH_ENGINE', 'ENRICHED', ?)
				""", "SRV-HOURLY", "HOURLY-VALVE", 14001L, java.sql.Timestamp.from(h14), "66.249.66.1", 50L, java.sql.Timestamp.from(h14));

		DailyReport report = dailyReportService.generateDailyReport(hourlyDate);
		assertNotNull(report);
		assertEquals(12000L, report.totalRequests());
		assertEquals(200L, report.totalBlocked());
		assertEquals(50L, report.totalMarked());

		String md = report.reportMarkdown();
		assertNotNull(md);

		// Check Section 3 Hourly Traffic & Threat Distribution
		assertTrue(md.contains("## 🕒 3. Hourly Traffic & Threat Distribution"));
		assertTrue(md.contains("Hourly Activity Profile"));
		assertTrue(md.contains("14:00 – 14:59"));
		assertTrue(md.contains("10,000"));
		assertTrue(md.contains("200 (2.00%)"));
		assertTrue(md.contains("50 (0.50%)"));

		// Peak hour (14:00) should have full bar
		assertTrue(md.contains("`████████████████`"), "Peak hour must have full block bar");

		// Hour 10 should have roughly 20% (3-4 blocks)
		assertTrue(md.contains("10:00 – 10:59"));
		assertTrue(md.contains("2,000"));
		assertTrue(md.contains("`███░░░░░░░░░░░░░`"), "Hour 10 must have proportional block bar");
	}

	@Test
	void testTopTrafficAsnsVolumeAnalysis() {
		LocalDate asnDate = LocalDate.of(2026, 10, 29);
		dailyReportRepository.deleteByReportDate(asnDate.toString());
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id = 'SRV-ASN-TEST'");
		jdbcTemplate.update("DELETE FROM client_events WHERE server_id = 'SRV-ASN-TEST'");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id = 'SRV-ASN-TEST'");

		ZonedDateTime startDay = asnDate.atStartOfDay(ZoneId.systemDefault());
		Instant slotTime = startDay.plusHours(11).toInstant();

		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-ASN-TEST", "DEFAULT", "Default Valve", 1, "BLOCKING", false, false,
				429, 1000, 60, 5, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv", Instant.now(), 2222, true
		));

		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-ASN-TEST", "DEFAULT", 99001L, slotTime, slotTime.plus(60, ChronoUnit.SECONDS),
				15000L, 50, 10, 0, true, slotTime.plus(60, ChronoUnit.SECONDS)
		));

		// 1. Google (AS15169): 8,000 requests, completely staying under the threshold (0 blocked!)
		jdbcTemplate.update("""
				INSERT INTO client_events (
					server_id, valve_name, slot_key, slot_time, client_key, request_count, status, client_type, asn, as_org, country_code, enrichment_status, last_updated_at
				) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 'SEARCH_ENGINE', 15169, 'Google LLC', 'US', 'ENRICHED', ?)
				""", "SRV-ASN-TEST", "DEFAULT", 99001L, java.sql.Timestamp.from(slotTime), "66.249.64.1", 8000L, java.sql.Timestamp.from(slotTime));

		// 2. Cloudflare (AS13335): 4,000 requests, 150 blocked
		jdbcTemplate.update("""
				INSERT INTO client_events (
					server_id, valve_name, slot_key, slot_time, client_key, request_count, status, client_type, asn, as_org, country_code, enrichment_status, last_updated_at
				) VALUES (?, ?, ?, ?, ?, ?, 'BLOCKED', 'DATACENTER', 13335, 'Cloudflare, Inc.', 'US', 'ENRICHED', ?)
				""", "SRV-ASN-TEST", "DEFAULT", 99001L, java.sql.Timestamp.from(slotTime), "172.64.0.1", 150L, java.sql.Timestamp.from(slotTime));

		DailyReport report = dailyReportService.generateDailyReport(asnDate);
		assertNotNull(report);

		String md = report.reportMarkdown();
		assertNotNull(md);

		// Top Autonomous Systems by Traffic Volume must be present
		assertTrue(md.contains("Top Autonomous Systems by Traffic Volume (Fleet Traffic Share)"));
		assertTrue(md.contains("AS15169"));
		assertTrue(md.contains("Google LLC"));
		assertTrue(md.contains("8,000"));
		assertTrue(md.contains("0 (0.00%)"), "Google should show 0 blocked requests (under threshold)");

		assertTrue(md.contains("AS13335"));
		assertTrue(md.contains("Cloudflare, Inc."));
		assertTrue(md.contains("150 (100.00%)"));
	}

	@Test
	void testValveCapacityAuditNominalAndSaturated() {
		LocalDate capDate = LocalDate.of(2026, 10, 30);
		dailyReportRepository.deleteByReportDate(capDate.toString());
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id = 'SRV-CAP-TEST'");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id = 'SRV-CAP-TEST'");

		ZonedDateTime startDay = capDate.atStartOfDay(ZoneId.systemDefault());
		Instant slotTime = startDay.plusHours(8).toInstant();

		// Configure valve with max_ip_cache_size = 500
		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-CAP-TEST", "CAP-VALVE", "Cap Test Valve", 1, "BLOCKING", false, false,
				429, 100, 60, 5, 0.5f, 32, 64, 500, 200, "", "", "", "", "/status", "*", "auto",
				false, "_adv", Instant.now(), 3333, true
		));

		// 1. Nominal case: active_counters = 150 < 500
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-CAP-TEST", "CAP-VALVE", 88001L, slotTime, slotTime.plus(60, ChronoUnit.SECONDS),
				1000L, 150, 0, 0, true, slotTime.plus(60, ChronoUnit.SECONDS)
		));

		DailyReport reportNominal = dailyReportService.generateDailyReport(capDate);
		assertNotNull(reportNominal);
		String mdNominal = reportNominal.reportMarkdown();
		assertTrue(mdNominal.contains("0 Saturated Slots (Nominal)"));
		assertTrue(mdNominal.contains("Nominal Memory Operations (0 Dropped Counters)"));

		// 2. Saturated case: active_counters = 550 >= 500
		dailyReportRepository.deleteByReportDate(capDate.toString());
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-CAP-TEST", "CAP-VALVE", 88002L, slotTime.plus(60, ChronoUnit.SECONDS), slotTime.plus(120, ChronoUnit.SECONDS),
				2000L, 550, 10, 0, true, slotTime.plus(120, ChronoUnit.SECONDS)
		));

		DailyReport reportSaturated = dailyReportService.generateDailyReport(capDate);
		assertNotNull(reportSaturated);
		String mdSaturated = reportSaturated.reportMarkdown();
		assertTrue(mdSaturated.contains("Saturated Slots"));
		assertTrue(mdSaturated.contains("Counter Cache Capacity Warning"));
		assertTrue(mdSaturated.contains("CAP-VALVE"));
		assertTrue(mdSaturated.contains("550 / 500"));
		assertTrue(mdSaturated.contains("Increase `maxCountersPerSlot` in server.xml"));
	}

	@Test
	void testFingerprintAnomaliesAndBaselineSurgeRadar() {
		LocalDate anomDate = LocalDate.of(2026, 10, 31);
		dailyReportRepository.deleteByReportDate(anomDate.toString());
		jdbcTemplate.update("DELETE FROM client_subnet_rollups WHERE server_id = 'SRV-ANOM-TEST'");
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id = 'SRV-ANOM-TEST'");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id = 'SRV-ANOM-TEST'");

		ZonedDateTime startDay = anomDate.atStartOfDay(ZoneId.systemDefault());
		Instant h10 = startDay.plusHours(10).toInstant();
		Instant prior5Days = startDay.minusDays(5).toInstant();

		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-ANOM-TEST", "PRIMARY", "Primary Valve", 1, "BLOCKING", false, false,
				429, 200, 60, 5, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv", Instant.now(), 4444, true
		));

		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-ANOM-TEST", "PRIMARY", 77001L, h10, h10.plus(60, ChronoUnit.SECONDS),
				25000L, 100, 50, 0, true, h10.plus(60, ChronoUnit.SECONDS)
		));

		// 1. UA Rotation / Spoofing rollup (1 client, 25 UAs)
		jdbcTemplate.update("""
				INSERT INTO client_subnet_rollups (
					bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
					total_requests, active_requests, blocked_requests, distinct_clients, distinct_user_agents,
					asn, as_org, country_code, client_type, created_at
				) VALUES (?, ?, 60, 'SRV-ANOM-TEST', 'PRIMARY', '198.51.100.0/24',
					5000, 4800, 200, 1, 25, 64496, 'Scraper Hosting AS', 'US', 'DATACENTER', ?)
				""", java.sql.Timestamp.from(h10), java.sql.Timestamp.from(h10.plus(1, ChronoUnit.HOURS)), java.sql.Timestamp.from(h10));

		// 2. Prior rollup for Baseline Surge: 500 requests over 5 days (~100 req/day)
		jdbcTemplate.update("""
				INSERT INTO client_subnet_rollups (
					bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
					total_requests, active_requests, blocked_requests, distinct_clients, distinct_user_agents,
					asn, as_org, country_code, client_type, created_at
				) VALUES (?, ?, 60, 'SRV-ANOM-TEST', 'PRIMARY', '203.0.113.0/24',
					500, 500, 0, 5, 2, 64497, 'Surging Partner AS', 'DE', 'RESIDENTIAL', ?)
				""", java.sql.Timestamp.from(prior5Days), java.sql.Timestamp.from(prior5Days.plus(1, ChronoUnit.HOURS)), java.sql.Timestamp.from(prior5Days));

		// 3. Current day rollup for Baseline Surge: 2,500 requests today (25x surge!)
		jdbcTemplate.update("""
				INSERT INTO client_subnet_rollups (
					bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
					total_requests, active_requests, blocked_requests, distinct_clients, distinct_user_agents,
					asn, as_org, country_code, client_type, created_at
				) VALUES (?, ?, 60, 'SRV-ANOM-TEST', 'PRIMARY', '203.0.113.0/24',
					2500, 2400, 100, 20, 5, 64497, 'Surging Partner AS', 'DE', 'RESIDENTIAL', ?)
				""", java.sql.Timestamp.from(h10), java.sql.Timestamp.from(h10.plus(1, ChronoUnit.HOURS)), java.sql.Timestamp.from(h10));

		DailyReport report = dailyReportService.generateDailyReport(anomDate);
		assertNotNull(report);
		String md = report.reportMarkdown();
		assertNotNull(md);

		// Verify Fingerprint Anomalies Section
		assertTrue(md.contains("Scraping & Behavioral Fingerprint Anomalies"));
		assertTrue(md.contains("198.51.100.0/24"));
		assertTrue(md.contains("UA Rotation / Spoofing"));
		assertTrue(md.contains("Scraper Hosting AS"));

		// Verify Baseline Surge Radar Section
		assertTrue(md.contains("Baseline Surge Radar"));
		assertTrue(md.contains("203.0.113.0/24"));
		assertTrue(md.contains("Surging Partner AS"));
		assertTrue(md.contains("2,500"));
	}

	@Test
	void testDailyReportWithDynamicMitigationsAndDryRun() {
		LocalDate mitDate = LocalDate.of(2026, 11, 2);
		dailyReportRepository.deleteByReportDate(mitDate.toString());
		ZonedDateTime startDay = mitDate.atStartOfDay(ZoneId.systemDefault());
		Instant startInstant = startDay.toInstant();
		Instant endInstant = startDay.plusDays(1).toInstant();
		jdbcTemplate.update("DELETE FROM mitigation_rules WHERE cidr LIKE '198.51.%' OR (created_at >= ? AND created_at < ?)", java.sql.Timestamp.from(startInstant), java.sql.Timestamp.from(endInstant));
		jdbcTemplate.update("DELETE FROM mitigation_audit_log WHERE created_at >= ? AND created_at < ?", java.sql.Timestamp.from(startInstant), java.sql.Timestamp.from(endInstant));
		jdbcTemplate.update("DELETE FROM client_subnet_rollups WHERE server_id = 'SRV-MIT-TEST'");
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id = 'SRV-MIT-TEST'");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id = 'SRV-MIT-TEST'");

		Instant h10 = startDay.plusHours(10).toInstant();
		Instant h11 = startDay.plusHours(11).toInstant();

		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-MIT-TEST", "PRIMARY", "Primary Mit Valve", 1, "BLOCKING", false, false,
				429, 200, 60, 5, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv",
				false, "NONE", "", "", 3600, 1000,
				"ALL", 0,
				true, "http://srv-mit/antidos-mitigation", 2, 850L, 1L,
				Instant.now(), 4444, true
		));

		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-MIT-TEST", "PRIMARY", 88001L, h10, h10.plus(60, ChronoUnit.SECONDS),
				30000L, 200, 50, 0, true, h10.plus(60, ChronoUnit.SECONDS)
		));

		// 1. Dynamic Rule 1: Active, Deterred
		mitigationRuleRepository.upsertRule(new MitigationRule(
				null, "198.51.100.0/24", 4, 24, "ALL", MitigationRule.STATUS_ACTIVE,
				"AUTO", "batch-101", "Carpet attack from ASN 64496", 64496L, "BadBot Cloud LLC",
				h10, h10, h10.plus(2, ChronoUnit.HOURS), null, null,
				650L, 30, h10.plus(15, ChronoUnit.MINUTES), MitigationRule.DETERRENCE_DETERRED
		));

		// 2. Audit Entry 1: AUTO_BLOCK
		mitigationRuleRepository.insertAuditEntry(new MitigationAuditEntry(
				null, null, "198.51.100.0/24", "batch-101", "AUTO_BLOCK",
				"AUTO_ENGINE", 7200, "Autonomous rule created for carpet attack", h10
		));

		// 3. Audit Entry 2: Dry-Run Simulation (AUTO_WOULD_BLOCK) - should be ignored in report
		mitigationRuleRepository.insertAuditEntry(new MitigationAuditEntry(
				null, null, "ALL", "sim-batch-202", "AUTO_WOULD_BLOCK",
				"AUTO_MITIGATION", 1800,
				"[DRY-RUN SIMULATION] Would block 1 subnets ([203.0.113.0/24]). Carpet attack from ASN 64497 (HostProvider Corp): 1 subnets, 1,200 reqs, returning ratio 88%",
				h11
		));

		// 4. Audit Entry 3: Routine FLEET_SYNC - should be filtered out from timeline
		mitigationRuleRepository.insertAuditEntry(new MitigationAuditEntry(
				null, null, "FLEET", null, "FLEET_SYNC",
				"AUTO_POLLER", 0, "Fleet rule sync", h11.plus(5, ChronoUnit.MINUTES)
		));

		// 5. Audit Entry 4: AUTO_SKIPPED_PROTECTED_ASN - should be filtered out from timeline
		mitigationRuleRepository.insertAuditEntry(new MitigationAuditEntry(
				null, null, "ASN-8075", null, "AUTO_SKIPPED_PROTECTED_ASN",
				"AUTO_ENGINE", 0, "Skipped Microsoft Azure", h11.plus(10, ChronoUnit.MINUTES)
		));

		// 6. Audit Entries 5-7: Clustered EXTEND entries by AUTO_ENGINE within 2 minutes
		Instant h12 = h11.plus(30, ChronoUnit.MINUTES);
		mitigationRuleRepository.insertAuditEntry(new MitigationAuditEntry(
				null, 1L, "198.51.100.0/24", "batch-101", "EXTEND",
				"AUTO_ENGINE", 3600, "Rule extended by +60m", h12
		));
		mitigationRuleRepository.insertAuditEntry(new MitigationAuditEntry(
				null, 2L, "198.51.101.0/24", "batch-101", "EXTEND",
				"AUTO_ENGINE", 3600, "Rule extended by +60m", h12.plus(10, ChronoUnit.SECONDS)
		));
		mitigationRuleRepository.insertAuditEntry(new MitigationAuditEntry(
				null, 3L, "198.51.102.0/24", "batch-101", "EXTEND",
				"AUTO_ENGINE", 3600, "Rule extended by +60m", h12.plus(20, ChronoUnit.SECONDS)
		));

		DailyReport report = dailyReportService.generateDailyReport(mitDate);
		assertNotNull(report);
		assertEquals("ATTACK_MITIGATED", report.status());

		String md = report.reportMarkdown();
		assertNotNull(md);

		// Section 1 Executive Summary should reflect dynamic mitigations
		assertTrue(md.contains("Dynamic CIDR Deflections") || md.contains("Dynamic Rules Enforced"));
		assertTrue(md.contains("650"));

		// Section 6 Dedicated Mitigation & Autonomous Defense Audit
		assertTrue(md.contains("## 🛡️ 6. Dynamic Mitigation & Autonomous Defense Audit"));
		assertTrue(md.contains("198.51.100.0/24"));
		assertTrue(md.contains("BadBot Cloud LLC"));
		assertTrue(md.contains("DETERRED"));

		// Dry-Run Simulation should be completely ignored in Daily Report
		assertFalse(md.contains("Dry-Run Simulation Impact Analysis"));
		assertFalse(md.contains("AUTO_WOULD_BLOCK"));

		// Routine sync and skipped ASN should be excluded from Timeline
		assertTrue(md.contains("AUTO_BLOCK"));
		assertFalse(md.contains("FLEET_SYNC"));
		assertFalse(md.contains("AUTO_SKIPPED_PROTECTED_ASN"));

		// Clustered EXTEND should be summarized as batch in Timeline
		assertTrue(md.contains("EXTEND (Batch)"));
		assertTrue(md.contains("3 subnets"));
	}

	@Test
	void testDynamicMitigationDailyReportReflectsActiveEngineAndManualBreakdown() {
		LocalDate testDate = LocalDate.parse("2026-11-05");
		dailyReportRepository.deleteByReportDate(testDate.toString());
		Instant start = testDate.atStartOfDay(ZoneId.systemDefault()).toInstant();
		Instant end = start.plus(24, ChronoUnit.HOURS);
		Instant h10 = start.plus(10, ChronoUnit.HOURS);

		jdbcTemplate.update("DELETE FROM mitigation_rules WHERE created_at >= ? AND created_at < ?", java.sql.Timestamp.from(start), java.sql.Timestamp.from(end));

		// Slot snapshot so telemetry exists
		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-AUTO-TEST", "PRIMARY", 99001L, h10, h10.plus(60, ChronoUnit.SECONDS),
				5000L, 50, 20, 0, true, h10.plus(60, ChronoUnit.SECONDS)
		));

		// Set auto mitigation setting using official key
		jdbcTemplate.update("INSERT OR REPLACE INTO system_settings (setting_key, setting_value, description, updated_by) VALUES ('mitigation.auto.enabled', 'true', 'test', 'TEST')");

		// Insert 1 Single Manual, 2 ASN-Batch, and 5 Auto rules using unique ranges
		Instant exp = h10.plus(1, ChronoUnit.HOURS);
		mitigationRuleRepository.upsertRule(new MitigationRule(
				null, "198.51.200.1/32", 4, 32, "ALL", "ACTIVE", "MANUAL", null, "Single manual test block",
				64496L, "TestOrg", h10, h10, exp, null, null, 10L, 1, h10, "OBSERVING"
		));

		mitigationRuleRepository.upsertRule(new MitigationRule(
				null, "198.51.200.0/24", 4, 24, "ALL", "ACTIVE", "ASN_BATCH", "ASN-64496-1", "ASN batch test block 1",
				64496L, "TestOrg", h10, h10, exp, null, null, 20L, 2, h10, "OBSERVING"
		));

		mitigationRuleRepository.upsertRule(new MitigationRule(
				null, "198.51.201.0/24", 4, 24, "ALL", "ACTIVE", "ASN_BATCH", "ASN-64496-1", "ASN batch test block 2",
				64496L, "TestOrg", h10, h10, exp, null, null, 30L, 3, h10, "OBSERVING"
		));

		for (int i = 1; i <= 5; i++) {
			mitigationRuleRepository.upsertRule(new MitigationRule(
					null, "203.0.114." + i + "/32", 4, 32, "ALL", "ACTIVE", "AUTO_CARPET", "AUTO-64496", "Auto test block",
					64496L, "TestOrg", h10, h10, exp, null, null, 50L, 5, h10, "PERSISTENT"
			));
		}

		DailyReport report = dailyReportService.generateDailyReport(testDate);
		assertNotNull(report);
		String md = report.reportMarkdown();
		assertNotNull(md);

		// Verify manual breakdown: 3 Manual [1 Single, 2 ASN-Batch], 5 Auto -> Total 8 created today
		assertTrue(md.contains("8 created today (3 Manual [1 Single, 2 ASN-Batch], 5 Auto)"),
				"Executive summary should show complete breakdown and exact sum: " + md);
		assertTrue(md.contains("ACTIVE (LIVE DEFENSE — 5 Auto-Blocks)"),
				"Executive summary should show ACTIVE defense mode: " + md);
		assertTrue(md.contains("🟢 ACTIVE (LIVE DEFENSE)"),
				"Section 6 should show green ACTIVE status: " + md);
		assertTrue(md.contains("8 rules** (3 Manual [1 Single, 2 ASN-Batch], 5 Auto)"),
				"Section 6 should show matching manual breakdown: " + md);
	}

	@Test
	void testClusterOutagesEmptyAndNull() {
		assertTrue(DailyReportService.clusterOutages(null).isEmpty());
		assertTrue(DailyReportService.clusterOutages(List.of()).isEmpty());
	}

	@Test
	void testClusterOutagesGroupsConsecutivePollsWithinThreshold() {
		Instant base = Instant.parse("2026-10-20T03:15:00Z");
		List<DailyReportService.OutageLog> logs = List.of(
				new DailyReportService.OutageLog("SRV-01", base, 0, 15, "Connection refused: connect"),
				new DailyReportService.OutageLog("SRV-01", base.plusSeconds(15), 0, 12, "Connection refused: connect"),
				new DailyReportService.OutageLog("SRV-01", base.plusSeconds(30), 0, 10, "Connection refused: connect"),
				new DailyReportService.OutageLog("SRV-01", base.plusSeconds(45), 0, 14, "Connection refused: connect"),
				new DailyReportService.OutageLog("SRV-01", base.plusSeconds(60), 0, 11, "Connection refused: connect")
		);

		List<DailyReportService.OutageIncident> incidents = DailyReportService.clusterOutages(logs, 120);
		assertEquals(1, incidents.size());
		DailyReportService.OutageIncident incident = incidents.get(0);
		assertEquals("SRV-01", incident.serverId());
		assertEquals(base, incident.startTime());
		assertEquals(base.plusSeconds(60), incident.endTime());
		assertEquals(5, incident.failedPollsCount());
		assertEquals("1m 00s", incident.formatDuration());
		assertEquals(0, incident.httpStatusCode());
		assertEquals("Connection refused: connect", incident.primaryErrorMessage());
		assertTrue(incident.formatTimeWindow(ZoneId.of("UTC")).contains("03:15:00 – 03:16:00"));
	}

	@Test
	void testClusterOutagesSeparateDisjointWindows() {
		Instant base = Instant.parse("2026-10-20T03:15:00Z");
		Instant afternoon = Instant.parse("2026-10-20T14:00:00Z");
		List<DailyReportService.OutageLog> logs = List.of(
				new DailyReportService.OutageLog("SRV-01", base, 0, 15, "Connection refused: connect"),
				new DailyReportService.OutageLog("SRV-01", base.plusSeconds(30), 0, 10, "Connection refused: connect"),
				new DailyReportService.OutageLog("SRV-01", afternoon, 504, 5000, "Gateway Timeout")
		);

		List<DailyReportService.OutageIncident> incidents = DailyReportService.clusterOutages(logs, 120);
		assertEquals(2, incidents.size());

		DailyReportService.OutageIncident inc1 = incidents.get(0);
		assertEquals("SRV-01", inc1.serverId());
		assertEquals(base, inc1.startTime());
		assertEquals(base.plusSeconds(30), inc1.endTime());
		assertEquals(2, inc1.failedPollsCount());
		assertEquals("30s", inc1.formatDuration());
		assertEquals("Connection refused: connect", inc1.primaryErrorMessage());

		DailyReportService.OutageIncident inc2 = incidents.get(1);
		assertEquals("SRV-01", inc2.serverId());
		assertEquals(afternoon, inc2.startTime());
		assertEquals(afternoon, inc2.endTime());
		assertEquals(1, inc2.failedPollsCount());
		assertEquals("< 15s", inc2.formatDuration());
		assertEquals(504, inc2.httpStatusCode());
		assertEquals("Gateway Timeout", inc2.primaryErrorMessage());
		assertTrue(inc2.formatTimeWindow(ZoneId.of("UTC")).contains("*(single poll)*"));
	}

	@Test
	void testClusterOutagesMultipleServersAndFrequencyResolution() {
		Instant t1 = Instant.parse("2026-10-20T03:00:00Z");
		List<DailyReportService.OutageLog> logs = List.of(
				// SRV-B at 03:01
				new DailyReportService.OutageLog("SRV-B", t1.plusSeconds(60), 503, 200, "Service Unavailable"),
				new DailyReportService.OutageLog("SRV-B", t1.plusSeconds(80), 503, 190, "Service Unavailable"),
				// SRV-A at 03:00
				new DailyReportService.OutageLog("SRV-A", t1, 0, 15, "Connection refused"),
				new DailyReportService.OutageLog("SRV-A", t1.plusSeconds(10), 0, 12, "Connection refused"),
				new DailyReportService.OutageLog("SRV-A", t1.plusSeconds(20), 0, 14, "Socket timeout")
		);

		List<DailyReportService.OutageIncident> incidents = DailyReportService.clusterOutages(logs, 120);
		assertEquals(2, incidents.size());

		// Chronological ordering: SRV-A starts at 03:00:00, SRV-B starts at 03:01:00
		assertEquals("SRV-A", incidents.get(0).serverId());
		assertEquals(3, incidents.get(0).failedPollsCount());
		assertEquals("Connection refused", incidents.get(0).primaryErrorMessage());

		assertEquals("SRV-B", incidents.get(1).serverId());
		assertEquals(2, incidents.get(1).failedPollsCount());
		assertEquals(503, incidents.get(1).httpStatusCode());
		assertEquals("Service Unavailable", incidents.get(1).primaryErrorMessage());
	}

	@Test
	void testDailyReportRendersClusteredOutageWindowsAndPerNodeAudit() {
		LocalDate reportDate = LocalDate.parse("2026-10-25");
		dailyReportRepository.deleteByReportDate(reportDate.toString());
		jdbcTemplate.update("DELETE FROM slot_snapshots WHERE server_id IN ('SRV-CLUSTER-A', 'SRV-CLUSTER-B')");
		jdbcTemplate.update("DELETE FROM poll_event_log WHERE server_id IN ('SRV-CLUSTER-A', 'SRV-CLUSTER-B')");
		jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id IN ('SRV-CLUSTER-A', 'SRV-CLUSTER-B')");

		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-CLUSTER-A", "VALVE-A", "Node A", 1, "BLOCKING", false, false,
				429, 500, 10, 6, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv", Instant.now(), 1111, true
		));
		monitoredValveRepository.upsert(new MonitoredValve(
				"SRV-CLUSTER-B", "VALVE-B", "Node B", 1, "BLOCKING", false, false,
				429, 500, 10, 6, 0.5f, 24, 64, 10000, 5000, "", "", "", "", "/status", "*", "auto",
				false, "_adv", Instant.now(), 2222, true
		));

		Instant dayStart = reportDate.atStartOfDay(ZoneId.systemDefault()).toInstant();
		Instant tReboot = dayStart.plus(3, ChronoUnit.HOURS).plus(15, ChronoUnit.MINUTES);
		Instant tSingle = dayStart.plus(11, ChronoUnit.HOURS).plus(30, ChronoUnit.MINUTES);

		slotSnapshotRepository.upsert(new SlotSnapshot(
				null, "SRV-CLUSTER-A", "VALVE-A", 101L, dayStart.plus(1, ChronoUnit.HOURS), dayStart.plus(1, ChronoUnit.HOURS).plus(10, ChronoUnit.SECONDS),
				1000L, 0, 0, true, dayStart.plus(1, ChronoUnit.HOURS).plus(10, ChronoUnit.SECONDS)
		));

		for (int i = 0; i < 10; i++) {
			pollEventLogRepository.insert(new PollEventLog(
					null, "SRV-CLUSTER-A", "http://cluster-a/status", tReboot.plusSeconds(i * 15),
					"ERROR", 0, 15L, 1, 0, 0, 0, 0, null, "Connection refused: connect"
			));
		}
		for (int i = 0; i < 50; i++) {
			pollEventLogRepository.insert(new PollEventLog(
					null, "SRV-CLUSTER-A", "http://cluster-a/status", dayStart.plus(4, ChronoUnit.HOURS).plusSeconds(i * 60),
					"SUCCESS", 200, 25L, 1, 1, 0, 0, 0, "OK", null
			));
		}

		pollEventLogRepository.insert(new PollEventLog(
				null, "SRV-CLUSTER-B", "http://cluster-b/status", tSingle,
				"ERROR", 504, 5000L, 1, 0, 0, 0, 0, null, "Gateway Timeout"
		));
		for (int i = 0; i < 50; i++) {
			pollEventLogRepository.insert(new PollEventLog(
					null, "SRV-CLUSTER-B", "http://cluster-b/status", dayStart.plus(4, ChronoUnit.HOURS).plusSeconds(i * 60),
					"SUCCESS", 200, 20L, 1, 1, 0, 0, 0, "OK", null
			));
		}

		DailyReport report = dailyReportService.generateDailyReport(reportDate);
		assertNotNull(report);
		String md = report.reportMarkdown();
		assertNotNull(md);

		// Verify Section 4 contains Per-Node Connectivity & Availability Audit
		assertTrue(md.contains("### 🖥️ Per-Node Connectivity & Availability Audit"),
				"Report should contain Per-Node Connectivity & Availability Audit table");
		assertTrue(md.contains("`SRV-CLUSTER-A`"), "Table should list SRV-CLUSTER-A");
		assertTrue(md.contains("`SRV-CLUSTER-B`"), "Table should list SRV-CLUSTER-B");
		assertTrue(md.contains("1 incident"), "Table should indicate 1 incident for nodes with outages");

		// Verify Section 4 contains Clustered Outage Windows table
		assertTrue(md.contains("### ⚠️ Connection Failures & Outage Windows"),
				"Report should contain Connection Failures & Outage Windows table");
		assertTrue(md.contains("2m 15s"), "SRV-CLUSTER-A reboot should be clustered into a 2m 15s duration window");
		assertTrue(md.contains("Connection refused: connect"), "SRV-CLUSTER-A should show primary error");
		assertTrue(md.contains("Gateway Timeout"), "SRV-CLUSTER-B should show Gateway Timeout");
		assertTrue(md.contains("*(single poll)*"), "SRV-CLUSTER-B single blip should be marked as single poll");
		assertTrue(md.contains("< 15s"), "SRV-CLUSTER-B duration should be < 15s");
	}
}
