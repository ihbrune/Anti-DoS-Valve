package org.henbru.antidos.collector.report;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import org.henbru.antidos.collector.model.DailyReport;
import org.henbru.antidos.collector.model.DailyReportNote;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.model.PollEventLog;
import org.henbru.antidos.collector.model.SlotSnapshot;
import org.henbru.antidos.collector.storage.DailyReportRepository;
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
}
