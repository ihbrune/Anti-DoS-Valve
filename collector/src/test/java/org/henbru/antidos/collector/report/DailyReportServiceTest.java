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
}
