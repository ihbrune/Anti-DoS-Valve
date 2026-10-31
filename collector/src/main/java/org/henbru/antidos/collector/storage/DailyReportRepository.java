package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.model.DailyReport;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for storing and querying permanent daily operational reports.
 * Completely immune to retention cleanup jobs.
 */
@Repository
public class DailyReportRepository {

	private final JdbcTemplate jdbcTemplate;

	public DailyReportRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<DailyReport> ROW_MAPPER = (rs, rowNum) -> {
		long totalMarked = 0L;
		try {
			totalMarked = rs.getLong("total_marked");
		} catch (java.sql.SQLException ignored) {
		}
		double peakMarked = 0.0;
		try {
			peakMarked = rs.getDouble("peak_marked_per_sec");
		} catch (java.sql.SQLException ignored) {
		}
		return new DailyReport(
				rs.getLong("id"),
				rs.getString("report_date"),
				rs.getString("status"),
				rs.getLong("total_requests"),
				rs.getLong("total_blocked"),
				totalMarked,
				rs.getDouble("peak_requests_per_sec"),
				rs.getDouble("peak_blocked_per_sec"),
				peakMarked,
				rs.getString("peak_valve_name"),
				rs.getString("peak_server_id"),
				rs.getInt("server_count"),
				rs.getInt("incident_count"),
				rs.getString("report_markdown"),
				rs.getTimestamp("created_at").toInstant(),
				rs.getTimestamp("updated_at").toInstant()
		);
	};

	public void upsert(DailyReport report) {
		String sql = """
				INSERT INTO daily_reports (
				    report_date, status, total_requests, total_blocked, total_marked,
				    peak_requests_per_sec, peak_blocked_per_sec, peak_marked_per_sec, peak_valve_name, peak_server_id,
				    server_count, incident_count, report_markdown, created_at, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (report_date) DO UPDATE SET
				    status = EXCLUDED.status,
				    total_requests = EXCLUDED.total_requests,
				    total_blocked = EXCLUDED.total_blocked,
				    total_marked = EXCLUDED.total_marked,
				    peak_requests_per_sec = EXCLUDED.peak_requests_per_sec,
				    peak_blocked_per_sec = EXCLUDED.peak_blocked_per_sec,
				    peak_marked_per_sec = EXCLUDED.peak_marked_per_sec,
				    peak_valve_name = EXCLUDED.peak_valve_name,
				    peak_server_id = EXCLUDED.peak_server_id,
				    server_count = EXCLUDED.server_count,
				    incident_count = EXCLUDED.incident_count,
				    report_markdown = EXCLUDED.report_markdown,
				    updated_at = EXCLUDED.updated_at
				""";

		Instant now = Instant.now();
		Instant createdAt = report.createdAt() != null ? report.createdAt() : now;
		Instant updatedAt = report.updatedAt() != null ? report.updatedAt() : now;

		StorageRetryUtil.executeWithRetry("DailyReportRepository.upsert", () -> {
			jdbcTemplate.update(
					sql,
					report.reportDate(),
					report.status(),
					report.totalRequests(),
					report.totalBlocked(),
					report.totalMarked(),
					report.peakRequestsPerSec(),
					report.peakBlockedPerSec(),
					report.peakMarkedPerSec(),
					report.peakValveName(),
					report.peakServerId(),
					report.serverCount(),
					report.incidentCount(),
					report.reportMarkdown(),
					Timestamp.from(createdAt),
					Timestamp.from(updatedAt)
			);
		});
	}

	public Optional<DailyReport> findByReportDate(String reportDate) {
		if (reportDate == null || reportDate.isBlank()) {
			return Optional.empty();
		}
		List<DailyReport> reports = jdbcTemplate.query(
				"SELECT * FROM daily_reports WHERE report_date = ?",
				ROW_MAPPER, reportDate.trim()
		);
		return reports.isEmpty() ? Optional.empty() : Optional.of(reports.getFirst());
	}

	public Optional<DailyReport> findLatest() {
		List<DailyReport> reports = jdbcTemplate.query(
				"SELECT * FROM daily_reports ORDER BY report_date DESC LIMIT 1",
				ROW_MAPPER
		);
		return reports.isEmpty() ? Optional.empty() : Optional.of(reports.getFirst());
	}

	public List<DailyReport> findRecent(int limit) {
		int safeLimit = Math.max(1, Math.min(limit, 365));
		return jdbcTemplate.query(
				"SELECT * FROM daily_reports ORDER BY report_date DESC LIMIT ?",
				ROW_MAPPER, safeLimit
		);
	}

	public List<String> findAllReportDates() {
		return jdbcTemplate.query(
				"SELECT report_date FROM daily_reports ORDER BY report_date DESC",
				(rs, rowNum) -> rs.getString(1)
		);
	}

	public int count() {
		Integer cnt = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM daily_reports", Integer.class);
		return cnt != null ? cnt : 0;
	}

	public int deleteByReportDate(String reportDate) {
		if (reportDate == null || reportDate.isBlank()) {
			return 0;
		}
		return jdbcTemplate.update("DELETE FROM daily_reports WHERE report_date = ?", reportDate.trim());
	}
}
