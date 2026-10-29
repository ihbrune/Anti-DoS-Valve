package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.henbru.antidos.collector.model.DailyReportNote;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for storing and querying operator notes and highlights per date.
 * Completely immune to retention cleanup jobs and report re-aggregations.
 */
@Repository
public class DailyReportNoteRepository {

	private final JdbcTemplate jdbcTemplate;

	public DailyReportNoteRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<DailyReportNote> ROW_MAPPER = (rs, rowNum) -> new DailyReportNote(
			rs.getLong("id"),
			rs.getString("report_date"),
			rs.getString("note_markdown"),
			rs.getTimestamp("created_at").toInstant(),
			rs.getTimestamp("updated_at").toInstant()
	);

	public void upsert(String reportDate, String noteMarkdown) {
		if (reportDate == null || reportDate.isBlank()) {
			throw new IllegalArgumentException("reportDate must not be blank");
		}
		String cleanNote = noteMarkdown != null ? noteMarkdown.trim() : "";
		Instant now = Instant.now();

		String sql = """
				INSERT INTO daily_report_notes (report_date, note_markdown, created_at, updated_at)
				VALUES (?, ?, ?, ?)
				ON CONFLICT (report_date) DO UPDATE SET
				    note_markdown = EXCLUDED.note_markdown,
				    updated_at = EXCLUDED.updated_at
				""";

		StorageRetryUtil.executeWithRetry("DailyReportNoteRepository.upsert", () -> {
			jdbcTemplate.update(sql, reportDate.trim(), cleanNote, Timestamp.from(now), Timestamp.from(now));
		});
	}

	public Optional<DailyReportNote> findByReportDate(String reportDate) {
		if (reportDate == null || reportDate.isBlank()) {
			return Optional.empty();
		}
		List<DailyReportNote> notes = jdbcTemplate.query(
				"SELECT * FROM daily_report_notes WHERE report_date = ?",
				ROW_MAPPER, reportDate.trim()
		);
		return notes.isEmpty() ? Optional.empty() : Optional.of(notes.getFirst());
	}

	public void deleteByReportDate(String reportDate) {
		if (reportDate == null || reportDate.isBlank()) {
			return;
		}
		StorageRetryUtil.executeWithRetry("DailyReportNoteRepository.delete", () -> {
			jdbcTemplate.update("DELETE FROM daily_report_notes WHERE report_date = ?", reportDate.trim());
		});
	}

	public List<String> findDatesWithNotes() {
		return jdbcTemplate.query(
				"SELECT report_date FROM daily_report_notes WHERE LENGTH(TRIM(note_markdown)) > 0 ORDER BY report_date DESC",
				(rs, rowNum) -> rs.getString(1)
		);
	}

	public Map<String, DailyReportNote> findAllAsMap() {
		List<DailyReportNote> list = jdbcTemplate.query("SELECT * FROM daily_report_notes", ROW_MAPPER);
		return list.stream().collect(Collectors.toMap(DailyReportNote::reportDate, n -> n, (a, b) -> a));
	}
}

