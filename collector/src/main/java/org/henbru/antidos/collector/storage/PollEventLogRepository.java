package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.henbru.antidos.collector.model.PollEventLog;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for storing and querying the collector polling event audit log.
 */
@Repository
public class PollEventLogRepository {

	private final JdbcTemplate jdbcTemplate;

	public PollEventLogRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<PollEventLog> ROW_MAPPER = (rs, rowNum) -> new PollEventLog(
			rs.getLong("id"),
			rs.getString("server_id"),
			rs.getString("url"),
			rs.getTimestamp("poll_time").toInstant(),
			rs.getString("status"),
			rs.getInt("http_status_code"),
			rs.getLong("response_time_ms"),
			rs.getInt("valves_polled"),
			rs.getInt("slots_ingested"),
			rs.getInt("events_ingested"),
			rs.getString("details"),
			rs.getString("error_message")
	);

	public void insert(PollEventLog log) {
		String sql = """
				INSERT INTO poll_event_log (
				    server_id, url, poll_time, status, http_status_code,
				    response_time_ms, valves_polled, slots_ingested, events_ingested,
				    details, error_message
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				""";

		jdbcTemplate.update(
				sql,
				log.serverId(),
				log.url(),
				Timestamp.from(log.pollTime()),
				log.status(),
				log.httpStatusCode(),
				log.responseTimeMs(),
				log.valvesPolled(),
				log.slotsIngested(),
				log.eventsIngested(),
				log.details(),
				log.errorMessage()
		);
	}

	@SuppressWarnings("null")
	public List<PollEventLog> findRecent(Long beforeId, String statusFilter, String serverId, int limit) {
		StringBuilder sql = new StringBuilder("SELECT * FROM poll_event_log WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		if (beforeId != null && beforeId > 0) {
			sql.append("AND id < ? ");
			params.add(beforeId);
		}

		if (statusFilter != null && !statusFilter.isBlank()) {
			if ("ERROR".equalsIgnoreCase(statusFilter)) {
				sql.append("AND status = 'ERROR' ");
			} else if ("WARNING".equalsIgnoreCase(statusFilter) || "WARN".equalsIgnoreCase(statusFilter)) {
				sql.append("AND status IN ('WARNING', 'ERROR') ");
			}
		}

		if (serverId != null && !serverId.isBlank()) {
			sql.append("AND server_id = ? ");
			params.add(serverId.trim());
		}

		sql.append("ORDER BY id DESC LIMIT ?");
		params.add(Math.max(1, Math.min(limit, 200)));

		return jdbcTemplate.query(sql.toString(), ROW_MAPPER, params.toArray());
	}

	public int deleteOlderThan(Instant cutoff) {
		return jdbcTemplate.update(
				"DELETE FROM poll_event_log WHERE poll_time < ?",
				Timestamp.from(cutoff));
	}

	public long countByStatusSince(String status, Instant since) {
		Long count = jdbcTemplate.queryForObject(
				"SELECT COUNT(*) FROM poll_event_log WHERE status = ? AND poll_time >= ?",
				Long.class, status, Timestamp.from(since));
		return count != null ? count : 0L;
	}
}
