package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.henbru.antidos.collector.model.SlotSnapshot;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for storing and querying slot telemetry snapshots.
 */
@Repository
public class SlotSnapshotRepository {

	private final JdbcTemplate jdbcTemplate;

	public SlotSnapshotRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<SlotSnapshot> ROW_MAPPER = (rs, rowNum) -> new SlotSnapshot(
			rs.getLong("id"),
			rs.getString("server_id"),
			rs.getString("valve_name"),
			rs.getLong("slot_key"),
			rs.getTimestamp("start_time").toInstant(),
			rs.getTimestamp("end_time").toInstant(),
			rs.getLong("total_requests"),
			rs.getInt("active_counters"),
			rs.getInt("blocked_counters"),
			rs.getBoolean("is_completed"),
			rs.getTimestamp("last_polled_at").toInstant()
	);

	public void upsert(SlotSnapshot s) {
		String sql = """
				INSERT INTO slot_snapshots (server_id, valve_name, slot_key, start_time, end_time, total_requests, active_counters, blocked_counters, is_completed, last_polled_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (server_id, valve_name, slot_key) DO UPDATE SET
				    start_time = EXCLUDED.start_time,
				    end_time = EXCLUDED.end_time,
				    total_requests = EXCLUDED.total_requests,
				    active_counters = EXCLUDED.active_counters,
				    blocked_counters = EXCLUDED.blocked_counters,
				    is_completed = EXCLUDED.is_completed,
				    last_polled_at = EXCLUDED.last_polled_at
				""";

		jdbcTemplate.update(sql,
				s.serverId(),
				s.valveName(),
				s.slotKey(),
				Timestamp.from(s.startTime()),
				Timestamp.from(s.endTime()),
				s.totalRequests(),
				s.activeCounters(),
				s.blockedCounters(),
				s.completed(),
				Timestamp.from(s.lastPolledAt())
		);
	}

	public Optional<Long> findLatestSlotKey(String serverId, String valveName) {
		List<Long> keys = jdbcTemplate.query(
				"SELECT MAX(slot_key) FROM slot_snapshots WHERE server_id = ? AND valve_name = ?",
				(rs, rowNum) -> rs.getLong(1), serverId, valveName);
		if (keys.isEmpty() || keys.getFirst() == 0) {
			return Optional.empty();
		}
		return Optional.of(keys.getFirst());
	}

	public List<SlotSnapshot> findRecent(String serverId, String valveName, int limit) {
		return jdbcTemplate.query(
				"SELECT * FROM slot_snapshots WHERE server_id = ? AND valve_name = ? ORDER BY slot_key DESC LIMIT ?",
				ROW_MAPPER, serverId, valveName, limit);
	}

	public List<SlotSnapshot> findRecentFleet(int limit) {
		return jdbcTemplate.query(
				"SELECT * FROM slot_snapshots ORDER BY start_time DESC LIMIT ?",
				ROW_MAPPER, limit);
	}

	public long sumRequestsSince(Instant since) {
		Long sum = jdbcTemplate.queryForObject(
				"SELECT COALESCE(SUM(total_requests), 0) FROM slot_snapshots WHERE start_time >= ?",
				Long.class, Timestamp.from(since));
		return sum != null ? sum : 0L;
	}

	public long sumBlockedRequestsSince(Instant since) {
		Long sum = jdbcTemplate.queryForObject(
				"SELECT COALESCE(SUM(blocked_counters), 0) FROM slot_snapshots WHERE start_time >= ?",
				Long.class, Timestamp.from(since));
		return sum != null ? sum : 0L;
	}

	public int countDistinctValves() {
		Integer count = jdbcTemplate.queryForObject(
				"SELECT COUNT(DISTINCT server_id || '#' || valve_name) FROM slot_snapshots",
				Integer.class);
		return count != null ? count : 0;
	}

	public int deleteOlderThan(Instant cutoff) {
		return jdbcTemplate.update(
				"DELETE FROM slot_snapshots WHERE start_time < ?",
				Timestamp.from(cutoff));
	}
}
