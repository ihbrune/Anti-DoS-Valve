package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import org.henbru.antidos.collector.model.BlockedClientEvent;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for storing individual blocked IP/subnet client events and running analytics.
 */
@Repository
public class ClientEventRepository {

	private final JdbcTemplate jdbcTemplate;

	public ClientEventRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<BlockedClientEvent> ROW_MAPPER = (rs, rowNum) -> new BlockedClientEvent(
			rs.getLong("id"),
			rs.getString("server_id"),
			rs.getString("valve_name"),
			rs.getLong("slot_key"),
			rs.getTimestamp("slot_time").toInstant(),
			rs.getString("client_key"),
			rs.getInt("request_count"),
			rs.getInt("retained_count"),
			rs.getBoolean("is_locked"),
			rs.getBoolean("is_completed"),
			rs.getTimestamp("last_updated_at").toInstant()
	);

	public void batchUpsert(List<BlockedClientEvent> events) {
		if (events == null || events.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO blocked_client_events (server_id, valve_name, slot_key, slot_time, client_key, request_count, retained_count, is_locked, is_completed, last_updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (server_id, valve_name, slot_key, client_key) DO UPDATE SET
				    slot_time = EXCLUDED.slot_time,
				    request_count = EXCLUDED.request_count,
				    retained_count = EXCLUDED.retained_count,
				    is_locked = EXCLUDED.is_locked,
				    is_completed = EXCLUDED.is_completed,
				    last_updated_at = EXCLUDED.last_updated_at
				""";

		jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
			@Override
			public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
				BlockedClientEvent e = events.get(i);
				ps.setString(1, e.serverId());
				ps.setString(2, e.valveName());
				ps.setLong(3, e.slotKey());
				ps.setTimestamp(4, Timestamp.from(e.slotTime()));
				ps.setString(5, e.clientKey());
				ps.setInt(6, e.requestCount());
				ps.setInt(7, e.retainedCount());
				ps.setBoolean(8, e.locked());
				ps.setBoolean(9, e.completed());
				ps.setTimestamp(10, Timestamp.from(e.lastUpdatedAt()));
			}

			@Override
			public int getBatchSize() {
				return events.size();
			}
		});
	}

	public List<TopOffenderSummary> findTopOffenders(Instant since, int limit) {
		String sql = """
				SELECT
				    client_key,
				    COUNT(*) AS total_incidents,
				    SUM(request_count + retained_count) AS total_requests,
				    COUNT(DISTINCT server_id) AS distinct_servers,
				    MIN(slot_time) AS first_seen,
				    MAX(slot_time) AS last_seen
				FROM blocked_client_events
				WHERE slot_time >= ?
				GROUP BY client_key
				ORDER BY total_requests DESC
				LIMIT ?
				""";

		return jdbcTemplate.query(sql, (rs, rowNum) -> new TopOffenderSummary(
				rs.getString("client_key"),
				rs.getLong("total_incidents"),
				rs.getLong("total_requests"),
				rs.getInt("distinct_servers"),
				"", // server list can be empty or populated via group_concat if needed
				rs.getTimestamp("first_seen").toInstant(),
				rs.getTimestamp("last_seen").toInstant()
		), Timestamp.from(since), limit);
	}

	@SuppressWarnings("null")
	public List<BlockedClientEvent> findRecentEvents(String serverId, String filterIp, int limit) {
		StringBuilder sql = new StringBuilder("SELECT * FROM blocked_client_events WHERE 1=1 ");
		if (serverId != null && !serverId.trim().isEmpty()) {
			sql.append("AND server_id = '").append(serverId.replace("'", "''")).append("' ");
		}
		if (filterIp != null && !filterIp.trim().isEmpty()) {
			sql.append("AND client_key LIKE '%").append(filterIp.replace("'", "''")).append("%' ");
		}
		sql.append("ORDER BY slot_time DESC LIMIT ").append(Math.min(limit, 500));

		return jdbcTemplate.query(sql.toString(), ROW_MAPPER);
	}

	public long countDistinctBlockedClientsSince(Instant since) {
		Long count = jdbcTemplate.queryForObject(
				"SELECT COUNT(DISTINCT client_key) FROM blocked_client_events WHERE slot_time >= ?",
				Long.class, Timestamp.from(since));
		return count != null ? count : 0L;
	}

	public int deleteOlderThan(Instant cutoff) {
		return jdbcTemplate.update(
				"DELETE FROM blocked_client_events WHERE slot_time < ?",
				Timestamp.from(cutoff));
	}
}
