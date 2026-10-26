package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.henbru.antidos.collector.model.EndpointHeartbeat;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for managing endpoint health and connectivity heartbeats.
 */
@Repository
public class HeartbeatRepository {

	private final JdbcTemplate jdbcTemplate;

	public HeartbeatRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<EndpointHeartbeat> ROW_MAPPER = (rs, rowNum) -> new EndpointHeartbeat(
			rs.getString("server_id"),
			rs.getString("url"),
			rs.getBoolean("is_online"),
			toInstant(rs.getTimestamp("last_poll_at")),
			toInstant(rs.getTimestamp("last_success_at")),
			rs.getString("last_error"),
			rs.getLong("response_time_ms"),
			rs.getInt("valves_count")
	);

	private static Instant toInstant(Timestamp ts) {
		return ts != null ? ts.toInstant() : null;
	}

	public void upsert(EndpointHeartbeat hb) {
		String sql = """
				INSERT INTO endpoint_heartbeats (server_id, url, is_online, last_poll_at, last_success_at, last_error, response_time_ms, valves_count)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (server_id) DO UPDATE SET
				    url = EXCLUDED.url,
				    is_online = EXCLUDED.is_online,
				    last_poll_at = EXCLUDED.last_poll_at,
				    last_success_at = COALESCE(EXCLUDED.last_success_at, endpoint_heartbeats.last_success_at),
				    last_error = EXCLUDED.last_error,
				    response_time_ms = EXCLUDED.response_time_ms,
				    valves_count = EXCLUDED.valves_count
				""";

		StorageRetryUtil.executeWithRetry("HeartbeatRepository.upsert", () -> {
			jdbcTemplate.update(sql,
					hb.serverId(),
					hb.url(),
					hb.online(),
					hb.lastPollAt() != null ? Timestamp.from(hb.lastPollAt()) : null,
					hb.lastSuccessAt() != null ? Timestamp.from(hb.lastSuccessAt()) : null,
					hb.lastError(),
					hb.responseTimeMs(),
					hb.valvesCount()
			);
		});
	}

	public List<EndpointHeartbeat> findAll() {
		return jdbcTemplate.query("SELECT * FROM endpoint_heartbeats ORDER BY server_id ASC", ROW_MAPPER);
	}

	public Optional<EndpointHeartbeat> findByServerId(String serverId) {
		List<EndpointHeartbeat> list = jdbcTemplate.query(
				"SELECT * FROM endpoint_heartbeats WHERE server_id = ?", ROW_MAPPER, serverId);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.getFirst());
	}
}
