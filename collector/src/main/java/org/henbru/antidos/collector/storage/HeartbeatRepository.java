package org.henbru.antidos.collector.storage;

import java.sql.ResultSet;
import java.sql.SQLException;
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
 * JDBC repository for managing endpoint health, connectivity, and resource telemetry heartbeats.
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
			rs.getInt("valves_count"),
			getNullableDouble(rs, "cpu_process"),
			getNullableDouble(rs, "cpu_system"),
			getNullableDouble(rs, "system_load_avg"),
			getNullableLong(rs, "heap_used_bytes"),
			getNullableLong(rs, "heap_max_bytes"),
			getNullableDouble(rs, "heap_used_percent"),
			getNullableLong(rs, "gc_time_ms"),
			getNullableInt(rs, "busy_threads"),
			getNullableInt(rs, "max_threads")
	);

	private static Instant toInstant(Timestamp ts) {
		return ts != null ? ts.toInstant() : null;
	}

	private static Double getNullableDouble(ResultSet rs, String col) {
		try {
			Object val = rs.getObject(col);
			return val instanceof Number n ? n.doubleValue() : null;
		} catch (SQLException ignored) {
			return null;
		}
	}

	private static Long getNullableLong(ResultSet rs, String col) {
		try {
			Object val = rs.getObject(col);
			return val instanceof Number n ? n.longValue() : null;
		} catch (SQLException ignored) {
			return null;
		}
	}

	private static Integer getNullableInt(ResultSet rs, String col) {
		try {
			Object val = rs.getObject(col);
			return val instanceof Number n ? n.intValue() : null;
		} catch (SQLException ignored) {
			return null;
		}
	}

	public void upsert(EndpointHeartbeat hb) {
		String sql = """
				INSERT INTO endpoint_heartbeats (
				    server_id, url, is_online, last_poll_at, last_success_at, last_error, response_time_ms, valves_count,
				    cpu_process, cpu_system, system_load_avg, heap_used_bytes, heap_max_bytes, heap_used_percent,
				    gc_time_ms, busy_threads, max_threads
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (server_id) DO UPDATE SET
				    url = EXCLUDED.url,
				    is_online = EXCLUDED.is_online,
				    last_poll_at = EXCLUDED.last_poll_at,
				    last_success_at = COALESCE(EXCLUDED.last_success_at, endpoint_heartbeats.last_success_at),
				    last_error = EXCLUDED.last_error,
				    response_time_ms = EXCLUDED.response_time_ms,
				    valves_count = EXCLUDED.valves_count,
				    cpu_process = COALESCE(EXCLUDED.cpu_process, endpoint_heartbeats.cpu_process),
				    cpu_system = COALESCE(EXCLUDED.cpu_system, endpoint_heartbeats.cpu_system),
				    system_load_avg = COALESCE(EXCLUDED.system_load_avg, endpoint_heartbeats.system_load_avg),
				    heap_used_bytes = COALESCE(EXCLUDED.heap_used_bytes, endpoint_heartbeats.heap_used_bytes),
				    heap_max_bytes = COALESCE(EXCLUDED.heap_max_bytes, endpoint_heartbeats.heap_max_bytes),
				    heap_used_percent = COALESCE(EXCLUDED.heap_used_percent, endpoint_heartbeats.heap_used_percent),
				    gc_time_ms = COALESCE(EXCLUDED.gc_time_ms, endpoint_heartbeats.gc_time_ms),
				    busy_threads = COALESCE(EXCLUDED.busy_threads, endpoint_heartbeats.busy_threads),
				    max_threads = COALESCE(EXCLUDED.max_threads, endpoint_heartbeats.max_threads)
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
					hb.valvesCount(),
					hb.processCpuLoad(),
					hb.systemCpuLoad(),
					hb.systemLoadAverage(),
					hb.heapUsedBytes(),
					hb.heapMaxBytes(),
					hb.heapUsedPercent(),
					hb.gcCollectionTimeMs(),
					hb.tomcatBusyThreads(),
					hb.tomcatMaxThreads()
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
