package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for persisting and querying runtime Valve configurations across the fleet.
 */
@Repository
public class MonitoredValveRepository {

	private final JdbcTemplate jdbcTemplate;

	public MonitoredValveRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<MonitoredValve> ROW_MAPPER = (rs, rowNum) -> new MonitoredValve(
			rs.getString("server_id"),
			rs.getString("valve_name"),
			rs.getString("description"),
			rs.getInt("pipeline_order"),
			rs.getString("monitor_mode"),
			rs.getBoolean("simulation_mode"),
			rs.getBoolean("server_wide_blocking"),
			rs.getInt("http_status_code"),
			rs.getInt("allowed_requests_per_slot"),
			rs.getInt("slot_length"),
			rs.getInt("number_of_slots"),
			rs.getFloat("share_of_retained_former_requests"),
			rs.getInt("ipv4_subnet_mask"),
			rs.getInt("ipv6_subnet_mask"),
			rs.getInt("max_ip_cache_size"),
			rs.getInt("max_blocked_ip_cache_size"),
			rs.getString("relevant_paths"),
			rs.getString("non_relevant_paths"),
			rs.getString("always_allowed_ips"),
			rs.getString("always_forbidden_ips"),
			rs.getString("status_uri"),
			rs.getString("status_allowed_ips"),
			toInstant(rs.getTimestamp("last_updated_at")),
			rs.getInt("config_hash")
	);

	private static Instant toInstant(Timestamp ts) {
		return ts != null ? ts.toInstant() : null;
	}

	public void upsert(MonitoredValve v) {
		String sql = """
				INSERT INTO monitored_valves (
				    server_id, valve_name, description, pipeline_order, monitor_mode,
				    simulation_mode, server_wide_blocking, http_status_code, allowed_requests_per_slot,
				    slot_length, number_of_slots, share_of_retained_former_requests,
				    ipv4_subnet_mask, ipv6_subnet_mask, max_ip_cache_size, max_blocked_ip_cache_size,
				    relevant_paths, non_relevant_paths, always_allowed_ips, always_forbidden_ips,
				    status_uri, status_allowed_ips, last_updated_at, config_hash
				)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (server_id, valve_name) DO UPDATE SET
				    description = EXCLUDED.description,
				    pipeline_order = EXCLUDED.pipeline_order,
				    monitor_mode = EXCLUDED.monitor_mode,
				    simulation_mode = EXCLUDED.simulation_mode,
				    server_wide_blocking = EXCLUDED.server_wide_blocking,
				    http_status_code = EXCLUDED.http_status_code,
				    allowed_requests_per_slot = EXCLUDED.allowed_requests_per_slot,
				    slot_length = EXCLUDED.slot_length,
				    number_of_slots = EXCLUDED.number_of_slots,
				    share_of_retained_former_requests = EXCLUDED.share_of_retained_former_requests,
				    ipv4_subnet_mask = EXCLUDED.ipv4_subnet_mask,
				    ipv6_subnet_mask = EXCLUDED.ipv6_subnet_mask,
				    max_ip_cache_size = EXCLUDED.max_ip_cache_size,
				    max_blocked_ip_cache_size = EXCLUDED.max_blocked_ip_cache_size,
				    relevant_paths = EXCLUDED.relevant_paths,
				    non_relevant_paths = EXCLUDED.non_relevant_paths,
				    always_allowed_ips = EXCLUDED.always_allowed_ips,
				    always_forbidden_ips = EXCLUDED.always_forbidden_ips,
				    status_uri = EXCLUDED.status_uri,
				    status_allowed_ips = EXCLUDED.status_allowed_ips,
				    last_updated_at = EXCLUDED.last_updated_at,
				    config_hash = EXCLUDED.config_hash
				""";

		jdbcTemplate.update(sql,
				v.serverId(),
				v.valveName(),
				v.description(),
				v.pipelineOrder(),
				v.monitorMode(),
				v.simulationMode(),
				v.serverWideBlocking(),
				v.httpStatusCode(),
				v.allowedRequestsPerSlot(),
				v.slotLength(),
				v.numberOfSlots(),
				v.shareOfRetainedFormerRequests(),
				v.ipv4SubnetMask(),
				v.ipv6SubnetMask(),
				v.maxIPCacheSize(),
				v.maxBlockedIPCacheSize(),
				v.relevantPaths(),
				v.nonRelevantPaths(),
				v.alwaysAllowedIPs(),
				v.alwaysForbiddenIPs(),
				v.statusUri(),
				v.statusAllowedIPs(),
				v.lastUpdatedAt() != null ? Timestamp.from(v.lastUpdatedAt()) : Timestamp.from(Instant.now()),
				v.configHash()
		);
	}

	public List<MonitoredValve> findByServerId(String serverId) {
		return jdbcTemplate.query(
				"SELECT * FROM monitored_valves WHERE server_id = ? ORDER BY pipeline_order ASC, valve_name ASC",
				ROW_MAPPER, serverId);
	}

	public Optional<MonitoredValve> findByServerIdAndValveName(String serverId, String valveName) {
		List<MonitoredValve> list = jdbcTemplate.query(
				"SELECT * FROM monitored_valves WHERE server_id = ? AND valve_name = ?",
				ROW_MAPPER, serverId, valveName);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.getFirst());
	}

	public List<MonitoredValve> findAll() {
		return jdbcTemplate.query(
				"SELECT * FROM monitored_valves ORDER BY server_id ASC, pipeline_order ASC, valve_name ASC",
				ROW_MAPPER);
	}

	public List<String> findDistinctValveNames() {
		return jdbcTemplate.queryForList(
				"SELECT DISTINCT valve_name FROM monitored_valves ORDER BY valve_name ASC",
				String.class);
	}

	public int deleteByServerId(String serverId) {
		return jdbcTemplate.update("DELETE FROM monitored_valves WHERE server_id = ?", serverId);
	}
}
