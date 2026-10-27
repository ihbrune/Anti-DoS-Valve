package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for persisting and querying runtime Valve configurations across the fleet.
 */
@Repository
public class MonitoredValveRepository {

	private static final Logger log = LoggerFactory.getLogger(MonitoredValveRepository.class);

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
			rs.getString("collector_integration"),
			rs.getBoolean("visitor_cookie_enabled"),
			rs.getString("visitor_cookie_name"),
			toInstant(rs.getTimestamp("last_updated_at")),
			rs.getInt("config_hash"),
			rs.getBoolean("is_active")
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
				    status_uri, status_allowed_ips, collector_integration,
				    visitor_cookie_enabled, visitor_cookie_name,
				    last_updated_at, config_hash, is_active
				)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
				    collector_integration = EXCLUDED.collector_integration,
				    visitor_cookie_enabled = EXCLUDED.visitor_cookie_enabled,
				    visitor_cookie_name = EXCLUDED.visitor_cookie_name,
				    last_updated_at = EXCLUDED.last_updated_at,
				    config_hash = EXCLUDED.config_hash,
				    is_active = EXCLUDED.is_active
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
				v.collectorIntegration(),
				v.visitorCookieEnabled(),
				v.visitorCookieName(),
				v.lastUpdatedAt() != null ? Timestamp.from(v.lastUpdatedAt()) : Timestamp.from(Instant.now()),
				v.configHash(),
				v.isActive()
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

	public int deleteByServerIdAndValveName(String serverId, String valveName) {
		return jdbcTemplate.update(
				"DELETE FROM monitored_valves WHERE server_id = ? AND valve_name = ?",
				serverId, valveName);
	}

	/**
	 * Synchronizes the active/inactive state of valves for a given server based on the latest poll.
	 * Any valve for this server not contained in {@code activeValveNames} will be set to {@code is_active = false}.
	 * Any valve contained in {@code activeValveNames} will be ensured to have {@code is_active = true}.
	 *
	 * @param serverId the identifier of the server/endpoint
	 * @param activeValveNames collection of valve names discovered in the latest poll
	 */
	public void syncActiveValves(String serverId, Collection<String> activeValveNames) {
		if (serverId == null || serverId.isBlank()) {
			return;
		}
		if (activeValveNames == null || activeValveNames.isEmpty()) {
			int deactivated = jdbcTemplate.update(
					"UPDATE monitored_valves SET is_active = ? WHERE server_id = ? AND is_active = ?",
					false, serverId, true);
			if (deactivated > 0) {
				log.info("Marked all {} valve(s) on '{}' as inactive (no active valves reported)", deactivated, serverId);
			}
			return;
		}

		String placeholders = String.join(",", Collections.nCopies(activeValveNames.size(), "?"));

		// 1. Deactivate missing valves
		String deactSql = "UPDATE monitored_valves SET is_active = ? WHERE server_id = ? AND is_active = ? AND valve_name NOT IN (" + placeholders + ")";
		List<Object> deactParams = new ArrayList<>();
		deactParams.add(false);
		deactParams.add(serverId);
		deactParams.add(true);
		deactParams.addAll(activeValveNames);
		int deactivated = jdbcTemplate.update(deactSql, deactParams.toArray());
		if (deactivated > 0) {
			log.info("Marked {} valve(s) on '{}' as inactive (no longer reported)", deactivated, serverId);
		}

		// 2. Reactivate any valves that were previously marked inactive
		String actSql = "UPDATE monitored_valves SET is_active = ? WHERE server_id = ? AND is_active = ? AND valve_name IN (" + placeholders + ")";
		List<Object> actParams = new ArrayList<>();
		actParams.add(true);
		actParams.add(serverId);
		actParams.add(false);
		actParams.addAll(activeValveNames);
		int reactivated = jdbcTemplate.update(actSql, actParams.toArray());
		if (reactivated > 0) {
			log.info("Re-activated {} valve(s) on '{}' (reported again)", reactivated, serverId);
		}
	}
}
