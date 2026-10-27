package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.EnrichmentStatus;
import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

import jakarta.annotation.PostConstruct;

/**
 * JDBC repository for storing individual client events (both BLOCKED and ACTIVE) and running analytics.
 */
@Repository
@SuppressWarnings("null")
public class ClientEventRepository {

	private static final Logger log = LoggerFactory.getLogger(ClientEventRepository.class);

	private final JdbcTemplate jdbcTemplate;

	public ClientEventRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<ClientEvent> ROW_MAPPER = (rs, rowNum) -> {
		String clientKey = rs.getString("client_key");
		int ipVersion = rs.getInt("ip_version");
		int cidrPrefix = rs.getInt("cidr_prefix");
		Long v4Start = rs.getObject("ip_v4_start") != null ? rs.getLong("ip_v4_start") : null;
		Long v4End = rs.getObject("ip_v4_end") != null ? rs.getLong("ip_v4_end") : null;
		String v6Start = rs.getString("ip_v6_start");
		String v6End = rs.getString("ip_v6_end");
		String subnetGroup = rs.getString("subnet_group");

		// Dynamic fallback normalization for legacy/unparsed rows
		if ((v4Start == null && v6Start == null) || (subnetGroup == null || !subnetGroup.contains("/"))) {
			IpNetworkInfo parsed = IpNetworkUtil.parse(clientKey);
			if (parsed.v4Start() != null || parsed.v6Start() != null) {
				ipVersion = parsed.version();
				cidrPrefix = parsed.prefix();
				v4Start = parsed.v4Start();
				v4End = parsed.v4End();
				v6Start = parsed.v6Start();
				v6End = parsed.v6End();
				subnetGroup = parsed.subnetGroup();
			}
		}

		Long asn = rs.getObject("asn") != null ? rs.getLong("asn") : null;
		String asOrg = rs.getString("as_org");
		String countryCode = rs.getString("country_code");
		String rawClientType = rs.getString("client_type");
		ClientType clientType = rawClientType != null ? ClientType.valueOf(rawClientType) : ClientType.UNKNOWN;
		String rawStatus = rs.getString("enrichment_status");
		EnrichmentStatus enrichmentStatus = rawStatus != null ? EnrichmentStatus.valueOf(rawStatus) : EnrichmentStatus.PENDING;
		Long entityId = rs.getObject("entity_id") != null ? rs.getLong("entity_id") : null;

		String eventStatus = rs.getString("status");
		if (eventStatus == null || eventStatus.isBlank()) {
			eventStatus = rs.getBoolean("is_locked") ? ClientEvent.STATUS_BLOCKED : ClientEvent.STATUS_ACTIVE;
		}

		Integer returningCount = null;
		try {
			returningCount = rs.getObject("returning_count") != null ? rs.getInt("returning_count") : null;
		} catch (SQLException ignored) {
		}

		Integer authenticatedCount = null;
		try {
			authenticatedCount = rs.getObject("authenticated_count") != null ? rs.getInt("authenticated_count") : null;
		} catch (SQLException ignored) {
		}

		return new ClientEvent(
				rs.getLong("id"),
				rs.getString("server_id"),
				rs.getString("valve_name"),
				rs.getLong("slot_key"),
				rs.getTimestamp("slot_time").toInstant(),
				clientKey,
				ipVersion,
				cidrPrefix,
				v4Start,
				v4End,
				v6Start,
				v6End,
				subnetGroup,
				rs.getInt("request_count"),
				rs.getInt("retained_count"),
				rs.getBoolean("is_locked"),
				eventStatus,
				rs.getBoolean("is_completed"),
				rs.getTimestamp("last_updated_at").toInstant(),
				asn,
				asOrg,
				countryCode,
				clientType,
				enrichmentStatus,
				entityId,
				getDistinctClientsFromResultSet(rs),
				returningCount,
				authenticatedCount
		);
	};

	private static int getDistinctClientsFromResultSet(ResultSet rs) {
		try {
			int val = rs.getInt("distinct_clients");
			return val > 0 ? val : 1;
		} catch (SQLException ignored) {
			return 1;
		}
	}

	@PostConstruct
	public void repairUnnormalizedEvents() {
		try {
			List<Map<String, Object>> rows = jdbcTemplate.queryForList("""
					SELECT id, client_key FROM client_events
					WHERE (ip_version = 4 AND (ip_v4_start IS NULL OR ip_v4_end IS NULL))
					   OR (ip_version = 6 AND (ip_v6_start IS NULL OR ip_v6_end IS NULL))
					   OR (subnet_group NOT LIKE '%/%' AND (client_key LIKE '%.%' OR client_key LIKE '%:%'))
					""");
			if (!rows.isEmpty()) {
				log.info("Repairing {} unnormalized client events with canonical network ranges and subnets...", rows.size());
				String updateSql = """
						UPDATE client_events SET
						    ip_version = ?,
						    cidr_prefix = ?,
						    ip_v4_start = ?,
						    ip_v4_end = ?,
						    ip_v6_start = ?,
						    ip_v6_end = ?,
						    subnet_group = ?
						WHERE id = ?
						""";
				jdbcTemplate.batchUpdate(updateSql, new BatchPreparedStatementSetter() {
					@Override
					public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
						Map<String, Object> row = rows.get(i);
						long id = ((Number) row.get("id")).longValue();
						String clientKey = (String) row.get("client_key");
						IpNetworkInfo net = IpNetworkUtil.parse(clientKey);

						ps.setInt(1, net.version());
						ps.setInt(2, net.prefix());
						if (net.v4Start() != null) {
							ps.setLong(3, net.v4Start());
						} else {
							ps.setNull(3, Types.BIGINT);
						}
						if (net.v4End() != null) {
							ps.setLong(4, net.v4End());
						} else {
							ps.setNull(4, Types.BIGINT);
						}
						ps.setString(5, net.v6Start());
						ps.setString(6, net.v6End());
						ps.setString(7, net.subnetGroup());
						ps.setLong(8, id);
					}

					@Override
					public int getBatchSize() {
						return rows.size();
					}
				});
				log.info("Successfully repaired {} client events.", rows.size());
			}

			// Backfill missing entity_id from network_entity if unassigned
			jdbcTemplate.update("""
					UPDATE client_events
					SET entity_id = (SELECT e.id FROM network_entity e WHERE e.client_key = client_events.client_key)
					WHERE entity_id IS NULL AND EXISTS (SELECT 1 FROM network_entity e WHERE e.client_key = client_events.client_key)
					""");
		} catch (DataAccessException e) {
			log.warn("Could not repair unnormalized events on startup: {}", e.getMessage());
		}
	}

	private static final int BATCH_CHUNK_SIZE = 500;

	public void batchUpsert(List<ClientEvent> events) {
		if (events == null || events.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO client_events (
				    server_id, valve_name, slot_key, slot_time, client_key,
				    ip_version, cidr_prefix, ip_v4_start, ip_v4_end, ip_v6_start, ip_v6_end, subnet_group,
				    request_count, retained_count, is_locked, status, is_completed, last_updated_at,
				    asn, as_org, country_code, client_type, enrichment_status, entity_id, distinct_clients,
				    returning_count, authenticated_count
				)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (server_id, valve_name, slot_key, client_key) DO UPDATE SET
				    slot_time = EXCLUDED.slot_time,
				    ip_version = EXCLUDED.ip_version,
				    cidr_prefix = EXCLUDED.cidr_prefix,
				    ip_v4_start = EXCLUDED.ip_v4_start,
				    ip_v4_end = EXCLUDED.ip_v4_end,
				    ip_v6_start = EXCLUDED.ip_v6_start,
				    ip_v6_end = EXCLUDED.ip_v6_end,
				    subnet_group = EXCLUDED.subnet_group,
				    request_count = EXCLUDED.request_count,
				    retained_count = EXCLUDED.retained_count,
				    is_locked = EXCLUDED.is_locked,
				    status = EXCLUDED.status,
				    is_completed = EXCLUDED.is_completed,
				    last_updated_at = EXCLUDED.last_updated_at,
				    distinct_clients = EXCLUDED.distinct_clients,
				    returning_count = EXCLUDED.returning_count,
				    authenticated_count = EXCLUDED.authenticated_count,
				    entity_id = COALESCE(EXCLUDED.entity_id, client_events.entity_id)
				""";

		for (int from = 0; from < events.size(); from += BATCH_CHUNK_SIZE) {
			int to = Math.min(from + BATCH_CHUNK_SIZE, events.size());
			List<ClientEvent> chunk = events.subList(from, to);
			StorageRetryUtil.executeWithRetry("ClientEventRepository.batchUpsert", () -> {
				jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
					@Override
					public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
						ClientEvent e = chunk.get(i);
						ps.setString(1, e.serverId());
						ps.setString(2, e.valveName());
						ps.setLong(3, e.slotKey());
						ps.setTimestamp(4, Timestamp.from(e.slotTime()));
						ps.setString(5, e.clientKey());
						ps.setInt(6, e.ipVersion());
						ps.setInt(7, e.cidrPrefix());
						if (e.ipV4Start() != null) {
							ps.setLong(8, e.ipV4Start());
						} else {
							ps.setNull(8, Types.BIGINT);
						}
						if (e.ipV4End() != null) {
							ps.setLong(9, e.ipV4End());
						} else {
							ps.setNull(9, Types.BIGINT);
						}
						ps.setString(10, e.ipV6Start());
						ps.setString(11, e.ipV6End());
						ps.setString(12, e.subnetGroup());
						ps.setInt(13, e.requestCount());
						ps.setInt(14, e.retainedCount());
						ps.setBoolean(15, e.locked());
						ps.setString(16, e.status() != null ? e.status() : (e.locked() ? ClientEvent.STATUS_BLOCKED : ClientEvent.STATUS_ACTIVE));
						ps.setBoolean(17, e.completed());
						ps.setTimestamp(18, Timestamp.from(e.lastUpdatedAt()));

						if (e.asn() != null) {
							ps.setLong(19, e.asn());
						} else {
							ps.setNull(19, Types.BIGINT);
						}
						ps.setString(20, e.asOrg());
						ps.setString(21, e.countryCode());
						ps.setString(22, e.clientType() != null ? e.clientType().name() : ClientType.UNKNOWN.name());
						ps.setString(23, e.enrichmentStatus() != null ? e.enrichmentStatus().name() : EnrichmentStatus.PENDING.name());
						if (e.entityId() != null) {
							ps.setLong(24, e.entityId());
						} else {
							ps.setNull(24, Types.BIGINT);
						}
						ps.setInt(25, Math.max(1, e.distinctClients()));
						if (e.returningCount() != null) {
							ps.setInt(26, e.returningCount());
						} else {
							ps.setNull(26, Types.INTEGER);
						}
						if (e.authenticatedCount() != null) {
							ps.setInt(27, e.authenticatedCount());
						} else {
							ps.setNull(27, Types.INTEGER);
						}
					}

					@Override
					public int getBatchSize() {
						return chunk.size();
					}
				});
			});
		}
	}

	public List<TopOffenderSummary> findTopOffenders(Instant since, int limit) {
		return findTopOffendersFiltered(null, null, since, null, null, null, null, null, "CLIENT", limit);
	}

	public List<ClientEvent> findRecentEvents(String serverId, String filterIp, int limit) {
		List<String> servers = (serverId != null && !serverId.trim().isEmpty()) ? List.of(serverId) : null;
		return findRecentEventsFiltered(servers, null, null, null, filterIp, null, null, null, limit, 0);
	}

	/**
	 * Core query builder for filtering recent client events with multi-server, multi-valve, time range,
	 * CIDR/subnet, classification, ASN, and status criteria.
	 */
	public List<ClientEvent> findRecentEventsFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			List<String> clientTypes,
			Long asn,
			String asOrg,
			String status,
			int limit,
			int offset
	) {
		StringBuilder sql = new StringBuilder("SELECT * FROM client_events WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		appendFilterCriteria(sql, params, serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn, asOrg, status);

		sql.append("ORDER BY slot_time DESC LIMIT ? OFFSET ?");
		params.add(Math.max(1, Math.min(limit, 500)));
		params.add(Math.max(0, offset));

		return jdbcTemplate.query(sql.toString(), ROW_MAPPER, params.toArray());
	}

	public List<ClientEvent> findRecentEventsFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			List<String> clientTypes,
			Long asn,
			String status,
			int limit,
			int offset
	) {
		return findRecentEventsFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn, null, status, limit, offset);
	}

	public List<ClientEvent> findRecentEventsFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			List<String> clientTypes,
			Long asn,
			int limit,
			int offset
	) {
		return findRecentEventsFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn, null, null, limit, offset);
	}

	public List<ClientEvent> findRecentEventsFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			int limit,
			int offset
	) {
		return findRecentEventsFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, null, null, null, null, limit, offset);
	}

	public long countRecentEventsFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			List<String> clientTypes,
			Long asn,
			String asOrg,
			String status
	) {
		StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM client_events WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		appendFilterCriteria(sql, params, serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn, asOrg, status);

		Long count = jdbcTemplate.queryForObject(sql.toString(), Long.class, params.toArray());
		return count != null ? count : 0L;
	}

	public long countRecentEventsFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			List<String> clientTypes,
			Long asn,
			String status
	) {
		return countRecentEventsFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn, null, status);
	}

	public long countRecentEventsFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery
	) {
		return countRecentEventsFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, null, null, null, null);
	}

	/**
	 * Aggregates top offenders either by single client IP/key ("CLIENT"), by canonical subnet ("SUBNET"),
	 * or by full Autonomous System ("ASN"), supporting classification, ASN, and status filtering.
	 */
	public List<TopOffenderSummary> findTopOffendersFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			List<String> clientTypes,
			Long asn,
			String asOrg,
			String status,
			String groupBy,
			int limit
	) {
		String groupCol;
		if ("ASN".equalsIgnoreCase(groupBy)) {
			groupCol = "COALESCE('AS' || asn, 'AS-UNKNOWN')";
		} else if ("SUBNET".equalsIgnoreCase(groupBy)) {
			groupCol = "subnet_group";
		} else {
			groupCol = "client_key";
		}

		StringBuilder sql = new StringBuilder();
		sql.append("SELECT ")
				.append(groupCol).append(" AS client_key, ")
				.append("MAX(asn) AS asn, ")
				.append("MAX(as_org) AS as_org, ")
				.append("MAX(country_code) AS country_code, ")
				.append("MAX(client_type) AS client_type, ")
				.append("CASE WHEN MAX(distinct_clients) > COUNT(DISTINCT client_key) THEN MAX(distinct_clients) ELSE COUNT(DISTINCT client_key) END AS distinct_clients, ")
				.append("COUNT(*) AS total_incidents, ")
				.append("SUM(request_count + retained_count) AS total_requests, ")
				.append("COUNT(DISTINCT server_id) AS distinct_servers, ")
				.append("MIN(slot_time) AS first_seen, ")
				.append("MAX(slot_time) AS last_seen ")
				.append("FROM client_events ")
				.append("WHERE 1=1 ");

		List<Object> params = new ArrayList<>();
		appendFilterCriteria(sql, params, serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn, asOrg, status);

		sql.append("GROUP BY ").append(groupCol).append(" ");
		sql.append("ORDER BY total_requests DESC LIMIT ?");
		params.add(Math.max(1, Math.min(limit, 500)));

		return jdbcTemplate.query(sql.toString(), (rs, rowNum) -> {
			Long rowAsn = rs.getObject("asn") != null ? rs.getLong("asn") : null;
			String rawType = rs.getString("client_type");
			ClientType clientType = rawType != null ? ClientType.valueOf(rawType) : ClientType.UNKNOWN;

			return new TopOffenderSummary(
					rs.getString("client_key") != null ? rs.getString("client_key") : "unknown",
					rs.getLong("total_incidents"),
					rs.getLong("total_requests"),
					rs.getInt("distinct_servers"),
					"",
					rs.getTimestamp("first_seen").toInstant(),
					rs.getTimestamp("last_seen").toInstant(),
					rowAsn,
					rs.getString("as_org"),
					rs.getString("country_code"),
					clientType,
					rs.getInt("distinct_clients")
			);
		}, params.toArray());
	}

	public List<TopOffenderSummary> findTopOffendersFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			List<String> clientTypes,
			Long asn,
			String status,
			String groupBy,
			int limit
	) {
		return findTopOffendersFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn, null, status, groupBy, limit);
	}

	public List<TopOffenderSummary> findTopOffendersFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			List<String> clientTypes,
			Long asn,
			String groupBy,
			int limit
	) {
		return findTopOffendersFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn, null, null, groupBy, limit);
	}

	public List<TopOffenderSummary> findTopOffendersFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			String groupBy,
			int limit
	) {
		return findTopOffendersFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, null, null, null, null, groupBy, limit);
	}

	private void appendFilterCriteria(
			StringBuilder sql,
			List<Object> params,
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			List<String> clientTypes,
			Long asn,
			String asOrg,
			String status
	) {
		if (serverIds != null && !serverIds.isEmpty()) {
			sql.append("AND server_id IN (");
			for (int i = 0; i < serverIds.size(); i++) {
				sql.append(i > 0 ? ",?" : "?");
				params.add(serverIds.get(i));
			}
			sql.append(") ");
		}

		if (valveNames != null && !valveNames.isEmpty()) {
			sql.append("AND valve_name IN (");
			for (int i = 0; i < valveNames.size(); i++) {
				sql.append(i > 0 ? ",?" : "?");
				params.add(valveNames.get(i));
			}
			sql.append(") ");
		}

		if (fromTime != null) {
			sql.append("AND slot_time >= ? ");
			params.add(Timestamp.from(fromTime));
		}

		if (toTime != null) {
			sql.append("AND slot_time <= ? ");
			params.add(Timestamp.from(toTime));
		}

		if (asn != null) {
			sql.append("AND asn = ? ");
			params.add(asn);
		} else if (asOrg != null && !asOrg.isBlank()) {
			sql.append("AND LOWER(as_org) LIKE LOWER(?) ");
			params.add("%" + asOrg.trim() + "%");
		}

		if (status != null && !status.isBlank() && !"ALL".equalsIgnoreCase(status.trim())) {
			sql.append("AND status = ? ");
			params.add(status.trim().toUpperCase());
		}

		if (clientTypes != null && !clientTypes.isEmpty()) {
			List<String> validTypes = clientTypes.stream()
					.filter(t -> t != null && !t.isBlank() && !"ALL".equalsIgnoreCase(t.trim()))
					.map(t -> t.trim().toUpperCase())
					.toList();
			if (!validTypes.isEmpty()) {
				sql.append("AND client_type IN (");
				for (int i = 0; i < validTypes.size(); i++) {
					sql.append(i > 0 ? ",?" : "?");
					params.add(validTypes.get(i));
				}
				sql.append(") ");
			}
		}

		if (clientQuery != null && !clientQuery.trim().isEmpty()) {
			String trimmedQuery = clientQuery.trim();
			Long parsedAsn = parseAsnQuery(trimmedQuery);
			if (parsedAsn != null && asn == null) {
				sql.append("AND asn = ? ");
				params.add(parsedAsn);
			} else {
				IpNetworkUtil.SearchCriteria criteria = IpNetworkUtil.parseSearchQuery(trimmedQuery);
				if (criteria.isIpSearch()) {
					if (criteria.ipVersion() == 4) {
						sql.append("AND ((ip_version = 4 AND ip_v4_start <= ? AND ip_v4_end >= ?) OR client_key = ? OR subnet_group = ? OR client_key LIKE ?) ");
						params.add(criteria.v4End());
						params.add(criteria.v4Start());
						params.add(criteria.rawQuery());
						params.add(criteria.rawQuery());
						params.add(criteria.rawQuery() + "%");
					} else if (criteria.ipVersion() == 6) {
						sql.append("AND ((ip_version = 6 AND ip_v6_start <= ? AND ip_v6_end >= ?) OR client_key = ? OR subnet_group = ? OR client_key LIKE ?) ");
						params.add(criteria.v6End());
						params.add(criteria.v6Start());
						params.add(criteria.rawQuery());
						params.add(criteria.rawQuery());
						params.add(criteria.rawQuery() + "%");
					}
				} else if (criteria.hasFilter()) {
					sql.append("AND (client_key LIKE ? OR subnet_group LIKE ? OR LOWER(as_org) LIKE LOWER(?)) ");
					String likePattern = "%" + criteria.rawQuery() + "%";
					params.add(likePattern);
					params.add(likePattern);
					params.add(likePattern);
				}
			}
		}
	}

	private static Long parseAsnQuery(String input) {
		if (input == null) {
			return null;
		}
		String s = input.trim();
		if (s.regionMatches(true, 0, "AS", 0, 2)) {
			String numPart = s.substring(2).trim();
			try {
				return Long.valueOf(numPart);
			} catch (NumberFormatException ignored) {
			}
		}
		return null;
	}

	public List<String> findDistinctServerIds() {
		return jdbcTemplate.query(
				"SELECT DISTINCT server_id FROM client_events ORDER BY server_id ASC",
				(rs, rowNum) -> rs.getString(1)
		);
	}

	public List<String> findDistinctValveNames(List<String> serverIds) {
		return findDistinctValves(serverIds);
	}

	public List<String> findDistinctValves(List<String> serverIds) {
		if (serverIds == null || serverIds.isEmpty()) {
			return jdbcTemplate.query(
					"SELECT DISTINCT valve_name FROM client_events ORDER BY valve_name ASC",
					(rs, rowNum) -> rs.getString(1)
			);
		}
		StringBuilder sql = new StringBuilder("SELECT DISTINCT valve_name FROM client_events WHERE server_id IN (");
		for (int i = 0; i < serverIds.size(); i++) {
			sql.append(i > 0 ? ",?" : "?");
		}
		sql.append(") ORDER BY valve_name ASC");
		return jdbcTemplate.query(sql.toString(), (rs, rowNum) -> rs.getString(1), serverIds.toArray());
	}

	public long countDistinctBlockedClientsSince(Instant since) {
		Long count = jdbcTemplate.queryForObject(
				"SELECT COUNT(DISTINCT client_key) FROM client_events WHERE status = 'BLOCKED' AND slot_time >= ?",
				Long.class, Timestamp.from(since));
		return count != null ? count : 0L;
	}

	public int deleteOlderThan(Instant cutoff) {
		return jdbcTemplate.update(
				"DELETE FROM client_events WHERE slot_time < ?",
				Timestamp.from(cutoff));
	}

	public int deleteOlderThan(Instant cutoff, String status) {
		if (status == null || status.isBlank()) {
			return deleteOlderThan(cutoff);
		}
		return jdbcTemplate.update(
				"DELETE FROM client_events WHERE status = ? AND slot_time < ?",
				status.trim().toUpperCase(), Timestamp.from(cutoff));
	}

	public List<ClientEvent> findPendingEnrichment(int limit) {
		String sql = "SELECT * FROM client_events WHERE enrichment_status = 'PENDING' ORDER BY id ASC LIMIT ?";
		return jdbcTemplate.query(sql, ROW_MAPPER, limit);
	}

	public void batchUpdateEnrichment(List<ClientEvent> events) {
		if (events == null || events.isEmpty()) {
			return;
		}

		String sql = """
				UPDATE client_events SET
				    asn = ?,
				    as_org = ?,
				    country_code = ?,
				    client_type = ?,
				    enrichment_status = ?
				WHERE id = ?
				""";

		for (int from = 0; from < events.size(); from += BATCH_CHUNK_SIZE) {
			int to = Math.min(from + BATCH_CHUNK_SIZE, events.size());
			List<ClientEvent> chunk = events.subList(from, to);
			StorageRetryUtil.executeWithRetry("ClientEventRepository.batchUpdateEnrichment", () -> {
				jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
					@Override
					public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
						ClientEvent e = chunk.get(i);
						if (e.asn() != null) {
							ps.setLong(1, e.asn());
						} else {
							ps.setNull(1, Types.BIGINT);
						}
						ps.setString(2, e.asOrg());
						ps.setString(3, e.countryCode());
						ps.setString(4, e.clientType() != null ? e.clientType().name() : ClientType.UNKNOWN.name());
						ps.setString(5, e.enrichmentStatus() != null ? e.enrichmentStatus().name() : EnrichmentStatus.ENRICHED.name());
						ps.setLong(6, e.id());
					}

					@Override
					public int getBatchSize() {
						return chunk.size();
					}
				});
			});
		}
	}

	public int deleteByServerIdAndValveName(String serverId, String valveName) {
		return jdbcTemplate.update(
				"DELETE FROM client_events WHERE server_id = ? AND valve_name = ?",
				serverId, valveName);
	}
}

