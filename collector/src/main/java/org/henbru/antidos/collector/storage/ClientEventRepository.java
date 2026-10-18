package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.henbru.antidos.collector.model.BlockedClientEvent;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.EnrichmentStatus;
import org.henbru.antidos.collector.model.TopOffenderSummary;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for storing individual blocked IP/subnet client events and running analytics.
 */
@Repository
@SuppressWarnings("null")
public class ClientEventRepository {

	private final JdbcTemplate jdbcTemplate;

	public ClientEventRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<BlockedClientEvent> ROW_MAPPER = (rs, rowNum) -> {
		Long v4Start = rs.getObject("ip_v4_start") != null ? rs.getLong("ip_v4_start") : null;
		Long v4End = rs.getObject("ip_v4_end") != null ? rs.getLong("ip_v4_end") : null;
		Long asn = rs.getObject("asn") != null ? rs.getLong("asn") : null;
		String asOrg = rs.getString("as_org");
		String countryCode = rs.getString("country_code");
		String rawClientType = rs.getString("client_type");
		ClientType clientType = rawClientType != null ? ClientType.valueOf(rawClientType) : ClientType.UNKNOWN;
		String rawStatus = rs.getString("enrichment_status");
		EnrichmentStatus enrichmentStatus = rawStatus != null ? EnrichmentStatus.valueOf(rawStatus) : EnrichmentStatus.PENDING;

		return new BlockedClientEvent(
				rs.getLong("id"),
				rs.getString("server_id"),
				rs.getString("valve_name"),
				rs.getLong("slot_key"),
				rs.getTimestamp("slot_time").toInstant(),
				rs.getString("client_key"),
				rs.getInt("ip_version"),
				rs.getInt("cidr_prefix"),
				v4Start,
				v4End,
				rs.getString("ip_v6_start"),
				rs.getString("ip_v6_end"),
				rs.getString("subnet_group"),
				rs.getInt("request_count"),
				rs.getInt("retained_count"),
				rs.getBoolean("is_locked"),
				rs.getBoolean("is_completed"),
				rs.getTimestamp("last_updated_at").toInstant(),
				asn,
				asOrg,
				countryCode,
				clientType,
				enrichmentStatus
		);
	};

	public void batchUpsert(List<BlockedClientEvent> events) {
		if (events == null || events.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO blocked_client_events (
				    server_id, valve_name, slot_key, slot_time, client_key,
				    ip_version, cidr_prefix, ip_v4_start, ip_v4_end, ip_v6_start, ip_v6_end, subnet_group,
				    request_count, retained_count, is_locked, is_completed, last_updated_at,
				    asn, as_org, country_code, client_type, enrichment_status
				)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
				ps.setBoolean(16, e.completed());
				ps.setTimestamp(17, Timestamp.from(e.lastUpdatedAt()));

				if (e.asn() != null) {
					ps.setLong(18, e.asn());
				} else {
					ps.setNull(18, Types.BIGINT);
				}
				ps.setString(19, e.asOrg());
				ps.setString(20, e.countryCode());
				ps.setString(21, e.clientType() != null ? e.clientType().name() : ClientType.UNKNOWN.name());
				ps.setString(22, e.enrichmentStatus() != null ? e.enrichmentStatus().name() : EnrichmentStatus.PENDING.name());
			}

			@Override
			public int getBatchSize() {
				return events.size();
			}
		});
	}

	public List<TopOffenderSummary> findTopOffenders(Instant since, int limit) {
		return findTopOffendersFiltered(null, null, since, null, null, "CLIENT", limit);
	}

	public List<BlockedClientEvent> findRecentEvents(String serverId, String filterIp, int limit) {
		List<String> servers = (serverId != null && !serverId.trim().isEmpty()) ? List.of(serverId) : null;
		return findRecentEventsFiltered(servers, null, null, null, filterIp, limit, 0);
	}

	/**
	 * Core query builder for filtering recent blocking events with multi-server, multi-valve, time range,
	 * CIDR/subnet, classification, and ASN criteria.
	 */
	public List<BlockedClientEvent> findRecentEventsFiltered(
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
		StringBuilder sql = new StringBuilder("SELECT * FROM blocked_client_events WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		appendFilterCriteria(sql, params, serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn);

		sql.append("ORDER BY slot_time DESC LIMIT ? OFFSET ?");
		params.add(Math.max(1, Math.min(limit, 500)));
		params.add(Math.max(0, offset));

		return jdbcTemplate.query(sql.toString(), ROW_MAPPER, params.toArray());
	}

	public List<BlockedClientEvent> findRecentEventsFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			int limit,
			int offset
	) {
		return findRecentEventsFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, null, null, limit, offset);
	}

	public long countRecentEventsFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery,
			List<String> clientTypes,
			Long asn
	) {
		StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM blocked_client_events WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		appendFilterCriteria(sql, params, serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn);

		Long count = jdbcTemplate.queryForObject(sql.toString(), Long.class, params.toArray());
		return count != null ? count : 0L;
	}

	public long countRecentEventsFiltered(
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery
	) {
		return countRecentEventsFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, null, null);
	}

	/**
	 * Aggregates top offenders either by single client IP/key ("CLIENT"), by canonical subnet ("SUBNET"),
	 * or by full Autonomous System ("ASN"), supporting classification and ASN filtering.
	 */
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
				.append("COUNT(DISTINCT client_key) AS distinct_clients, ")
				.append("COUNT(*) AS total_incidents, ")
				.append("SUM(request_count + retained_count) AS total_requests, ")
				.append("COUNT(DISTINCT server_id) AS distinct_servers, ")
				.append("MIN(slot_time) AS first_seen, ")
				.append("MAX(slot_time) AS last_seen ")
				.append("FROM blocked_client_events ")
				.append("WHERE 1=1 ");

		List<Object> params = new ArrayList<>();
		appendFilterCriteria(sql, params, serverIds, valveNames, fromTime, toTime, clientQuery, clientTypes, asn);

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
			String groupBy,
			int limit
	) {
		return findTopOffendersFiltered(serverIds, valveNames, fromTime, toTime, clientQuery, null, null, groupBy, limit);
	}

	private void appendFilterCriteria(
			StringBuilder sql,
			List<Object> params,
			List<String> serverIds,
			List<String> valveNames,
			Instant fromTime,
			Instant toTime,
			String clientQuery
	) {
		appendFilterCriteria(sql, params, serverIds, valveNames, fromTime, toTime, clientQuery, null, null);
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
			Long asn
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
						sql.append("AND (ip_version = 4 AND ip_v4_start <= ? AND ip_v4_end >= ?) ");
						params.add(criteria.v4End());
						params.add(criteria.v4Start());
					} else if (criteria.ipVersion() == 6) {
						sql.append("AND (ip_version = 6 AND ip_v6_start <= ? AND ip_v6_end >= ?) ");
						params.add(criteria.v6End());
						params.add(criteria.v6Start());
					}
				} else if (criteria.hasFilter()) {
					sql.append("AND (client_key LIKE ? OR subnet_group LIKE ? OR as_org LIKE ?) ");
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
				return Long.parseLong(numPart);
			} catch (NumberFormatException ignored) {
			}
		}
		return null;
	}

	public List<String> findDistinctServerIds() {
		return jdbcTemplate.query(
				"SELECT DISTINCT server_id FROM blocked_client_events ORDER BY server_id ASC",
				(rs, rowNum) -> rs.getString(1)
		);
	}

	public List<String> findDistinctValveNames(List<String> serverIds) {
		if (serverIds == null || serverIds.isEmpty()) {
			return jdbcTemplate.query(
					"SELECT DISTINCT valve_name FROM blocked_client_events ORDER BY valve_name ASC",
					(rs, rowNum) -> rs.getString(1)
			);
		}
		StringBuilder sql = new StringBuilder("SELECT DISTINCT valve_name FROM blocked_client_events WHERE server_id IN (");
		for (int i = 0; i < serverIds.size(); i++) {
			sql.append(i > 0 ? ",?" : "?");
		}
		sql.append(") ORDER BY valve_name ASC");
		return jdbcTemplate.query(sql.toString(), (rs, rowNum) -> rs.getString(1), serverIds.toArray());
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

	public List<BlockedClientEvent> findPendingEnrichment(int limit) {
		String sql = "SELECT * FROM blocked_client_events WHERE enrichment_status = 'PENDING' ORDER BY id ASC LIMIT ?";
		return jdbcTemplate.query(sql, ROW_MAPPER, limit);
	}

	public void batchUpdateEnrichment(List<BlockedClientEvent> events) {
		if (events == null || events.isEmpty()) {
			return;
		}

		String sql = """
				UPDATE blocked_client_events SET
				    asn = ?,
				    as_org = ?,
				    country_code = ?,
				    client_type = ?,
				    enrichment_status = ?
				WHERE id = ?
				""";

		jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
			@Override
			public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
				BlockedClientEvent e = events.get(i);
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
				return events.size();
			}
		});
	}
}
