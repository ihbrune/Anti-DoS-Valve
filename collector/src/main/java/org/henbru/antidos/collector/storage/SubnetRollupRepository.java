package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.henbru.antidos.collector.model.ClientSubnetRollup;
import org.henbru.antidos.collector.model.ClientType;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for managing aggregated subnet time-bucket rollups.
 */
@Repository
public class SubnetRollupRepository {

	private final JdbcTemplate jdbcTemplate;

	public SubnetRollupRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<ClientSubnetRollup> ROW_MAPPER = (rs, rowNum) -> {
		Long asn = rs.getObject("asn") != null ? rs.getLong("asn") : null;
		String rawClientType = rs.getString("client_type");
		ClientType clientType = rawClientType != null ? ClientType.valueOf(rawClientType) : ClientType.UNKNOWN;

		return new ClientSubnetRollup(
				rs.getLong("id"),
				rs.getTimestamp("bucket_start").toInstant(),
				rs.getTimestamp("bucket_end").toInstant(),
				rs.getInt("bucket_minutes"),
				rs.getString("server_id"),
				rs.getString("valve_name"),
				rs.getString("subnet_group"),
				rs.getLong("total_requests"),
				rs.getLong("active_requests"),
				rs.getLong("blocked_requests"),
				rs.getInt("distinct_clients"),
				rs.getInt("min_requests_per_client"),
				rs.getInt("max_requests_per_client"),
				rs.getInt("slots_active_count"),
				asn,
				rs.getString("as_org"),
				rs.getString("country_code"),
				clientType,
				rs.getTimestamp("created_at").toInstant()
		);
	};

	public void batchUpsert(List<ClientSubnetRollup> rollups) {
		if (rollups == null || rollups.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO client_subnet_rollups (
				    bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
				    total_requests, active_requests, blocked_requests, distinct_clients,
				    min_requests_per_client, max_requests_per_client, slots_active_count,
				    asn, as_org, country_code, client_type
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (bucket_start, server_id, valve_name, subnet_group) DO UPDATE SET
				    bucket_end = EXCLUDED.bucket_end,
				    bucket_minutes = EXCLUDED.bucket_minutes,
				    total_requests = EXCLUDED.total_requests,
				    active_requests = EXCLUDED.active_requests,
				    blocked_requests = EXCLUDED.blocked_requests,
				    distinct_clients = EXCLUDED.distinct_clients,
				    min_requests_per_client = EXCLUDED.min_requests_per_client,
				    max_requests_per_client = EXCLUDED.max_requests_per_client,
				    slots_active_count = EXCLUDED.slots_active_count,
				    asn = COALESCE(EXCLUDED.asn, client_subnet_rollups.asn),
				    as_org = COALESCE(EXCLUDED.as_org, client_subnet_rollups.as_org),
				    country_code = COALESCE(EXCLUDED.country_code, client_subnet_rollups.country_code),
				    client_type = EXCLUDED.client_type
				""";

		jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
			@Override
			public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
				ClientSubnetRollup r = rollups.get(i);
				ps.setTimestamp(1, Timestamp.from(r.bucketStart()));
				ps.setTimestamp(2, Timestamp.from(r.bucketEnd()));
				ps.setInt(3, r.bucketMinutes());
				ps.setString(4, r.serverId());
				ps.setString(5, r.valveName());
				ps.setString(6, r.subnetGroup());
				ps.setLong(7, r.totalRequests());
				ps.setLong(8, r.activeRequests());
				ps.setLong(9, r.blockedRequests());
				ps.setInt(10, r.distinctClients());
				ps.setInt(11, r.minRequestsPerClient());
				ps.setInt(12, r.maxRequestsPerClient());
				ps.setInt(13, r.slotsActiveCount());

				if (r.asn() != null) {
					ps.setLong(14, r.asn());
				} else {
					ps.setNull(14, Types.BIGINT);
				}
				ps.setString(15, r.asOrg());
				ps.setString(16, r.countryCode());
				ps.setString(17, r.clientType() != null ? r.clientType().name() : ClientType.UNKNOWN.name());
			}

			@Override
			public int getBatchSize() {
				return rollups.size();
			}
		});
	}

	public List<ClientSubnetRollup> findRollupsFiltered(
			List<String> servers,
			List<String> valves,
			Instant from,
			Instant to,
			String subnetQuery,
			Long asn,
			List<String> clientTypes,
			int limit,
			int offset
	) {
		StringBuilder sql = new StringBuilder("SELECT * FROM client_subnet_rollups WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		appendFilterConditions(sql, params, servers, valves, from, to, subnetQuery, asn, clientTypes);

		sql.append(" ORDER BY bucket_start DESC, total_requests DESC LIMIT ? OFFSET ?");
		params.add(limit);
		params.add(offset);

		return jdbcTemplate.query(sql.toString(), ROW_MAPPER, params.toArray());
	}

	public long countRollupsFiltered(
			List<String> servers,
			List<String> valves,
			Instant from,
			Instant to,
			String subnetQuery,
			Long asn,
			List<String> clientTypes
	) {
		StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM client_subnet_rollups WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		appendFilterConditions(sql, params, servers, valves, from, to, subnetQuery, asn, clientTypes);

		Long count = jdbcTemplate.queryForObject(sql.toString(), Long.class, params.toArray());
		return count != null ? count : 0L;
	}

	public Optional<Instant> findLatestBucketEnd(String serverId, String valveName) {
		String sql = "SELECT MAX(bucket_end) FROM client_subnet_rollups WHERE server_id = ? AND valve_name = ?";
		Timestamp ts = jdbcTemplate.queryForObject(sql, Timestamp.class, serverId, valveName);
		return ts != null ? Optional.of(ts.toInstant()) : Optional.empty();
	}

	public int deleteOlderThan(Instant cutoff) {
		String sql = "DELETE FROM client_subnet_rollups WHERE bucket_start < ?";
		return jdbcTemplate.update(sql, Timestamp.from(cutoff));
	}

	private void appendFilterConditions(
			StringBuilder sql,
			List<Object> params,
			List<String> servers,
			List<String> valves,
			Instant from,
			Instant to,
			String subnetQuery,
			Long asn,
			List<String> clientTypes
	) {
		if (servers != null && !servers.isEmpty()) {
			sql.append(" AND server_id IN (")
					.append(String.join(",", Collections.nCopies(servers.size(), "?")))
					.append(")");
			params.addAll(servers);
		}
		if (valves != null && !valves.isEmpty()) {
			sql.append(" AND valve_name IN (")
					.append(String.join(",", Collections.nCopies(valves.size(), "?")))
					.append(")");
			params.addAll(valves);
		}
		if (from != null) {
			sql.append(" AND bucket_start >= ?");
			params.add(Timestamp.from(from));
		}
		if (to != null) {
			sql.append(" AND bucket_start <= ?");
			params.add(Timestamp.from(to));
		}
		if (subnetQuery != null && !subnetQuery.trim().isEmpty()) {
			sql.append(" AND subnet_group LIKE ?");
			params.add("%" + subnetQuery.trim() + "%");
		}
		if (asn != null) {
			sql.append(" AND asn = ?");
			params.add(asn);
		}
		if (clientTypes != null && !clientTypes.isEmpty()) {
			sql.append(" AND client_type IN (")
					.append(String.join(",", Collections.nCopies(clientTypes.size(), "?")))
					.append(")");
			params.addAll(clientTypes);
		}
	}
}
