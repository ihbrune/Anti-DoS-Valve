package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
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

		long markedRequests = 0L;
		try {
			markedRequests = rs.getLong("marked_requests");
		} catch (SQLException ignored) {
		}

		long returningRequests = 0L;
		try {
			returningRequests = rs.getLong("returning_requests");
		} catch (SQLException ignored) {
		}

		long returningTrackedRequests = 0L;
		try {
			returningTrackedRequests = rs.getLong("returning_tracked_requests");
		} catch (SQLException ignored) {
		}

		long authenticatedRequests = 0L;
		try {
			authenticatedRequests = rs.getLong("authenticated_requests");
		} catch (SQLException ignored) {
		}

		long authenticatedTrackedRequests = 0L;
		try {
			authenticatedTrackedRequests = rs.getLong("authenticated_tracked_requests");
		} catch (SQLException ignored) {
		}

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
				markedRequests,
				rs.getInt("distinct_clients"),
				rs.getInt("min_requests_per_client"),
				rs.getInt("max_requests_per_client"),
				rs.getInt("slots_active_count"),
				asn,
				rs.getString("as_org"),
				rs.getString("country_code"),
				clientType,
				rs.getTimestamp("created_at").toInstant(),
				returningRequests,
				returningTrackedRequests,
				authenticatedRequests,
				authenticatedTrackedRequests
		);
	};

	public void batchUpsert(List<ClientSubnetRollup> rollups) {
		if (rollups == null || rollups.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO client_subnet_rollups (
				    bucket_start, bucket_end, bucket_minutes, server_id, valve_name, subnet_group,
				    total_requests, active_requests, blocked_requests, marked_requests, distinct_clients,
				    min_requests_per_client, max_requests_per_client, slots_active_count,
				    asn, as_org, country_code, client_type,
				    returning_requests, returning_tracked_requests,
				    authenticated_requests, authenticated_tracked_requests
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (bucket_start, server_id, valve_name, subnet_group) DO UPDATE SET
				    bucket_end = EXCLUDED.bucket_end,
				    bucket_minutes = EXCLUDED.bucket_minutes,
				    total_requests = EXCLUDED.total_requests,
				    active_requests = EXCLUDED.active_requests,
				    blocked_requests = EXCLUDED.blocked_requests,
				    marked_requests = EXCLUDED.marked_requests,
				    distinct_clients = EXCLUDED.distinct_clients,
				    min_requests_per_client = EXCLUDED.min_requests_per_client,
				    max_requests_per_client = EXCLUDED.max_requests_per_client,
				    slots_active_count = EXCLUDED.slots_active_count,
				    asn = COALESCE(EXCLUDED.asn, client_subnet_rollups.asn),
				    as_org = COALESCE(EXCLUDED.as_org, client_subnet_rollups.as_org),
				    country_code = COALESCE(EXCLUDED.country_code, client_subnet_rollups.country_code),
				    client_type = EXCLUDED.client_type,
				    returning_requests = EXCLUDED.returning_requests,
				    returning_tracked_requests = EXCLUDED.returning_tracked_requests,
				    authenticated_requests = EXCLUDED.authenticated_requests,
				    authenticated_tracked_requests = EXCLUDED.authenticated_tracked_requests
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
				ps.setLong(10, r.markedRequests());
				ps.setInt(11, r.distinctClients());
				ps.setInt(12, r.minRequestsPerClient());
				ps.setInt(13, r.maxRequestsPerClient());
				ps.setInt(14, r.slotsActiveCount());

				if (r.asn() != null) {
					ps.setLong(15, r.asn());
				} else {
					ps.setNull(15, Types.BIGINT);
				}
				ps.setString(16, r.asOrg());
				ps.setString(17, r.countryCode());
				ps.setString(18, r.clientType() != null ? r.clientType().name() : ClientType.UNKNOWN.name());
				ps.setLong(19, r.returningRequests());
				ps.setLong(20, r.returningTrackedRequests());
				ps.setLong(21, r.authenticatedRequests());
				ps.setLong(22, r.authenticatedTrackedRequests());
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
			String asOrg,
			List<String> clientTypes,
			int limit,
			int offset
	) {
		StringBuilder sql = new StringBuilder("SELECT * FROM client_subnet_rollups WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		appendFilterConditions(sql, params, servers, valves, from, to, subnetQuery, asn, asOrg, clientTypes);

		sql.append(" ORDER BY bucket_start DESC, total_requests DESC LIMIT ? OFFSET ?");
		params.add(limit);
		params.add(offset);

		return jdbcTemplate.query(Objects.requireNonNull(sql.toString()), ROW_MAPPER, params.toArray());
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
		return findRollupsFiltered(servers, valves, from, to, subnetQuery, asn, null, clientTypes, limit, offset);
	}

	public long countRollupsFiltered(
			List<String> servers,
			List<String> valves,
			Instant from,
			Instant to,
			String subnetQuery,
			Long asn,
			String asOrg,
			List<String> clientTypes
	) {
		StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM client_subnet_rollups WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		appendFilterConditions(sql, params, servers, valves, from, to, subnetQuery, asn, asOrg, clientTypes);

		Long count = jdbcTemplate.queryForObject(Objects.requireNonNull(sql.toString()), Long.class, params.toArray());
		return count != null ? count : 0L;
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
		return countRollupsFiltered(servers, valves, from, to, subnetQuery, asn, null, clientTypes);
	}

	public Optional<Instant> findLatestBucketEnd(String serverId, String valveName) {
		String sql = "SELECT MAX(bucket_end) FROM client_subnet_rollups WHERE server_id = ? AND valve_name = ?";
		Timestamp ts = jdbcTemplate.queryForObject(sql, Timestamp.class, serverId, valveName);
		return ts != null ? Optional.of(ts.toInstant()) : Optional.empty();
	}

	public Optional<Instant> findLatestBucketEnd() {
		String sql = "SELECT MAX(bucket_end) FROM client_subnet_rollups";
		Timestamp ts = jdbcTemplate.queryForObject(sql, Timestamp.class);
		return ts != null ? Optional.of(ts.toInstant()) : Optional.empty();
	}

	public Optional<Instant> findEarliestBucketStart() {
		String sql = "SELECT MIN(bucket_start) FROM client_subnet_rollups";
		Timestamp ts = jdbcTemplate.queryForObject(sql, Timestamp.class);
		return ts != null ? Optional.of(ts.toInstant()) : Optional.empty();
	}

	public List<org.henbru.antidos.collector.model.TimelinePoint> findTimeline(
			List<String> servers,
			List<String> valves,
			Instant from,
			Instant to
	) {
		StringBuilder sql = new StringBuilder("""
				SELECT
				    bucket_start,
				    SUM(total_requests) AS total_reqs,
				    SUM(active_requests) AS active_reqs,
				    SUM(blocked_requests) AS blocked_reqs,
				    SUM(COALESCE(marked_requests, 0)) AS marked_reqs
				FROM client_subnet_rollups
				WHERE 1=1
				""");
		List<Object> params = new ArrayList<>();
		appendFilterConditions(sql, params, servers, valves, from, to, null, null, null);
		sql.append(" GROUP BY bucket_start ORDER BY bucket_start ASC");

		return jdbcTemplate.query(Objects.requireNonNull(sql.toString()), (rs, rowNum) -> new org.henbru.antidos.collector.model.TimelinePoint(
				rs.getTimestamp("bucket_start").toInstant(),
				rs.getLong("total_reqs"),
				rs.getLong("active_reqs"),
				rs.getLong("blocked_reqs"),
				rs.getLong("marked_reqs")
		), params.toArray());
	}

	public record RawCompositionRow(
			ClientType clientType,
			long totalRequests,
			long blockedRequests,
			long markedRequests,
			int subnetCount
	) {
		public RawCompositionRow(
				ClientType clientType,
				long totalRequests,
				long blockedRequests,
				int subnetCount
		) {
			this(clientType, totalRequests, blockedRequests, 0L, subnetCount);
		}
	}

	public List<RawCompositionRow> findTrafficComposition(
			List<String> servers,
			List<String> valves,
			Instant from,
			Instant to
	) {
		StringBuilder sql = new StringBuilder("""
				SELECT
				    client_type,
				    SUM(total_requests) AS total_reqs,
				    SUM(blocked_requests) AS blocked_reqs,
				    SUM(COALESCE(marked_requests, 0)) AS marked_reqs,
				    COUNT(DISTINCT subnet_group) AS subnets_cnt
				FROM client_subnet_rollups
				WHERE 1=1
				""");
		List<Object> params = new ArrayList<>();
		appendFilterConditions(sql, params, servers, valves, from, to, null, null, null);
		sql.append(" GROUP BY client_type ORDER BY SUM(total_requests) DESC");

		return jdbcTemplate.query(Objects.requireNonNull(sql.toString()), (rs, rowNum) -> {
			String rawType = rs.getString("client_type");
			ClientType type = rawType != null ? ClientType.valueOf(rawType) : ClientType.UNKNOWN;
			return new RawCompositionRow(
					type,
					rs.getLong("total_reqs"),
					rs.getLong("blocked_reqs"),
					rs.getLong("marked_reqs"),
					rs.getInt("subnets_cnt")
			);
		}, params.toArray());
	}

	public record RawScatterCluster(
			String subnetGroup,
			long totalRequests,
			long activeRequests,
			long blockedRequests,
			long markedRequests,
			int distinctClients,
			Long asn,
			String asOrg,
			String countryCode,
			ClientType clientType,
			long returningRequests,
			long returningTrackedRequests
	) {
		public RawScatterCluster(
				String subnetGroup,
				long totalRequests,
				long activeRequests,
				long blockedRequests,
				int distinctClients,
				Long asn,
				String asOrg,
				String countryCode,
				ClientType clientType
		) {
			this(subnetGroup, totalRequests, activeRequests, blockedRequests, 0L,
					distinctClients, asn, asOrg, countryCode, clientType, 0L, 0L);
		}

		public Double returningRatio() {
			return returningTrackedRequests > 0
					? Math.round((returningRequests * 1000.0) / returningTrackedRequests) / 10.0
					: null;
		}
	}

	public List<RawScatterCluster> findScatterClusters(
			List<String> servers,
			List<String> valves,
			Instant from,
			Instant to,
			int limit
	) {
		StringBuilder sql = new StringBuilder("""
				SELECT
				    subnet_group,
				    SUM(total_requests) AS total_reqs,
				    SUM(active_requests) AS active_reqs,
				    SUM(blocked_requests) AS blocked_reqs,
				    SUM(COALESCE(marked_requests, 0)) AS marked_reqs,
				    MAX(distinct_clients) AS max_distinct_clients,
				    MAX(asn) AS asn,
				    MAX(as_org) AS as_org,
				    MAX(country_code) AS country_code,
				    MAX(client_type) AS client_type,
				    SUM(COALESCE(returning_requests, 0)) AS returning_reqs,
				    SUM(COALESCE(returning_tracked_requests, 0)) AS returning_tracked_reqs
				FROM client_subnet_rollups
				WHERE 1=1
				""");
		List<Object> params = new ArrayList<>();
		appendFilterConditions(sql, params, servers, valves, from, to, null, null, null);
		sql.append(" GROUP BY subnet_group HAVING SUM(total_requests) > 0");
		sql.append(" ORDER BY SUM(blocked_requests) DESC, SUM(COALESCE(marked_requests, 0)) DESC, SUM(total_requests) DESC LIMIT ?");
		params.add(limit);

		return jdbcTemplate.query(Objects.requireNonNull(sql.toString()), (rs, rowNum) -> {
			Long asnVal = rs.getObject("asn") != null ? rs.getLong("asn") : null;
			String rawType = rs.getString("client_type");
			ClientType type = rawType != null ? ClientType.valueOf(rawType) : ClientType.UNKNOWN;
			return new RawScatterCluster(
					rs.getString("subnet_group"),
					rs.getLong("total_reqs"),
					rs.getLong("active_reqs"),
					rs.getLong("blocked_reqs"),
					rs.getLong("marked_reqs"),
					rs.getInt("max_distinct_clients"),
					asnVal,
					rs.getString("as_org"),
					rs.getString("country_code"),
					type,
					rs.getLong("returning_reqs"),
					rs.getLong("returning_tracked_reqs")
			);
		}, params.toArray());
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
		appendFilterConditions(sql, params, servers, valves, from, to, subnetQuery, asn, null, clientTypes);
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
			String asOrg,
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
			sql.append(" AND (subnet_group LIKE ? OR LOWER(as_org) LIKE LOWER(?))");
			params.add("%" + subnetQuery.trim() + "%");
			params.add("%" + subnetQuery.trim() + "%");
		}
		if (asn != null) {
			sql.append(" AND asn = ?");
			params.add(asn);
		} else if (asOrg != null && !asOrg.isBlank()) {
			sql.append(" AND LOWER(as_org) LIKE LOWER(?)");
			params.add("%" + asOrg.trim() + "%");
		}
		if (clientTypes != null && !clientTypes.isEmpty()) {
			sql.append(" AND client_type IN (")
					.append(String.join(",", Collections.nCopies(clientTypes.size(), "?")))
					.append(")");
			params.addAll(clientTypes);
		}
	}
}
