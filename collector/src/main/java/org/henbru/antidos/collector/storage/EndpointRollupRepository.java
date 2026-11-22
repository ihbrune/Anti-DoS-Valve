package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.henbru.antidos.collector.model.EndpointRollup;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for persisting and querying aggregated endpoint (URI) time-bucket rollups.
 */
@Repository
public class EndpointRollupRepository {

	private final JdbcTemplate jdbcTemplate;

	public EndpointRollupRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<EndpointRollup> ROW_MAPPER = (rs, rowNum) -> new EndpointRollup(
			rs.getLong("id"),
			rs.getTimestamp("bucket_start").toInstant(),
			rs.getString("server_id"),
			rs.getString("valve_name"),
			rs.getString("clean_endpoint"),
			rs.getString("sample_method"),
			rs.getLong("total_requests"),
			rs.getLong("blocked_requests"),
			rs.getLong("marked_requests"),
			rs.getLong("active_requests"),
			rs.getLong("authenticated_requests"),
			rs.getLong("internal_requests"),
			rs.getLong("crawler_requests"),
			rs.getInt("distinct_clients"),
			rs.getInt("distinct_subnets"),
			rs.getInt("distinct_user_agents"),
			rs.getInt("auth_samples"),
			rs.getInt("returning_samples")
	);

	/**
	 * Persists a list of aggregated endpoint rollups using an atomic upsert.
	 *
	 * @param rollups List of rollups to insert or update
	 */
	public void batchUpsert(List<EndpointRollup> rollups) {
		if (rollups == null || rollups.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO endpoint_rollups (
				    bucket_start, server_id, valve_name, clean_endpoint, sample_method,
				    total_requests, blocked_requests, marked_requests, active_requests,
				    authenticated_requests, internal_requests, crawler_requests,
				    distinct_clients, distinct_subnets, distinct_user_agents,
				    auth_samples, returning_samples
				)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (bucket_start, server_id, valve_name, clean_endpoint, sample_method) DO UPDATE SET
				    total_requests = EXCLUDED.total_requests,
				    blocked_requests = EXCLUDED.blocked_requests,
				    marked_requests = EXCLUDED.marked_requests,
				    active_requests = EXCLUDED.active_requests,
				    authenticated_requests = EXCLUDED.authenticated_requests,
				    internal_requests = EXCLUDED.internal_requests,
				    crawler_requests = EXCLUDED.crawler_requests,
				    distinct_clients = EXCLUDED.distinct_clients,
				    distinct_subnets = EXCLUDED.distinct_subnets,
				    distinct_user_agents = EXCLUDED.distinct_user_agents,
				    auth_samples = EXCLUDED.auth_samples,
				    returning_samples = EXCLUDED.returning_samples
				""";

		int batchChunkSize = 500;
		for (int from = 0; from < rollups.size(); from += batchChunkSize) {
			int to = Math.min(from + batchChunkSize, rollups.size());
			List<EndpointRollup> chunk = rollups.subList(from, to);
			StorageRetryUtil.executeWithRetry("EndpointRollupRepository.batchUpsert", () -> {
				jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
					@Override
					public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
						EndpointRollup r = chunk.get(i);
						ps.setTimestamp(1, Timestamp.from(r.bucketStart()));
						ps.setString(2, r.serverId() != null ? r.serverId() : "ALL");
						ps.setString(3, r.valveName() != null ? r.valveName() : "ALL");
						ps.setString(4, r.cleanEndpoint());
						ps.setString(5, r.sampleMethod() != null ? r.sampleMethod() : "GET");
						ps.setLong(6, r.totalRequests());
						ps.setLong(7, r.blockedRequests());
						ps.setLong(8, r.markedRequests());
						ps.setLong(9, r.activeRequests());
						ps.setLong(10, r.authenticatedRequests());
						ps.setLong(11, r.internalRequests());
						ps.setLong(12, r.crawlerRequests());
						ps.setInt(13, r.distinctClients());
						ps.setInt(14, r.distinctSubnets());
						ps.setInt(15, r.distinctUserAgents());
						ps.setInt(16, r.authSamples());
						ps.setInt(17, r.returningSamples());
					}

					@Override
					public int getBatchSize() {
						return chunk.size();
					}
				});
				return null;
			});
		}
	}

	/**
	 * Deletes endpoint rollup records older than the specified cutoff timestamp.
	 *
	 * @param cutoff Oldest timestamp to retain
	 * @return Number of deleted rows
	 */
	public int deleteOlderThan(Instant cutoff) {
		if (cutoff == null) {
			return 0;
		}
		return StorageRetryUtil.executeWithRetry("EndpointRollupRepository.deleteOlderThan", () -> {
			String sql = "DELETE FROM endpoint_rollups WHERE bucket_start < ?";
			return jdbcTemplate.update(sql, Timestamp.from(cutoff));
		});
	}

	/**
	 * Aggregated summary record for an endpoint over a queried time window.
	 */
	public record EndpointSummary(
			String cleanEndpoint,
			String sampleMethod,
			long totalRequests,
			long blockedRequests,
			long markedRequests,
			long activeRequests,
			long authenticatedRequests,
			long internalRequests,
			long crawlerRequests,
			int distinctClients,
			int distinctSubnets,
			int distinctUserAgents,
			int authSamples,
			int returningSamples
	) {
		public double internalRatioPct() {
			return totalRequests > 0 ? Math.round((internalRequests * 1000.0) / totalRequests) / 10.0 : 0.0;
		}

		public double authRatioPct() {
			return totalRequests > 0 ? Math.round((authenticatedRequests * 1000.0) / totalRequests) / 10.0 : 0.0;
		}

		public double blockedRatioPct() {
			return totalRequests > 0 ? Math.round((blockedRequests * 1000.0) / totalRequests) / 10.0 : 0.0;
		}
	}

	/**
	 * Finds top endpoints from aggregated rollups in the given time window.
	 */
	public List<EndpointSummary> findTopEndpoints(
			Instant fromTime,
			Instant toTime,
			List<String> servers,
			List<String> valves,
			boolean excludeInternal,
			String statusFilter,
			int limit
	) {
		StringBuilder sql = new StringBuilder("""
				SELECT
				    clean_endpoint,
				    sample_method,
				    SUM(total_requests) AS total_requests,
				    SUM(blocked_requests) AS blocked_requests,
				    SUM(marked_requests) AS marked_requests,
				    SUM(active_requests) AS active_requests,
				    SUM(authenticated_requests) AS authenticated_requests,
				    SUM(internal_requests) AS internal_requests,
				    SUM(crawler_requests) AS crawler_requests,
				    MAX(distinct_clients) AS distinct_clients,
				    MAX(distinct_subnets) AS distinct_subnets,
				    MAX(distinct_user_agents) AS distinct_user_agents,
				    SUM(auth_samples) AS auth_samples,
				    SUM(returning_samples) AS returning_samples
				FROM endpoint_rollups
				WHERE bucket_start >= ? AND bucket_start < ?
				""");

		List<Object> params = new ArrayList<>();
		params.add(Timestamp.from(fromTime));
		params.add(Timestamp.from(toTime));

		if (servers != null && !servers.isEmpty()) {
			sql.append(" AND server_id IN (").append(String.join(",", Collections.nCopies(servers.size(), "?"))).append(")");
			params.addAll(servers);
		}
		if (valves != null && !valves.isEmpty()) {
			sql.append(" AND valve_name IN (").append(String.join(",", Collections.nCopies(valves.size(), "?"))).append(")");
			params.addAll(valves);
		}

		sql.append(" GROUP BY clean_endpoint, sample_method");

		// Filter clauses
		if (excludeInternal) {
			// Having filter: exclude endpoints where >= 90% requests are internal
			sql.append(" HAVING (SUM(internal_requests) * 1.0 / NULLIF(SUM(total_requests), 0)) < 0.90");
		}

		String orderCol = "total_requests";
		if ("BLOCKED".equalsIgnoreCase(statusFilter)) {
			sql.append(excludeInternal ? " AND SUM(blocked_requests) > 0" : " HAVING SUM(blocked_requests) > 0");
			orderCol = "blocked_requests";
		} else if ("MARKED".equalsIgnoreCase(statusFilter)) {
			sql.append(excludeInternal ? " AND SUM(marked_requests) > 0" : " HAVING SUM(marked_requests) > 0");
			orderCol = "marked_requests";
		} else if ("ACTIVE".equalsIgnoreCase(statusFilter)) {
			orderCol = "active_requests";
		}

		sql.append(" ORDER BY ").append(orderCol).append(" DESC LIMIT ?");
		params.add(Math.max(1, limit));

		return StorageRetryUtil.executeWithRetry("EndpointRollupRepository.findTopEndpoints", () ->
				jdbcTemplate.query(sql.toString(), (rs, rowNum) -> new EndpointSummary(
						rs.getString("clean_endpoint"),
						rs.getString("sample_method"),
						rs.getLong("total_requests"),
						rs.getLong("blocked_requests"),
						rs.getLong("marked_requests"),
						rs.getLong("active_requests"),
						rs.getLong("authenticated_requests"),
						rs.getLong("internal_requests"),
						rs.getLong("crawler_requests"),
						rs.getInt("distinct_clients"),
						rs.getInt("distinct_subnets"),
						rs.getInt("distinct_user_agents"),
						rs.getInt("auth_samples"),
						rs.getInt("returning_samples")
				), params.toArray())
		);
	}
}
