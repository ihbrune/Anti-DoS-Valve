package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.henbru.antidos.collector.model.UaMitigationRollup;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for persisting and querying aggregated dynamic User-Agent mitigation rollups.
 */
@Repository
public class UaMitigationRollupRepository {

	private final JdbcTemplate jdbcTemplate;

	public UaMitigationRollupRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<UaMitigationRollup> ROW_MAPPER = (rs, rowNum) -> new UaMitigationRollup(
			rs.getLong("id"),
			rs.getTimestamp("bucket_start").toInstant(),
			rs.getString("server_id"),
			rs.getString("valve_name"),
			rs.getLong("total_requests"),
			rs.getLong("blocked_requests"),
			rs.getLong("marked_requests"),
			rs.getInt("distinct_ua_rules"),
			rs.getTimestamp("created_at").toInstant()
	);

	/**
	 * Persists a list of aggregated User-Agent mitigation rollups using an atomic upsert.
	 *
	 * @param rollups List of rollups to insert or update
	 */
	public void batchUpsert(List<UaMitigationRollup> rollups) {
		if (rollups == null || rollups.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO ua_mitigation_rollups (
				    bucket_start, server_id, valve_name,
				    total_requests, blocked_requests, marked_requests, distinct_ua_rules, created_at
				)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (bucket_start, server_id, valve_name) DO UPDATE SET
				    total_requests = EXCLUDED.total_requests,
				    blocked_requests = EXCLUDED.blocked_requests,
				    marked_requests = EXCLUDED.marked_requests,
				    distinct_ua_rules = EXCLUDED.distinct_ua_rules,
				    created_at = EXCLUDED.created_at
				""";

		int batchChunkSize = 500;
		for (int from = 0; from < rollups.size(); from += batchChunkSize) {
			int to = Math.min(from + batchChunkSize, rollups.size());
			List<UaMitigationRollup> chunk = rollups.subList(from, to);
			StorageRetryUtil.executeWithRetry("UaMitigationRollupRepository.batchUpsert", () -> {
				jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
					@Override
					public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
						UaMitigationRollup r = chunk.get(i);
						ps.setTimestamp(1, Timestamp.from(r.bucketStart()));
						ps.setString(2, r.serverId() != null ? r.serverId() : "ALL");
						ps.setString(3, r.valveName() != null ? r.valveName() : "ALL");
						ps.setLong(4, r.totalRequests());
						ps.setLong(5, r.blockedRequests());
						ps.setLong(6, r.markedRequests());
						ps.setInt(7, r.distinctUaRules());
						ps.setTimestamp(8, Timestamp.from(r.createdAt() != null ? r.createdAt() : Instant.now()));
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
	 * Deletes User-Agent mitigation rollup records older than the specified cutoff timestamp.
	 *
	 * @param cutoff Oldest timestamp to retain
	 * @return Number of deleted rows
	 */
	public int deleteOlderThan(Instant cutoff) {
		if (cutoff == null) {
			return 0;
		}
		return StorageRetryUtil.executeWithRetry("UaMitigationRollupRepository.deleteOlderThan", () -> {
			String sql = "DELETE FROM ua_mitigation_rollups WHERE bucket_start < ?";
			return jdbcTemplate.update(sql, Timestamp.from(cutoff));
		});
	}

	public record UaTimelinePoint(
			Instant bucketStart,
			long totalRequests,
			long blockedRequests,
			long markedRequests,
			int distinctUaRules
	) {}

	/**
	 * Finds aggregated timeline points for UA mitigations within the specified filter criteria.
	 */
	public List<UaTimelinePoint> findTimeline(
			List<String> servers,
			List<String> valves,
			Instant from,
			Instant to
	) {
		StringBuilder sql = new StringBuilder("""
				SELECT
				    bucket_start,
				    SUM(total_requests) AS total_reqs,
				    SUM(blocked_requests) AS blocked_reqs,
				    SUM(marked_requests) AS marked_reqs,
				    MAX(distinct_ua_rules) AS max_ua_rules
				FROM ua_mitigation_rollups
				WHERE 1=1
				""");
		List<Object> params = new ArrayList<>();
		appendFilterConditions(sql, params, servers, valves, from, to);
		sql.append(" GROUP BY bucket_start ORDER BY bucket_start ASC");

		return jdbcTemplate.query(Objects.requireNonNull(sql.toString()), (rs, rowNum) -> new UaTimelinePoint(
				rs.getTimestamp("bucket_start").toInstant(),
				rs.getLong("total_reqs"),
				rs.getLong("blocked_reqs"),
				rs.getLong("marked_reqs"),
				rs.getInt("max_ua_rules")
		), params.toArray());
	}

	public record UaRollupSummary(
			long totalRequests,
			long blockedRequests,
			long markedRequests,
			int distinctUaRules
	) {}

	/**
	 * Computes overall total requests and blocked requests across the queried window.
	 */
	public UaRollupSummary findSummary(
			List<String> servers,
			List<String> valves,
			Instant from,
			Instant to
	) {
		StringBuilder sql = new StringBuilder("""
				SELECT
				    COALESCE(SUM(total_requests), 0) AS total_reqs,
				    COALESCE(SUM(blocked_requests), 0) AS blocked_reqs,
				    COALESCE(SUM(marked_requests), 0) AS marked_reqs,
				    COALESCE(MAX(distinct_ua_rules), 0) AS max_ua_rules
				FROM ua_mitigation_rollups
				WHERE 1=1
				""");
		List<Object> params = new ArrayList<>();
		appendFilterConditions(sql, params, servers, valves, from, to);

		List<UaRollupSummary> list = jdbcTemplate.query(Objects.requireNonNull(sql.toString()), (rs, rowNum) -> new UaRollupSummary(
				rs.getLong("total_reqs"),
				rs.getLong("blocked_reqs"),
				rs.getLong("marked_reqs"),
				rs.getInt("max_ua_rules")
		), params.toArray());

		return list.isEmpty() ? new UaRollupSummary(0L, 0L, 0L, 0) : list.getFirst();
	}

	private void appendFilterConditions(
			StringBuilder sql,
			List<Object> params,
			List<String> servers,
			List<String> valves,
			Instant from,
			Instant to
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
			sql.append(" AND bucket_start < ?");
			params.add(Timestamp.from(to));
		}
	}
}
