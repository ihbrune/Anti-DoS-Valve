package org.henbru.antidos.collector.storage;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.SubnetProfile;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository managing subnet frequency baselines, first-seen/dormancy tracking,
 * and surge metrics.
 */
@Repository
public class SubnetProfileRepository {

	private final JdbcTemplate jdbcTemplate;

	public SubnetProfileRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@NonNull
	private static final RowMapper<SubnetProfile> ROW_MAPPER = (rs, rowNum) -> {
		Long asn = rs.getObject("asn") != null ? rs.getLong("asn") : null;
		String rawClientType = rs.getString("client_type");
		ClientType clientType = rawClientType != null ? ClientType.valueOf(rawClientType) : ClientType.UNKNOWN;

		return new SubnetProfile(
				rs.getString("subnet_group"),
				rs.getTimestamp("first_seen_at").toInstant(),
				rs.getTimestamp("last_seen_at").toInstant(),
				rs.getInt("days_dormant_before_last_seen"),
				rs.getLong("total_lifetime_requests"),
				rs.getLong("total_active_requests"),
				rs.getLong("total_blocked_requests"),
				rs.getDouble("baseline_daily_avg"),
				rs.getInt("baseline_distinct_clients"),
				rs.getLong("peak_daily_requests"),
				rs.getLong("last_24h_requests"),
				rs.getInt("last_24h_distinct_clients"),
				rs.getLong("last_24h_blocked_requests"),
				rs.getDouble("last_24h_surge_factor"),
				asn,
				rs.getString("as_org"),
				rs.getString("country_code"),
				clientType,
				rs.getTimestamp("updated_at").toInstant()
		);
	};

	public void batchUpsert(List<SubnetProfile> profiles) {
		if (profiles == null || profiles.isEmpty()) {
			return;
		}

		String sql = """
				INSERT INTO subnet_profiles (
				    subnet_group, first_seen_at, last_seen_at, days_dormant_before_last_seen,
				    total_lifetime_requests, total_active_requests, total_blocked_requests,
				    baseline_daily_avg, baseline_distinct_clients, peak_daily_requests,
				    last_24h_requests, last_24h_distinct_clients, last_24h_blocked_requests,
				    last_24h_surge_factor, asn, as_org, country_code, client_type, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (subnet_group) DO UPDATE SET
				    first_seen_at = CASE WHEN subnet_profiles.first_seen_at < EXCLUDED.first_seen_at THEN subnet_profiles.first_seen_at ELSE EXCLUDED.first_seen_at END,
				    last_seen_at = EXCLUDED.last_seen_at,
				    days_dormant_before_last_seen = EXCLUDED.days_dormant_before_last_seen,
				    total_lifetime_requests = EXCLUDED.total_lifetime_requests,
				    total_active_requests = EXCLUDED.total_active_requests,
				    total_blocked_requests = EXCLUDED.total_blocked_requests,
				    baseline_daily_avg = EXCLUDED.baseline_daily_avg,
				    baseline_distinct_clients = EXCLUDED.baseline_distinct_clients,
				    peak_daily_requests = EXCLUDED.peak_daily_requests,
				    last_24h_requests = EXCLUDED.last_24h_requests,
				    last_24h_distinct_clients = EXCLUDED.last_24h_distinct_clients,
				    last_24h_blocked_requests = EXCLUDED.last_24h_blocked_requests,
				    last_24h_surge_factor = EXCLUDED.last_24h_surge_factor,
				    asn = COALESCE(EXCLUDED.asn, subnet_profiles.asn),
				    as_org = COALESCE(EXCLUDED.as_org, subnet_profiles.as_org),
				    country_code = COALESCE(EXCLUDED.country_code, subnet_profiles.country_code),
				    client_type = EXCLUDED.client_type,
				    updated_at = EXCLUDED.updated_at
				""";

		jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
			@Override
			public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
				SubnetProfile p = profiles.get(i);
				ps.setString(1, p.subnetGroup());
				ps.setTimestamp(2, Timestamp.from(p.firstSeenAt()));
				ps.setTimestamp(3, Timestamp.from(p.lastSeenAt()));
				ps.setInt(4, p.daysDormantBeforeLastSeen());
				ps.setLong(5, p.totalLifetimeRequests());
				ps.setLong(6, p.totalActiveRequests());
				ps.setLong(7, p.totalBlockedRequests());
				ps.setDouble(8, p.baselineDailyAvg());
				ps.setInt(9, p.baselineDistinctClients());
				ps.setLong(10, p.peakDailyRequests());
				ps.setLong(11, p.last24hRequests());
				ps.setInt(12, p.last24hDistinctClients());
				ps.setLong(13, p.last24hBlockedRequests());
				ps.setDouble(14, p.last24hSurgeFactor());

				if (p.asn() != null) {
					ps.setLong(15, p.asn());
				} else {
					ps.setNull(15, Types.BIGINT);
				}
				ps.setString(16, p.asOrg());
				ps.setString(17, p.countryCode());
				ps.setString(18, p.clientType() != null ? p.clientType().name() : ClientType.UNKNOWN.name());
				ps.setTimestamp(19, Timestamp.from(p.updatedAt() != null ? p.updatedAt() : Instant.now()));
			}

			@Override
			public int getBatchSize() {
				return profiles.size();
			}
		});
	}

	public Optional<SubnetProfile> findBySubnetGroup(String subnetGroup) {
		if (subnetGroup == null || subnetGroup.isBlank()) {
			return Optional.empty();
		}
		String sql = "SELECT * FROM subnet_profiles WHERE subnet_group = ?";
		List<SubnetProfile> list = jdbcTemplate.query(sql, ROW_MAPPER, subnetGroup.trim());
		return list.isEmpty() ? Optional.empty() : Optional.of(list.getFirst());
	}

	public Map<String, SubnetProfile> findSubnetProfilesMap(List<String> subnetGroups) {
		if (subnetGroups == null || subnetGroups.isEmpty()) {
			return Map.of();
		}
		String placeholders = String.join(",", Collections.nCopies(subnetGroups.size(), "?"));
		String sql = "SELECT * FROM subnet_profiles WHERE subnet_group IN (" + placeholders + ")";
		List<SubnetProfile> list = jdbcTemplate.query(sql, ROW_MAPPER, subnetGroups.toArray());
		Map<String, SubnetProfile> map = new HashMap<>();
		for (SubnetProfile p : list) {
			map.put(p.subnetGroup(), p);
		}
		return map;
	}

	public List<SubnetProfile> findProfilesFiltered(
			String activityPattern,
			Long minRequests24h,
			String subnetQuery,
			Long asn,
			String asOrg,
			List<String> clientTypes,
			String sortBy,
			int limit,
			int offset
	) {
		StringBuilder sql = new StringBuilder("SELECT * FROM subnet_profiles WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		appendFilterConditions(sql, params, activityPattern, minRequests24h, subnetQuery, asn, asOrg, clientTypes);

		String orderClause = switch (sortBy != null ? sortBy.toUpperCase() : "SURGE") {
			case "REQUESTS" -> "last_24h_requests DESC, last_24h_surge_factor DESC";
			case "DORMANT" -> "days_dormant_before_last_seen DESC, last_24h_requests DESC";
			case "FIRST_SEEN" -> "first_seen_at DESC";
			case "LAST_SEEN" -> "last_seen_at DESC";
			case "DISTINCT_IPS" -> "last_24h_distinct_clients DESC, last_24h_requests DESC";
			default -> "last_24h_surge_factor DESC, last_24h_requests DESC";
		};

		sql.append(" ORDER BY ").append(orderClause).append(" LIMIT ? OFFSET ?");
		params.add(limit);
		params.add(offset);

		return jdbcTemplate.query(Objects.requireNonNull(sql.toString()), ROW_MAPPER, params.toArray());
	}

	public long countProfilesFiltered(
			String activityPattern,
			Long minRequests24h,
			String subnetQuery,
			Long asn,
			String asOrg,
			List<String> clientTypes
	) {
		StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM subnet_profiles WHERE 1=1 ");
		List<Object> params = new ArrayList<>();

		appendFilterConditions(sql, params, activityPattern, minRequests24h, subnetQuery, asn, asOrg, clientTypes);

		Long count = jdbcTemplate.queryForObject(Objects.requireNonNull(sql.toString()), Long.class, params.toArray());
		return count != null ? count : 0L;
	}

	public org.henbru.antidos.collector.model.SubnetProfileStats getProfileStats() {
		Instant sevenDaysAgo = Instant.now().minus(7, ChronoUnit.DAYS);
		String sql = """
				SELECT
				    COUNT(*) AS total_count,
				    COUNT(CASE WHEN last_24h_requests > 0 THEN 1 END) AS active_24h,
				    COUNT(CASE WHEN last_24h_requests > 0 AND last_24h_surge_factor >= 5.0 THEN 1 END) AS high_surge,
				    COUNT(CASE WHEN last_24h_requests > 0 AND (days_dormant_before_last_seen >= 900 OR first_seen_at >= ?) THEN 1 END) AS new_subnets,
				    COUNT(CASE WHEN last_24h_requests > 0 AND days_dormant_before_last_seen >= 14 AND days_dormant_before_last_seen < 900 THEN 1 END) AS dormant_breaks,
				    COUNT(CASE WHEN last_24h_requests > 0 AND last_24h_distinct_clients >= 5 AND (last_24h_requests * 1.0 / CASE WHEN last_24h_distinct_clients = 0 THEN 1 ELSE last_24h_distinct_clients END) <= 20.0 THEN 1 END) AS proxy_pools
				FROM subnet_profiles
				""";
		try {
			return jdbcTemplate.queryForObject(sql, (rs, rowNum) -> new org.henbru.antidos.collector.model.SubnetProfileStats(
					rs.getLong("total_count"),
					rs.getLong("active_24h"),
					rs.getLong("high_surge"),
					rs.getLong("new_subnets"),
					rs.getLong("dormant_breaks"),
					rs.getLong("proxy_pools")
			), Timestamp.from(sevenDaysAgo));
		} catch (Exception e) {
			return org.henbru.antidos.collector.model.SubnetProfileStats.empty();
		}
	}

	/**
	 * Computes and returns updated subnet profiles from historical rollups looking back up to 30 days.
	 */
	public List<SubnetProfile> computeProfilesFromRollups(Instant cutoff24h, Instant cutoff30d) {
		String sql = """
				SELECT
				    subnet_group,
				    MIN(bucket_start) AS first_seen,
				    MAX(bucket_end) AS last_seen,
				    SUM(total_requests) AS total_lifetime_requests,
				    SUM(active_requests) AS total_active_requests,
				    SUM(blocked_requests) AS total_blocked_requests,
				    MAX(distinct_clients) AS max_distinct_clients,
				    SUM(CASE WHEN bucket_start >= ? THEN total_requests ELSE 0 END) AS req_24h,
				    SUM(CASE WHEN bucket_start >= ? THEN active_requests ELSE 0 END) AS active_24h,
				    SUM(CASE WHEN bucket_start >= ? THEN blocked_requests ELSE 0 END) AS blocked_24h,
				    MAX(CASE WHEN bucket_start >= ? THEN distinct_clients ELSE 0 END) AS distinct_24h,
				    SUM(CASE WHEN bucket_start < ? THEN total_requests ELSE 0 END) AS req_prior,
				    MAX(CASE WHEN bucket_start < ? THEN bucket_end ELSE NULL END) AS last_seen_prior,
				    MIN(CASE WHEN bucket_start >= ? THEN bucket_start ELSE NULL END) AS first_seen_current,
				    MAX(asn) AS asn,
				    MAX(as_org) AS as_org,
				    MAX(country_code) AS country_code,
				    MAX(client_type) AS client_type
				FROM client_subnet_rollups
				WHERE bucket_start >= ?
				GROUP BY subnet_group
				""";

		Timestamp ts24h = Timestamp.from(cutoff24h);
		Timestamp ts30d = Timestamp.from(cutoff30d);

		return jdbcTemplate.query(sql, (rs, rowNum) -> {
			String subnetGroup = rs.getString("subnet_group");
			Instant firstSeen = rs.getTimestamp("first_seen").toInstant();
			Instant lastSeen = rs.getTimestamp("last_seen").toInstant();
			long totalReqs = rs.getLong("total_lifetime_requests");
			long totalActive = rs.getLong("total_active_requests");
			long totalBlocked = rs.getLong("total_blocked_requests");
			int maxClients = rs.getInt("max_distinct_clients");

			long req24h = rs.getLong("req_24h");
			long active24h = rs.getLong("active_24h");
			long blocked24h = rs.getLong("blocked_24h");
			int distinct24h = rs.getInt("distinct_24h");

			long reqPrior = rs.getLong("req_prior");
			Timestamp tsPrior = rs.getTimestamp("last_seen_prior");
			Timestamp tsCurrent = rs.getTimestamp("first_seen_current");

			int daysDormant = 0;
			if (tsPrior != null && tsCurrent != null) {
				daysDormant = (int) ChronoUnit.DAYS.between(tsPrior.toInstant(), tsCurrent.toInstant());
			} else if (tsPrior == null && tsCurrent != null) {
				daysDormant = 999; // Brand new within lookback window
			}

			// 29 days of prior lookback
			double baselineDailyAvg = reqPrior > 0 ? (double) reqPrior / 29.0 : 0.0;
			double surgeFactor;
			if (baselineDailyAvg > 0.0) {
				surgeFactor = Math.round(((double) req24h / baselineDailyAvg) * 10.0) / 10.0;
			} else if (req24h > 0) {
				surgeFactor = (double) req24h; // Spike from zero
			} else {
				surgeFactor = 1.0;
			}

			long peakDaily = Math.max(req24h, (long) Math.ceil(baselineDailyAvg));

			Long asnVal = rs.getObject("asn") != null ? rs.getLong("asn") : null;
			String rawType = rs.getString("client_type");
			ClientType clientType = rawType != null ? ClientType.valueOf(rawType) : ClientType.UNKNOWN;

			return new SubnetProfile(
					subnetGroup,
					firstSeen,
					lastSeen,
					daysDormant,
					totalReqs,
					totalActive,
					totalBlocked,
					Math.round(baselineDailyAvg * 10.0) / 10.0,
					maxClients,
					peakDaily,
					req24h,
					distinct24h,
					blocked24h,
					surgeFactor,
					asnVal,
					rs.getString("as_org"),
					rs.getString("country_code"),
					clientType,
					Instant.now()
			);
		}, ts24h, ts24h, ts24h, ts24h, ts24h, ts24h, ts24h, ts30d);
	}

	private void appendFilterConditions(
			StringBuilder sql,
			List<Object> params,
			String activityPattern,
			Long minRequests24h,
			String subnetQuery,
			Long asn,
			String asOrg,
			List<String> clientTypes
	) {
		if (activityPattern != null && !activityPattern.isBlank() && !"ALL".equalsIgnoreCase(activityPattern.trim())) {
			switch (activityPattern.trim().toUpperCase()) {
				case "NEW" -> {
					sql.append(" AND last_24h_requests > 0 AND (days_dormant_before_last_seen >= 900 OR first_seen_at >= ?)");
					params.add(Timestamp.from(Instant.now().minus(7, ChronoUnit.DAYS)));
				}
				case "DORMANT" -> sql.append(" AND last_24h_requests > 0 AND days_dormant_before_last_seen >= 14 AND days_dormant_before_last_seen < 900");
				case "SURGE" -> sql.append(" AND last_24h_requests > 0 AND last_24h_surge_factor >= 5.0");
				case "PROXY_POOL" -> sql.append(" AND last_24h_requests > 0 AND last_24h_distinct_clients >= 5 AND (last_24h_requests * 1.0 / CASE WHEN last_24h_distinct_clients = 0 THEN 1 ELSE last_24h_distinct_clients END) <= 20.0");
				default -> {}
			}
		}

		if (minRequests24h != null && minRequests24h > 0) {
			sql.append(" AND last_24h_requests >= ?");
			params.add(minRequests24h);
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
