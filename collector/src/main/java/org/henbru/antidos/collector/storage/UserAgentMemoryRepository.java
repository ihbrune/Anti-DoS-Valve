package org.henbru.antidos.collector.storage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.henbru.antidos.collector.model.UserAgentAutoVerdict;
import org.henbru.antidos.collector.model.UserAgentFamily;
import org.henbru.antidos.collector.model.UserAgentHourlyPoint;
import org.henbru.antidos.collector.model.UserAgentManualOverride;
import org.henbru.antidos.collector.model.UserAgentProfile;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository managing long-term User-Agent profiles ({@code dim_user_agent})
 * and hourly evaluation rollups ({@code user_agent_hourly_rollups}).
 */
@Repository
public class UserAgentMemoryRepository {

	private static final int BATCH_CHUNK_SIZE = 250;

	private final JdbcTemplate jdbcTemplate;

	public UserAgentMemoryRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	/**
	 * Computes lowercase SHA-256 hex digest of a normalized (trimmed) User-Agent string.
	 */
	public static String computeSha256Hex(String rawUserAgent) {
		String normalized = rawUserAgent != null ? rawUserAgent.trim() : "";
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(normalized.getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder(digest.length * 2);
			for (byte b : digest) {
				sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
				sb.append(Character.forDigit(b & 0xF, 16));
			}
			return sb.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 not available", e);
		}
	}

	/**
	 * Mirrors {@code AntiDoSVisitorTokenService.computeUserAgentHash32} so Collector profiles
	 * share the exact 32-bit User-Agent hash computed inside the Valve.
	 */
	public static int computeUaHash32(String userAgent) {
		if (userAgent == null || userAgent.isBlank()) {
			return 0;
		}
		String trimmed = userAgent.trim();
		int len = trimmed.length();
		long h = 0x9E3779B97F4A7C15L ^ (len * 0xBF58476D1CE4E5B9L);
		for (int i = 0; i < len; i++) {
			h ^= trimmed.charAt(i);
			h *= 0xBF58476D1CE4E5B9L;
			h ^= (h >>> 31);
		}
		h = (h ^ (h >>> 30)) * 0xBF58476D1CE4E5B9L;
		h = (h ^ (h >>> 27)) * 0x94D049BB133111EBL;
		long res = h ^ (h >>> 31);
		long hash64 = (res == 0L) ? 1L : res;
		return (int) (hash64 ^ (hash64 >>> 32));
	}

	@NonNull
	private static final RowMapper<UserAgentProfile> PROFILE_MAPPER = (rs, rowNum) -> {
		Integer majorVer = rs.getObject("parsed_major_version") != null ? rs.getInt("parsed_major_version") : null;
		Timestamp firstSeen = rs.getTimestamp("first_seen_at");
		Timestamp lastSeen = rs.getTimestamp("last_seen_at");
		Timestamp autoEval = rs.getTimestamp("auto_evaluated_at");
		Timestamp updatedAt = rs.getTimestamp("updated_at");

		UserAgentFamily family;
		try {
			String famRaw = rs.getString("browser_family");
			family = famRaw != null ? UserAgentFamily.valueOf(famRaw) : UserAgentFamily.UNKNOWN;
		} catch (IllegalArgumentException e) {
			family = UserAgentFamily.UNKNOWN;
		}

		return new UserAgentProfile(
				rs.getLong("id"),
				rs.getString("user_agent_hash"),
				rs.getInt("ua_hash_32"),
				rs.getString("raw_user_agent"),
				family,
				majorVer,
				rs.getBoolean("is_bot"),
				firstSeen != null ? firstSeen.toInstant() : Instant.now(),
				lastSeen != null ? lastSeen.toInstant() : Instant.now(),
				rs.getLong("total_lifetime_requests"),
				rs.getLong("total_blocked_requests"),
				rs.getLong("total_marked_requests"),
				rs.getLong("total_authenticated_samples"),
				rs.getLong("total_authenticated_requests"),
				rs.getLong("total_internal_requests"),
				rs.getLong("total_crawler_requests"),
				rs.getLong("last_24h_requests"),
				rs.getInt("last_24h_events"),
				rs.getLong("last_24h_blocked_requests"),
				rs.getLong("last_24h_marked_requests"),
				rs.getInt("last_24h_distinct_subnets"),
				rs.getInt("last_24h_distinct_asns"),
				rs.getInt("last_24h_auth_samples"),
				rs.getLong("last_24h_auth_requests"),
				rs.getLong("last_24h_internal_requests"),
				rs.getLong("last_24h_crawler_requests"),
				rs.getLong("last_24h_datacenter_requests"),
				rs.getLong("last_24h_residential_requests"),
				rs.getLong("last_24h_returning_requests"),
				rs.getLong("last_24h_ua_mismatch_requests"),
				UserAgentAutoVerdict.fromString(rs.getString("auto_verdict")),
				rs.getString("auto_pillar"),
				rs.getString("auto_verdict_reason"),
				autoEval != null ? autoEval.toInstant() : null,
				UserAgentManualOverride.fromString(rs.getString("manual_override")),
				rs.getString("operator_note"),
				rs.getString("updated_by"),
				updatedAt != null ? updatedAt.toInstant() : Instant.now()
		);
	};

	@NonNull
	private static final RowMapper<UserAgentHourlyPoint> HOURLY_MAPPER = (rs, rowNum) -> {
		Timestamp bStart = rs.getTimestamp("bucket_start");
		Timestamp bEnd = rs.getTimestamp("bucket_end");
		return new UserAgentHourlyPoint(
				bStart != null ? bStart.toInstant() : Instant.now(),
				bEnd != null ? bEnd.toInstant() : Instant.now(),
				rs.getLong("total_requests"),
				rs.getInt("event_count"),
				rs.getLong("blocked_requests"),
				rs.getLong("marked_requests"),
				rs.getInt("incident_events"),
				rs.getInt("authenticated_samples"),
				rs.getLong("authenticated_requests"),
				rs.getLong("internal_requests"),
				rs.getLong("crawler_requests"),
				rs.getLong("datacenter_requests"),
				rs.getLong("residential_requests"),
				rs.getLong("returning_requests"),
				rs.getLong("ua_mismatch_requests"),
				rs.getInt("distinct_subnets"),
				rs.getInt("distinct_asns"),
				UserAgentAutoVerdict.fromString(rs.getString("evaluated_verdict")),
				rs.getString("evaluated_pillar"),
				rs.getString("evaluated_reason")
		);
	};

	public record HourlyRollupWrite(
			Instant bucketStart,
			Instant bucketEnd,
			long uaId,
			long totalRequests,
			int eventCount,
			long blockedRequests,
			long markedRequests,
			int incidentEvents,
			int authenticatedSamples,
			long authenticatedRequests,
			long internalRequests,
			long crawlerRequests,
			long datacenterRequests,
			long residentialRequests,
			long returningRequests,
			long uaMismatchRequests,
			int distinctSubnets,
			int distinctAsns,
			UserAgentAutoVerdict evaluatedVerdict,
			String evaluatedPillar,
			String evaluatedReason
	) {}

	public long ensureProfileExists(
			String rawUserAgent,
			UserAgentFamily family,
			Integer parsedMajorVersion,
			Instant seenAt
	) {
		String trimmed = rawUserAgent != null ? rawUserAgent.trim() : "";
		String hash = computeSha256Hex(trimmed);
		int hash32 = computeUaHash32(trimmed);
		Timestamp ts = Timestamp.from(seenAt != null ? seenAt : Instant.now());

		String insertSql = """
				INSERT INTO dim_user_agent (
				    user_agent_hash, ua_hash_32, raw_user_agent, browser_family, parsed_major_version,
				    is_bot, first_seen_at, last_seen_at, manual_override, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'AUTO', ?)
				ON CONFLICT (user_agent_hash) DO NOTHING
				""";

		StorageRetryUtil.executeWithRetry("UserAgentMemoryRepository.ensureProfileExists", () ->
				jdbcTemplate.update(insertSql, ps -> {
					ps.setString(1, hash);
					ps.setInt(2, hash32);
					ps.setString(3, trimmed);
					ps.setString(4, (family != null ? family : UserAgentFamily.UNKNOWN).name());
					if (parsedMajorVersion != null) {
						ps.setInt(5, parsedMajorVersion);
					} else {
						ps.setNull(5, Types.INTEGER);
					}
					ps.setBoolean(6, family != null && family.isAutomated());
					ps.setTimestamp(7, ts);
					ps.setTimestamp(8, ts);
					ps.setTimestamp(9, ts);
				})
		);

		Long id = jdbcTemplate.queryForObject(
				"SELECT id FROM dim_user_agent WHERE user_agent_hash = ?", Long.class, hash);
		return id != null ? id : 0L;
	}

	public Map<String, Long> ensureProfilesBatch(List<ProfileSeed> seeds) {
		if (seeds == null || seeds.isEmpty()) {
			return Map.of();
		}

		String insertSql = """
				INSERT INTO dim_user_agent (
				    user_agent_hash, ua_hash_32, raw_user_agent, browser_family, parsed_major_version,
				    is_bot, first_seen_at, last_seen_at, manual_override, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'AUTO', ?)
				ON CONFLICT (user_agent_hash) DO NOTHING
				""";

		for (int from = 0; from < seeds.size(); from += BATCH_CHUNK_SIZE) {
			int to = Math.min(from + BATCH_CHUNK_SIZE, seeds.size());
			List<ProfileSeed> chunk = seeds.subList(from, to);
			StorageRetryUtil.executeWithRetry("UserAgentMemoryRepository.ensureProfilesBatch", () -> {
				jdbcTemplate.batchUpdate(insertSql, new BatchPreparedStatementSetter() {
					@Override
					public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
						ProfileSeed s = chunk.get(i);
						Timestamp ts = Timestamp.from(s.seenAt() != null ? s.seenAt() : Instant.now());
						ps.setString(1, s.hash());
						ps.setInt(2, s.hash32());
						ps.setString(3, s.rawUserAgent());
						ps.setString(4, (s.family() != null ? s.family() : UserAgentFamily.UNKNOWN).name());
						if (s.parsedMajorVersion() != null) {
							ps.setInt(5, s.parsedMajorVersion());
						} else {
							ps.setNull(5, Types.INTEGER);
						}
						ps.setBoolean(6, s.family() != null && s.family().isAutomated());
						ps.setTimestamp(7, ts);
						ps.setTimestamp(8, ts);
						ps.setTimestamp(9, ts);
					}

					@Override
					public int getBatchSize() {
						return chunk.size();
					}
				});
			});
		}

		Map<String, Long> idByHash = new HashMap<>();
		for (int from = 0; from < seeds.size(); from += BATCH_CHUNK_SIZE) {
			int to = Math.min(from + BATCH_CHUNK_SIZE, seeds.size());
			List<ProfileSeed> chunk = seeds.subList(from, to);
			String placeholders = String.join(",", Collections.nCopies(chunk.size(), "?"));
			String selectSql = "SELECT id, user_agent_hash FROM dim_user_agent WHERE user_agent_hash IN (" + placeholders + ")";
			Object[] args = chunk.stream().map(ProfileSeed::hash).toArray();
			jdbcTemplate.query(selectSql, rs -> {
				idByHash.put(rs.getString("user_agent_hash"), rs.getLong("id"));
			}, args);
		}
		return idByHash;
	}

	public record ProfileSeed(
			String hash,
			int hash32,
			String rawUserAgent,
			UserAgentFamily family,
			Integer parsedMajorVersion,
			Instant seenAt
	) {}

	public void batchUpsertHourlyRollups(List<HourlyRollupWrite> rows) {
		if (rows == null || rows.isEmpty()) {
			return;
		}
		String sql = """
				INSERT INTO user_agent_hourly_rollups (
				    bucket_start, bucket_end, ua_id,
				    total_requests, event_count, blocked_requests, marked_requests, incident_events,
				    authenticated_samples, authenticated_requests, internal_requests, crawler_requests,
				    datacenter_requests, residential_requests, returning_requests, ua_mismatch_requests,
				    distinct_subnets, distinct_asns,
				    evaluated_verdict, evaluated_pillar, evaluated_reason
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (bucket_start, ua_id) DO UPDATE SET
				    bucket_end = EXCLUDED.bucket_end,
				    total_requests = EXCLUDED.total_requests,
				    event_count = EXCLUDED.event_count,
				    blocked_requests = EXCLUDED.blocked_requests,
				    marked_requests = EXCLUDED.marked_requests,
				    incident_events = EXCLUDED.incident_events,
				    authenticated_samples = EXCLUDED.authenticated_samples,
				    authenticated_requests = EXCLUDED.authenticated_requests,
				    internal_requests = EXCLUDED.internal_requests,
				    crawler_requests = EXCLUDED.crawler_requests,
				    datacenter_requests = EXCLUDED.datacenter_requests,
				    residential_requests = EXCLUDED.residential_requests,
				    returning_requests = EXCLUDED.returning_requests,
				    ua_mismatch_requests = EXCLUDED.ua_mismatch_requests,
				    distinct_subnets = EXCLUDED.distinct_subnets,
				    distinct_asns = EXCLUDED.distinct_asns,
				    evaluated_verdict = EXCLUDED.evaluated_verdict,
				    evaluated_pillar = EXCLUDED.evaluated_pillar,
				    evaluated_reason = EXCLUDED.evaluated_reason
				""";

		for (int from = 0; from < rows.size(); from += BATCH_CHUNK_SIZE) {
			int to = Math.min(from + BATCH_CHUNK_SIZE, rows.size());
			List<HourlyRollupWrite> chunk = rows.subList(from, to);
			StorageRetryUtil.executeWithRetry("UserAgentMemoryRepository.batchUpsertHourlyRollups", () -> {
				jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
					@Override
					public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
						HourlyRollupWrite r = chunk.get(i);
						ps.setTimestamp(1, Timestamp.from(r.bucketStart()));
						ps.setTimestamp(2, Timestamp.from(r.bucketEnd()));
						ps.setLong(3, r.uaId());
						ps.setLong(4, r.totalRequests());
						ps.setInt(5, r.eventCount());
						ps.setLong(6, r.blockedRequests());
						ps.setLong(7, r.markedRequests());
						ps.setInt(8, r.incidentEvents());
						ps.setInt(9, r.authenticatedSamples());
						ps.setLong(10, r.authenticatedRequests());
						ps.setLong(11, r.internalRequests());
						ps.setLong(12, r.crawlerRequests());
						ps.setLong(13, r.datacenterRequests());
						ps.setLong(14, r.residentialRequests());
						ps.setLong(15, r.returningRequests());
						ps.setLong(16, r.uaMismatchRequests());
						ps.setInt(17, r.distinctSubnets());
						ps.setInt(18, r.distinctAsns());
						UserAgentAutoVerdict v = r.evaluatedVerdict() != null ? r.evaluatedVerdict() : UserAgentAutoVerdict.NEUTRAL;
						ps.setString(19, v.name());
						ps.setString(20, r.evaluatedPillar() != null ? r.evaluatedPillar() : v.pillarCode());
						ps.setString(21, r.evaluatedReason());
					}

					@Override
					public int getBatchSize() {
						return chunk.size();
					}
				});
			});
		}
	}

	public void batchUpdateProfilesPreservingOverrides(List<UserAgentProfile> profiles) {
		if (profiles == null || profiles.isEmpty()) {
			return;
		}
		String sql = """
				INSERT INTO dim_user_agent (
				    user_agent_hash, ua_hash_32, raw_user_agent, browser_family, parsed_major_version, is_bot,
				    first_seen_at, last_seen_at,
				    total_lifetime_requests, total_blocked_requests, total_marked_requests,
				    total_authenticated_samples, total_authenticated_requests,
				    total_internal_requests, total_crawler_requests,
				    last_24h_requests, last_24h_events, last_24h_blocked_requests, last_24h_marked_requests,
				    last_24h_distinct_subnets, last_24h_distinct_asns,
				    last_24h_auth_samples, last_24h_auth_requests,
				    last_24h_internal_requests, last_24h_crawler_requests,
				    last_24h_datacenter_requests, last_24h_residential_requests,
				    last_24h_returning_requests, last_24h_ua_mismatch_requests,
				    auto_verdict, auto_pillar, auto_verdict_reason, auto_evaluated_at,
				    manual_override, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'AUTO', ?)
				ON CONFLICT (user_agent_hash) DO UPDATE SET
				    browser_family = EXCLUDED.browser_family,
				    parsed_major_version = COALESCE(EXCLUDED.parsed_major_version, dim_user_agent.parsed_major_version),
				    is_bot = EXCLUDED.is_bot,
				    first_seen_at = CASE WHEN EXCLUDED.first_seen_at < dim_user_agent.first_seen_at THEN EXCLUDED.first_seen_at ELSE dim_user_agent.first_seen_at END,
				    last_seen_at = CASE WHEN EXCLUDED.last_seen_at > dim_user_agent.last_seen_at THEN EXCLUDED.last_seen_at ELSE dim_user_agent.last_seen_at END,
				    total_lifetime_requests = CASE WHEN EXCLUDED.total_lifetime_requests > dim_user_agent.total_lifetime_requests THEN EXCLUDED.total_lifetime_requests ELSE dim_user_agent.total_lifetime_requests END,
				    total_blocked_requests = CASE WHEN EXCLUDED.total_blocked_requests > dim_user_agent.total_blocked_requests THEN EXCLUDED.total_blocked_requests ELSE dim_user_agent.total_blocked_requests END,
				    total_marked_requests = CASE WHEN EXCLUDED.total_marked_requests > dim_user_agent.total_marked_requests THEN EXCLUDED.total_marked_requests ELSE dim_user_agent.total_marked_requests END,
				    total_authenticated_samples = CASE WHEN EXCLUDED.total_authenticated_samples > dim_user_agent.total_authenticated_samples THEN EXCLUDED.total_authenticated_samples ELSE dim_user_agent.total_authenticated_samples END,
				    total_authenticated_requests = CASE WHEN EXCLUDED.total_authenticated_requests > dim_user_agent.total_authenticated_requests THEN EXCLUDED.total_authenticated_requests ELSE dim_user_agent.total_authenticated_requests END,
				    total_internal_requests = CASE WHEN EXCLUDED.total_internal_requests > dim_user_agent.total_internal_requests THEN EXCLUDED.total_internal_requests ELSE dim_user_agent.total_internal_requests END,
				    total_crawler_requests = CASE WHEN EXCLUDED.total_crawler_requests > dim_user_agent.total_crawler_requests THEN EXCLUDED.total_crawler_requests ELSE dim_user_agent.total_crawler_requests END,
				    last_24h_requests = EXCLUDED.last_24h_requests,
				    last_24h_events = EXCLUDED.last_24h_events,
				    last_24h_blocked_requests = EXCLUDED.last_24h_blocked_requests,
				    last_24h_marked_requests = EXCLUDED.last_24h_marked_requests,
				    last_24h_distinct_subnets = EXCLUDED.last_24h_distinct_subnets,
				    last_24h_distinct_asns = EXCLUDED.last_24h_distinct_asns,
				    last_24h_auth_samples = EXCLUDED.last_24h_auth_samples,
				    last_24h_auth_requests = EXCLUDED.last_24h_auth_requests,
				    last_24h_internal_requests = EXCLUDED.last_24h_internal_requests,
				    last_24h_crawler_requests = EXCLUDED.last_24h_crawler_requests,
				    last_24h_datacenter_requests = EXCLUDED.last_24h_datacenter_requests,
				    last_24h_residential_requests = EXCLUDED.last_24h_residential_requests,
				    last_24h_returning_requests = EXCLUDED.last_24h_returning_requests,
				    last_24h_ua_mismatch_requests = EXCLUDED.last_24h_ua_mismatch_requests,
				    auto_verdict = EXCLUDED.auto_verdict,
				    auto_pillar = EXCLUDED.auto_pillar,
				    auto_verdict_reason = EXCLUDED.auto_verdict_reason,
				    auto_evaluated_at = EXCLUDED.auto_evaluated_at,
				    updated_at = EXCLUDED.updated_at
				""";

		Instant now = Instant.now();
		for (int from = 0; from < profiles.size(); from += BATCH_CHUNK_SIZE) {
			int to = Math.min(from + BATCH_CHUNK_SIZE, profiles.size());
			List<UserAgentProfile> chunk = profiles.subList(from, to);
			StorageRetryUtil.executeWithRetry("UserAgentMemoryRepository.batchUpdateProfiles", () -> {
				jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
					@Override
					public void setValues(@NonNull PreparedStatement ps, int i) throws SQLException {
						UserAgentProfile p = chunk.get(i);
						Timestamp nowTs = Timestamp.from(now);
						ps.setString(1, p.userAgentHash());
						ps.setInt(2, p.uaHash32());
						ps.setString(3, p.rawUserAgent());
						ps.setString(4, p.browserFamily() != null ? p.browserFamily().name() : UserAgentFamily.UNKNOWN.name());
						if (p.parsedMajorVersion() != null) {
							ps.setInt(5, p.parsedMajorVersion());
						} else {
							ps.setNull(5, Types.INTEGER);
						}
						ps.setBoolean(6, p.bot());
						ps.setTimestamp(7, Timestamp.from(p.firstSeenAt() != null ? p.firstSeenAt() : now));
						ps.setTimestamp(8, Timestamp.from(p.lastSeenAt() != null ? p.lastSeenAt() : now));
						ps.setLong(9, p.totalLifetimeRequests());
						ps.setLong(10, p.totalBlockedRequests());
						ps.setLong(11, p.totalMarkedRequests());
						ps.setLong(12, p.totalAuthenticatedSamples());
						ps.setLong(13, p.totalAuthenticatedRequests());
						ps.setLong(14, p.totalInternalRequests());
						ps.setLong(15, p.totalCrawlerRequests());
						ps.setLong(16, p.last24hRequests());
						ps.setInt(17, p.last24hEvents());
						ps.setLong(18, p.last24hBlockedRequests());
						ps.setLong(19, p.last24hMarkedRequests());
						ps.setInt(20, p.last24hDistinctSubnets());
						ps.setInt(21, p.last24hDistinctAsns());
						ps.setInt(22, p.last24hAuthSamples());
						ps.setLong(23, p.last24hAuthRequests());
						ps.setLong(24, p.last24hInternalRequests());
						ps.setLong(25, p.last24hCrawlerRequests());
						ps.setLong(26, p.last24hDatacenterRequests());
						ps.setLong(27, p.last24hResidentialRequests());
						ps.setLong(28, p.last24hReturningRequests());
						ps.setLong(29, p.last24hUaMismatchRequests());
						UserAgentAutoVerdict verdict = p.effectiveAutoVerdict();
						ps.setString(30, verdict.name());
						ps.setString(31, p.autoPillar() != null ? p.autoPillar() : verdict.pillarCode());
						ps.setString(32, p.autoVerdictReason());
						ps.setTimestamp(33, Timestamp.from(p.autoEvaluatedAt() != null ? p.autoEvaluatedAt() : now));
						ps.setTimestamp(34, nowTs);
					}

					@Override
					public int getBatchSize() {
						return chunk.size();
					}
				});
			});
		}
	}

	public void updateManualOverride(
			String rawUserAgent,
			UserAgentFamily family,
			Integer parsedMajorVersion,
			UserAgentManualOverride override,
			String operatorNote,
			String updatedBy
	) {
		String trimmed = rawUserAgent != null ? rawUserAgent.trim() : "";
		String hash = computeSha256Hex(trimmed);
		int hash32 = computeUaHash32(trimmed);
		Timestamp nowTs = Timestamp.from(Instant.now());
		String cleanNote = (operatorNote != null && !operatorNote.isBlank()) ? operatorNote.trim() : null;
		UserAgentManualOverride effectiveOverride = override != null ? override : UserAgentManualOverride.AUTO;

		String sql = """
				INSERT INTO dim_user_agent (
				    user_agent_hash, ua_hash_32, raw_user_agent, browser_family, parsed_major_version, is_bot,
				    first_seen_at, last_seen_at, manual_override, operator_note, updated_by, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (user_agent_hash) DO UPDATE SET
				    manual_override = EXCLUDED.manual_override,
				    operator_note = EXCLUDED.operator_note,
				    updated_by = EXCLUDED.updated_by,
				    updated_at = EXCLUDED.updated_at
				""";

		StorageRetryUtil.executeWithRetry("UserAgentMemoryRepository.updateManualOverride", () ->
				jdbcTemplate.update(sql, ps -> {
					ps.setString(1, hash);
					ps.setInt(2, hash32);
					ps.setString(3, trimmed);
					ps.setString(4, (family != null ? family : UserAgentFamily.UNKNOWN).name());
					if (parsedMajorVersion != null) {
						ps.setInt(5, parsedMajorVersion);
					} else {
						ps.setNull(5, Types.INTEGER);
					}
					ps.setBoolean(6, family != null && family.isAutomated());
					ps.setTimestamp(7, nowTs);
					ps.setTimestamp(8, nowTs);
					ps.setString(9, effectiveOverride.name());
					ps.setString(10, cleanNote);
					ps.setString(11, updatedBy != null ? updatedBy : "ADMIN");
					ps.setTimestamp(12, nowTs);
				})
		);
	}

	public Optional<UserAgentProfile> findByRawUserAgent(String rawUserAgent) {
		if (rawUserAgent == null || rawUserAgent.isBlank()) {
			return Optional.empty();
		}
		String hash = computeSha256Hex(rawUserAgent.trim());
		return findByHash(hash);
	}

	public Optional<UserAgentProfile> findByHash(String userAgentHash) {
		if (userAgentHash == null || userAgentHash.isBlank()) {
			return Optional.empty();
		}
		List<UserAgentProfile> list = jdbcTemplate.query(
				"SELECT * FROM dim_user_agent WHERE user_agent_hash = ? LIMIT 1",
				PROFILE_MAPPER,
				userAgentHash.trim()
		);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.getFirst());
	}

	public Map<String, UserAgentProfile> findProfilesByRawUserAgents(Collection<String> rawUserAgents) {
		if (rawUserAgents == null || rawUserAgents.isEmpty()) {
			return Map.of();
		}
		List<String> hashes = new ArrayList<>();
		for (String ua : rawUserAgents) {
			if (ua != null && !ua.isBlank()) {
				hashes.add(computeSha256Hex(ua));
			}
		}
		if (hashes.isEmpty()) {
			return Map.of();
		}
		Map<String, UserAgentProfile> result = new LinkedHashMap<>();
		for (int from = 0; from < hashes.size(); from += BATCH_CHUNK_SIZE) {
			int to = Math.min(from + BATCH_CHUNK_SIZE, hashes.size());
			List<String> chunk = hashes.subList(from, to);
			String placeholders = String.join(",", Collections.nCopies(chunk.size(), "?"));
			String sql = "SELECT * FROM dim_user_agent WHERE user_agent_hash IN (" + placeholders + ")";
			List<UserAgentProfile> found = jdbcTemplate.query(sql, PROFILE_MAPPER, chunk.toArray());
			for (UserAgentProfile p : found) {
				result.put(p.rawUserAgent(), p);
			}
		}
		return result;
	}

	public Map<String, UserAgentProfile> findAllManualOverrides() {
		List<UserAgentProfile> list = jdbcTemplate.query(
				"SELECT * FROM dim_user_agent WHERE manual_override != 'AUTO' OR (operator_note IS NOT NULL AND operator_note != '')",
				PROFILE_MAPPER
		);
		Map<String, UserAgentProfile> map = new LinkedHashMap<>();
		for (UserAgentProfile p : list) {
			map.put(p.rawUserAgent(), p);
		}
		return map;
	}

	public List<UserAgentProfile> findAllProfiles(int limit) {
		return jdbcTemplate.query(
				"SELECT * FROM dim_user_agent ORDER BY last_24h_requests DESC, total_lifetime_requests DESC LIMIT ?",
				PROFILE_MAPPER,
				Math.max(1, limit)
		);
	}

	/**
	 * Finds User-Agent profiles matching the given raw User-Agent or browser family substring.
	 */
	public List<UserAgentProfile> searchProfilesBySubstring(String query, int limit) {
		if (query == null || query.isBlank()) {
			return List.of();
		}
		String term = "%" + query.trim().toLowerCase() + "%";
		return jdbcTemplate.query("""
				SELECT * FROM dim_user_agent
				WHERE LOWER(COALESCE(raw_user_agent, '')) LIKE ? OR LOWER(COALESCE(browser_family, '')) LIKE ?
				ORDER BY last_24h_requests DESC, total_lifetime_requests DESC
				LIMIT ?
				""", PROFILE_MAPPER, term, term, Math.max(1, limit));
	}

	public long countProfiles() {
		Long count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM dim_user_agent", Long.class);
		return count != null ? count : 0L;
	}

	public long countHourlyRollups() {
		Long count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM user_agent_hourly_rollups", Long.class);
		return count != null ? count : 0L;
	}

	public List<UserAgentHourlyPoint> findHourlyHistoryByUaId(long uaId, Instant from, Instant to) {
		String sql = """
				SELECT * FROM user_agent_hourly_rollups
				WHERE ua_id = ? AND bucket_start >= ? AND bucket_start <= ?
				ORDER BY bucket_start DESC
				""";
		return jdbcTemplate.query(sql, HOURLY_MAPPER, uaId, Timestamp.from(from), Timestamp.from(to));
	}

	public int deleteHourlyRollupsOlderThan(Instant cutoff) {
		return StorageRetryUtil.executeWithRetry("UserAgentMemoryRepository.deleteOlderThan", () ->
				jdbcTemplate.update("DELETE FROM user_agent_hourly_rollups WHERE bucket_start < ?", Timestamp.from(cutoff))
		);
	}
}
