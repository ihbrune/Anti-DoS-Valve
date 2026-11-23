package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.henbru.antidos.collector.model.MitigationUaRule;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * Repository managing persistent User-Agent dynamic block rules ({@code mitigation_ua_rules}).
 */
@Repository
public class MitigationUaRuleRepository {

	private final JdbcTemplate jdbcTemplate;

	public MitigationUaRuleRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	public static final RowMapper<MitigationUaRule> ROW_MAPPER = (rs, rowNum) -> new MitigationUaRule(
			rs.getLong("id"),
			rs.getString("user_agent_hash"),
			rs.getInt("ua_hash_32"),
			rs.getString("raw_user_agent"),
			rs.getString("browser_family") != null ? rs.getString("browser_family") : "OTHER",
			rs.getString("target_scope") != null ? rs.getString("target_scope") : "ALL",
			rs.getString("status"),
			rs.getString("source"),
			rs.getString("batch_id"),
			rs.getString("reason"),
			toInstant(rs.getTimestamp("created_at")),
			toInstant(rs.getTimestamp("updated_at")),
			toInstant(rs.getTimestamp("expires_at")),
			toInstant(rs.getTimestamp("revoked_at")),
			rs.getString("revoked_reason"),
			rs.getLong("total_blocked_hits"),
			rs.getLong("total_bypassed_hits"),
			toInstant(rs.getTimestamp("last_hit_at")),
			rs.getString("deterrence_state") != null ? rs.getString("deterrence_state") : MitigationUaRule.DETERRENCE_OBSERVING
	);

	private static Instant toInstant(Timestamp ts) {
		return ts != null ? ts.toInstant() : null;
	}

	public MitigationUaRule upsertRule(MitigationUaRule r) {
		String sql = """
				INSERT INTO mitigation_ua_rules (
				    user_agent_hash, ua_hash_32, raw_user_agent, browser_family, target_scope,
				    status, source, batch_id, reason, created_at, updated_at, expires_at,
				    revoked_at, revoked_reason, total_blocked_hits, total_bypassed_hits, last_hit_at,
				    deterrence_state
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (user_agent_hash, target_scope) DO UPDATE SET
				    ua_hash_32 = EXCLUDED.ua_hash_32,
				    raw_user_agent = EXCLUDED.raw_user_agent,
				    browser_family = EXCLUDED.browser_family,
				    status = EXCLUDED.status,
				    source = EXCLUDED.source,
				    batch_id = COALESCE(EXCLUDED.batch_id, mitigation_ua_rules.batch_id),
				    reason = EXCLUDED.reason,
				    created_at = EXCLUDED.created_at,
				    updated_at = EXCLUDED.updated_at,
				    expires_at = EXCLUDED.expires_at,
				    revoked_at = EXCLUDED.revoked_at,
				    revoked_reason = EXCLUDED.revoked_reason,
				    total_blocked_hits = EXCLUDED.total_blocked_hits,
				    total_bypassed_hits = EXCLUDED.total_bypassed_hits,
				    last_hit_at = EXCLUDED.last_hit_at,
				    deterrence_state = EXCLUDED.deterrence_state
				""";

		Instant now = r.updatedAt() != null ? r.updatedAt() : Instant.now();
		Instant created = r.createdAt() != null ? r.createdAt() : now;
		String scope = r.targetScope() != null && !r.targetScope().isBlank() ? r.targetScope() : "ALL";

		StorageRetryUtil.executeWithRetry("MitigationUaRuleRepository.upsertRule", () -> {
			jdbcTemplate.update(sql,
					r.userAgentHash(),
					r.uaHash32(),
					r.rawUserAgent(),
					r.browserFamily() != null ? r.browserFamily() : "OTHER",
					scope,
					r.status() != null ? r.status() : MitigationUaRule.STATUS_ACTIVE,
					r.source() != null ? r.source() : MitigationUaRule.SOURCE_MANUAL,
					r.batchId(),
					r.reason(),
					Timestamp.from(created),
					Timestamp.from(now),
					Timestamp.from(r.expiresAt()),
					r.revokedAt() != null ? Timestamp.from(r.revokedAt()) : null,
					r.revokedReason(),
					r.totalBlockedHits(),
					r.totalBypassedHits(),
					r.lastHitAt() != null ? Timestamp.from(r.lastHitAt()) : null,
					r.deterrenceState() != null ? r.deterrenceState() : MitigationUaRule.DETERRENCE_OBSERVING
			);
			return null;
		});

		return findByHashAndScope(r.userAgentHash(), scope).orElse(r);
	}

	public Optional<MitigationUaRule> findById(long id) {
		List<MitigationUaRule> list = jdbcTemplate.query(
				"SELECT * FROM mitigation_ua_rules WHERE id = ?",
				ROW_MAPPER, id);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.getFirst());
	}

	public Optional<MitigationUaRule> findByHashAndScope(String userAgentHash, String targetScope) {
		if (userAgentHash == null || userAgentHash.isBlank()) {
			return Optional.empty();
		}
		String scope = targetScope != null && !targetScope.isBlank() ? targetScope : "ALL";
		List<MitigationUaRule> list = jdbcTemplate.query(
				"SELECT * FROM mitigation_ua_rules WHERE user_agent_hash = ? AND target_scope = ?",
				ROW_MAPPER, userAgentHash, scope);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.getFirst());
	}

	public Optional<MitigationUaRule> findByRawUserAgent(String rawUserAgent, String targetScope) {
		if (rawUserAgent == null || rawUserAgent.isBlank()) {
			return Optional.empty();
		}
		String sha256 = UserAgentMemoryRepository.computeSha256Hex(rawUserAgent.trim());
		return findByHashAndScope(sha256, targetScope);
	}

	public List<MitigationUaRule> findActiveRules(Instant now) {
		return jdbcTemplate.query(
				"SELECT * FROM mitigation_ua_rules WHERE status = 'ACTIVE' AND expires_at > ? ORDER BY expires_at ASC, id ASC",
				ROW_MAPPER, Timestamp.from(now));
	}

	/**
	 * Finds all User-Agent mitigation rules whose lifetime overlaps the requested time window.
	 */
	public List<MitigationUaRule> findRulesOverlappingWindow(Instant windowStart, Instant windowEnd, int limit) {
		return jdbcTemplate.query("""
				SELECT * FROM mitigation_ua_rules
				WHERE created_at <= ?
				  AND COALESCE(revoked_at, expires_at) >= ?
				ORDER BY updated_at DESC, id DESC
				LIMIT ?
				""", ROW_MAPPER, Timestamp.from(windowEnd), Timestamp.from(windowStart), Math.max(1, limit));
	}

	public List<MitigationUaRule> findRecentRules(int limit) {
		return jdbcTemplate.query(
				"SELECT * FROM mitigation_ua_rules ORDER BY updated_at DESC, id DESC LIMIT ?",
				ROW_MAPPER, Math.max(1, limit));
	}

	public long countActiveRules(Instant now) {
		Long count = jdbcTemplate.queryForObject(
				"SELECT COUNT(*) FROM mitigation_ua_rules WHERE status = 'ACTIVE' AND expires_at > ?",
				Long.class, Timestamp.from(now));
		return count != null ? count : 0L;
	}

	public int expireElapsedRules(Instant now) {
		return StorageRetryUtil.executeWithRetry("MitigationUaRuleRepository.expireElapsedRules", () ->
				jdbcTemplate.update(
						"UPDATE mitigation_ua_rules SET status = 'EXPIRED', updated_at = ? WHERE status = 'ACTIVE' AND expires_at <= ?",
						Timestamp.from(now), Timestamp.from(now)));
	}

	public int revokeAllActive(Instant now, String reason) {
		String sql = """
				UPDATE mitigation_ua_rules
				SET status = 'REVOKED',
				    revoked_at = ?,
				    revoked_reason = ?,
				    updated_at = ?
				WHERE status = 'ACTIVE' AND expires_at > ?
				""";
		return StorageRetryUtil.executeWithRetry("MitigationUaRuleRepository.revokeAllActive", () ->
				jdbcTemplate.update(sql,
						Timestamp.from(now),
						reason,
						Timestamp.from(now),
						Timestamp.from(now)));
	}

	public List<MitigationUaRule> findHistoricalRulesFiltered(String search, String status, int offset, int limit) {
		StringBuilder sql = new StringBuilder("SELECT * FROM mitigation_ua_rules WHERE status IN ('EXPIRED', 'REVOKED')");
		List<Object> params = new ArrayList<>();
		appendHistoricalFilters(sql, params, search, status);
		sql.append(" ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?");
		params.add(Math.max(1, limit));
		params.add(Math.max(0, offset));
		return jdbcTemplate.query(sql.toString(), ROW_MAPPER, params.toArray());
	}

	public long countHistoricalRulesFiltered(String search, String status) {
		StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM mitigation_ua_rules WHERE status IN ('EXPIRED', 'REVOKED')");
		List<Object> params = new ArrayList<>();
		appendHistoricalFilters(sql, params, search, status);
		Long count = jdbcTemplate.queryForObject(sql.toString(), Long.class, params.toArray());
		return count != null ? count : 0L;
	}

	private void appendHistoricalFilters(StringBuilder sql, List<Object> params, String search, String status) {
		if (status != null && !status.isBlank() && !"ALL".equalsIgnoreCase(status)) {
			sql.append(" AND status = ?");
			params.add(status.trim().toUpperCase());
		}
		if (search != null && !search.isBlank()) {
			String term = "%" + search.trim().toLowerCase() + "%";
			sql.append(" AND (LOWER(COALESCE(raw_user_agent, '')) LIKE ? OR LOWER(COALESCE(user_agent_hash, '')) LIKE ? "
					+ "OR LOWER(COALESCE(browser_family, '')) LIKE ? OR LOWER(COALESCE(reason, '')) LIKE ?)");
			params.add(term);
			params.add(term);
			params.add(term);
			params.add(term);
		}
	}

	public List<MitigationUaRule> findAllByHashOrRawUserAgent(String userAgentHash, String rawUserAgent) {
		String sha = userAgentHash != null && !userAgentHash.isBlank()
				? userAgentHash.trim()
				: (rawUserAgent != null && !rawUserAgent.isBlank() ? UserAgentMemoryRepository.computeSha256Hex(rawUserAgent.trim()) : null);
		if (sha == null) {
			return List.of();
		}
		return jdbcTemplate.query(
				"SELECT * FROM mitigation_ua_rules WHERE user_agent_hash = ? ORDER BY created_at DESC, id DESC",
				ROW_MAPPER, sha);
	}

	public record UaDeterrenceUpdate(
			long id,
			long totalBlockedHits,
			long totalBypassedHits,
			Instant lastHitAt,
			String deterrenceState
	) {
		public UaDeterrenceUpdate(long id, long totalBlockedHits, long totalBypassedHits, Instant lastHitAt) {
			this(id, totalBlockedHits, totalBypassedHits, lastHitAt, MitigationUaRule.DETERRENCE_OBSERVING);
		}
	}

	public void batchUpdateDeterrenceTelemetry(List<UaDeterrenceUpdate> updates, Instant now) {
		if (updates == null || updates.isEmpty()) {
			return;
		}
		String sql = """
				UPDATE mitigation_ua_rules
				SET total_blocked_hits = ?,
				    total_bypassed_hits = ?,
				    last_hit_at = ?,
				    deterrence_state = ?,
				    updated_at = ?
				WHERE id = ?
				""";
		Timestamp tsNow = Timestamp.from(now != null ? now : Instant.now());
		StorageRetryUtil.executeWithRetry("MitigationUaRuleRepository.batchUpdateDeterrenceTelemetry", () -> {
			jdbcTemplate.batchUpdate(sql, updates, updates.size(), (ps, u) -> {
				ps.setLong(1, u.totalBlockedHits());
				ps.setLong(2, u.totalBypassedHits());
				if (u.lastHitAt() != null) {
					ps.setTimestamp(3, Timestamp.from(u.lastHitAt()));
				} else {
					ps.setNull(3, java.sql.Types.TIMESTAMP);
				}
				ps.setString(4, u.deterrenceState() != null ? u.deterrenceState() : MitigationUaRule.DETERRENCE_OBSERVING);
				ps.setTimestamp(5, tsNow);
				ps.setLong(6, u.id());
			});
			return null;
		});
	}

	public int deleteHistoricalRulesOlderThan(Instant cutoff) {
		if (cutoff == null) {
			return 0;
		}
		return StorageRetryUtil.executeWithRetry("MitigationUaRuleRepository.deleteHistoricalRulesOlderThan", () ->
				jdbcTemplate.update(
						"DELETE FROM mitigation_ua_rules WHERE status IN ('EXPIRED', 'REVOKED') AND updated_at < ?",
						Timestamp.from(cutoff)));
	}
}
