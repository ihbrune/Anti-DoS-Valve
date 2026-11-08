package org.henbru.antidos.collector.storage;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.henbru.antidos.collector.model.MitigationAuditEntry;
import org.henbru.antidos.collector.model.MitigationRule;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * JDBC repository for persistent dynamic CIDR mitigation rules and audit history.
 */
@Repository
public class MitigationRuleRepository {

	private final JdbcTemplate jdbcTemplate;

	public MitigationRuleRepository(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	private static final RowMapper<MitigationRule> RULE_MAPPER = (rs, rowNum) -> new MitigationRule(
			rs.getLong("id"),
			rs.getString("cidr"),
			rs.getInt("ip_version"),
			rs.getInt("prefix_length"),
			rs.getString("target_scope"),
			rs.getString("status"),
			rs.getString("source"),
			rs.getString("batch_id"),
			rs.getString("reason"),
			rs.getObject("asn") != null ? rs.getLong("asn") : null,
			rs.getString("asn_organization"),
			toInstant(rs.getTimestamp("created_at")),
			toInstant(rs.getTimestamp("updated_at")),
			toInstant(rs.getTimestamp("expires_at")),
			toInstant(rs.getTimestamp("revoked_at")),
			rs.getString("revoked_reason"),
			rs.getLong("total_blocked_hits"),
			rs.getInt("peak_distinct_ips"),
			toInstant(rs.getTimestamp("last_hit_at")),
			rs.getString("deterrence_state") != null ? rs.getString("deterrence_state") : MitigationRule.DETERRENCE_OBSERVING
	);

	private static final RowMapper<MitigationAuditEntry> AUDIT_MAPPER = (rs, rowNum) -> new MitigationAuditEntry(
			rs.getLong("id"),
			rs.getObject("rule_id") != null ? rs.getLong("rule_id") : null,
			rs.getString("cidr"),
			rs.getString("batch_id"),
			rs.getString("action"),
			rs.getString("actor"),
			rs.getObject("ttl_seconds") != null ? rs.getInt("ttl_seconds") : null,
			rs.getString("details"),
			toInstant(rs.getTimestamp("created_at"))
	);

	private static Instant toInstant(Timestamp ts) {
		return ts != null ? ts.toInstant() : null;
	}

	public MitigationRule upsertRule(MitigationRule r) {
		String sql = """
				INSERT INTO mitigation_rules (
				    cidr, ip_version, prefix_length, target_scope, status, source, batch_id,
				    reason, asn, asn_organization, created_at, updated_at, expires_at,
				    revoked_at, revoked_reason, total_blocked_hits, peak_distinct_ips, last_hit_at, deterrence_state
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (cidr, target_scope) DO UPDATE SET
				    status = EXCLUDED.status,
				    source = EXCLUDED.source,
				    batch_id = COALESCE(EXCLUDED.batch_id, mitigation_rules.batch_id),
				    reason = EXCLUDED.reason,
				    asn = COALESCE(EXCLUDED.asn, mitigation_rules.asn),
				    asn_organization = COALESCE(EXCLUDED.asn_organization, mitigation_rules.asn_organization),
				    updated_at = EXCLUDED.updated_at,
				    expires_at = EXCLUDED.expires_at,
				    revoked_at = EXCLUDED.revoked_at,
				    revoked_reason = EXCLUDED.revoked_reason,
				    deterrence_state = EXCLUDED.deterrence_state
				""";

		Instant now = r.updatedAt() != null ? r.updatedAt() : Instant.now();
		Instant created = r.createdAt() != null ? r.createdAt() : now;

		StorageRetryUtil.executeWithRetry("MitigationRuleRepository.upsertRule", () -> {
			jdbcTemplate.update(sql,
					r.cidr(),
					r.ipVersion(),
					r.prefixLength(),
					r.targetScope() != null ? r.targetScope() : "ALL",
					r.status() != null ? r.status() : MitigationRule.STATUS_ACTIVE,
					r.source() != null ? r.source() : MitigationRule.SOURCE_MANUAL,
					r.batchId(),
					r.reason(),
					r.asn(),
					r.asnOrganization(),
					Timestamp.from(created),
					Timestamp.from(now),
					Timestamp.from(r.expiresAt()),
					r.revokedAt() != null ? Timestamp.from(r.revokedAt()) : null,
					r.revokedReason(),
					r.totalBlockedHits(),
					r.peakDistinctIps(),
					r.lastHitAt() != null ? Timestamp.from(r.lastHitAt()) : null,
					r.deterrenceState() != null ? r.deterrenceState() : MitigationRule.DETERRENCE_OBSERVING
			);
			return null;
		});

		return findByCidrAndScope(r.cidr(), r.targetScope() != null ? r.targetScope() : "ALL").orElse(r);
	}

	public Optional<MitigationRule> findById(long id) {
		List<MitigationRule> list = jdbcTemplate.query(
				"SELECT * FROM mitigation_rules WHERE id = ?", RULE_MAPPER, id);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.getFirst());
	}

	public Optional<MitigationRule> findByCidrAndScope(String cidr, String targetScope) {
		List<MitigationRule> list = jdbcTemplate.query(
				"SELECT * FROM mitigation_rules WHERE cidr = ? AND target_scope = ?",
				RULE_MAPPER, cidr, targetScope);
		return list.isEmpty() ? Optional.empty() : Optional.of(list.getFirst());
	}

	public List<MitigationRule> findActiveRules(Instant now) {
		return jdbcTemplate.query(
				"SELECT * FROM mitigation_rules WHERE status = 'ACTIVE' AND expires_at > ? ORDER BY expires_at ASC, cidr ASC",
				RULE_MAPPER, Timestamp.from(now));
	}

	public List<MitigationRule> findRecentRules(int limit) {
		return jdbcTemplate.query(
				"SELECT * FROM mitigation_rules ORDER BY updated_at DESC, id DESC LIMIT ?",
				RULE_MAPPER, Math.max(1, limit));
	}

	public List<MitigationRule> findByBatchId(String batchId) {
		return jdbcTemplate.query(
				"SELECT * FROM mitigation_rules WHERE batch_id = ? ORDER BY cidr ASC",
				RULE_MAPPER, batchId);
	}

	public int expireElapsedRules(Instant now) {
		return StorageRetryUtil.executeWithRetry("MitigationRuleRepository.expireElapsedRules", () -> jdbcTemplate.update(
				"UPDATE mitigation_rules SET status = 'EXPIRED', updated_at = ? WHERE status = 'ACTIVE' AND expires_at <= ?",
				Timestamp.from(now), Timestamp.from(now)));
	}

	public void updateDeterrenceTelemetry(long id, long totalBlockedHits, int peakDistinctIps, Instant lastHitAt, String deterrenceState, Instant now) {
		StorageRetryUtil.executeWithRetry("MitigationRuleRepository.updateDeterrenceTelemetry", () -> {
			jdbcTemplate.update(
					"UPDATE mitigation_rules SET total_blocked_hits = ?, peak_distinct_ips = ?, last_hit_at = COALESCE(?, last_hit_at), deterrence_state = ?, updated_at = ? WHERE id = ?",
					totalBlockedHits,
					peakDistinctIps,
					lastHitAt != null ? Timestamp.from(lastHitAt) : null,
					deterrenceState,
					Timestamp.from(now),
					id
			);
			return null;
		});
	}

	public void insertAuditEntry(MitigationAuditEntry entry) {
		String sql = """
				INSERT INTO mitigation_audit_log (
				    rule_id, cidr, batch_id, action, actor, ttl_seconds, details, created_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				""";
		Instant created = entry.createdAt() != null ? entry.createdAt() : Instant.now();
		StorageRetryUtil.executeWithRetry("MitigationRuleRepository.insertAuditEntry", () -> {
			jdbcTemplate.update(sql,
					entry.ruleId(),
					entry.cidr(),
					entry.batchId(),
					entry.action(),
					entry.actor() != null ? entry.actor() : "ADMIN",
					entry.ttlSeconds(),
					entry.details(),
					Timestamp.from(created)
			);
			return null;
		});
	}

	public List<MitigationAuditEntry> findRecentAuditEntries(int limit) {
		return jdbcTemplate.query(
				"SELECT * FROM mitigation_audit_log ORDER BY created_at DESC, id DESC LIMIT ?",
				AUDIT_MAPPER, Math.max(1, limit));
	}

	public long findLatestAlertAuditId() {
		Long max = jdbcTemplate.queryForObject(
				"SELECT COALESCE(MAX(id), 0) FROM mitigation_audit_log WHERE action IN ('AUTO_BLOCK', 'AUTO_EXTEND', 'AUTO_CIRCUIT_BREAKER')",
				Long.class);
		return max != null ? max : 0L;
	}

	public List<MitigationAuditEntry> findAlertEntriesSince(long sinceId, int limit) {
		return jdbcTemplate.query(
				"""
				SELECT * FROM mitigation_audit_log
				WHERE id > ?
				  AND action IN ('AUTO_BLOCK', 'AUTO_EXTEND', 'AUTO_CIRCUIT_BREAKER')
				ORDER BY id ASC
				LIMIT ?
				""",
				AUDIT_MAPPER, sinceId, Math.max(1, limit));
	}
}
