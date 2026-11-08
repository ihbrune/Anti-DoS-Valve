package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Audit trail entry for dynamic CIDR mitigation actions.
 */
public record MitigationAuditEntry(
		Long id,
		Long ruleId,
		String cidr,
		String batchId,
		String action,
		String actor,
		Integer ttlSeconds,
		String details,
		Instant createdAt
) {
	private static final DateTimeFormatter TS_FMT =
			DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

	public static final String ACTION_CREATED = "CREATED";
	public static final String ACTION_EXTENDED = "EXTENDED";
	public static final String ACTION_REVOKED = "REVOKED";
	public static final String ACTION_EXPIRED = "EXPIRED";
	public static final String ACTION_RESYNCED = "RESYNCED";

	public String formattedCreatedAt() {
		return createdAt != null ? TS_FMT.format(createdAt) : "-";
	}

	// JavaBean getters for Thymeleaf / SpringEL compatibility
	public Long getId() { return id; }
	public Long getRuleId() { return ruleId; }
	public String getCidr() { return cidr; }
	public String getBatchId() { return batchId; }
	public String getAction() { return action; }
	public String getActor() { return actor; }
	public Integer getTtlSeconds() { return ttlSeconds; }
	public String getDetails() { return details; }
	public Instant getCreatedAt() { return createdAt; }
}

