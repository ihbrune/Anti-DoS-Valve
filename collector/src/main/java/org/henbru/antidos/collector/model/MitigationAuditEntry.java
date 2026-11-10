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

	/**
	 * Extracts the target ASN number from cidr (e.g. ASN-64496), batchId (e.g. AUTO-ASN-64496-...)
	 * or details (e.g. ASN 64496), or null if no ASN is associated.
	 */
	public Long getAsn() {
		if (cidr != null && cidr.startsWith("ASN-")) {
			try {
				return Long.parseLong(cidr.substring(4).trim());
			} catch (Exception ignored) {}
		}
		if (batchId != null) {
			java.util.regex.Matcher m = java.util.regex.Pattern.compile("ASN-(\\d+)").matcher(batchId);
			if (m.find()) {
				try {
					return Long.parseLong(m.group(1));
				} catch (Exception ignored) {}
			}
		}
		if (details != null) {
			java.util.regex.Matcher m = java.util.regex.Pattern.compile("ASN\\s+(\\d+)").matcher(details);
			if (m.find()) {
				try {
					return Long.parseLong(m.group(1));
				} catch (Exception ignored) {}
			}
		}
		return null;
	}
}

