package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Persistent dynamic CIDR block rule managed by the Anti-DoS Collector.
 */
public record MitigationRule(
		Long id,
		String cidr,
		int ipVersion,
		int prefixLength,
		String targetScope,
		String status,
		String source,
		String batchId,
		String reason,
		Long asn,
		String asnOrganization,
		Instant createdAt,
		Instant updatedAt,
		Instant expiresAt,
		Instant revokedAt,
		String revokedReason,
		long totalBlockedHits,
		int peakDistinctIps,
		Instant lastHitAt,
		String deterrenceState
) {
	public static final String STATUS_ACTIVE = "ACTIVE";
	public static final String STATUS_EXPIRED = "EXPIRED";
	public static final String STATUS_REVOKED = "REVOKED";

	public static final String SOURCE_MANUAL = "MANUAL";
	public static final String SOURCE_ASN_BATCH = "ASN_BATCH";
	public static final String SOURCE_ADVISOR = "ADVISOR";
	public static final String SOURCE_AUTO_RULE = "AUTO_RULE";
	public static final String SOURCE_AUTO_CARPET = "AUTO_CARPET";

	public static final String DETERRENCE_OBSERVING = "OBSERVING";
	public static final String DETERRENCE_DETERRED = "DETERRED";
	public static final String DETERRENCE_PERSISTENT = "PERSISTENT";

	public boolean isActiveAt(Instant now) {
		return STATUS_ACTIVE.equalsIgnoreCase(status) && expiresAt != null && expiresAt.isAfter(now);
	}

	public boolean isCurrentlyActive(Instant now) {
		return isActiveAt(now);
	}

	public long remainingSeconds(Instant now) {
		if (expiresAt == null || !expiresAt.isAfter(now)) {
			return 0L;
		}
		return Math.max(0L, ChronoUnit.SECONDS.between(now, expiresAt));
	}

	public long remainingMinutes(Instant now) {
		if (expiresAt == null || !expiresAt.isAfter(now)) {
			return 0L;
		}
		return Math.max(1L, ChronoUnit.MINUTES.between(now, expiresAt));
	}

	public String formattedRemaining(Instant now) {
		if (!isActiveAt(now)) {
			return "Expired";
		}
		long sec = ChronoUnit.SECONDS.between(now, expiresAt);
		if (sec < 60) {
			return sec + "s";
		}
		long min = sec / 60;
		if (min < 60) {
			return min + "m";
		}
		long h = min / 60;
		long remM = min % 60;
		return remM > 0 ? h + "h " + remM + "m" : h + "h";
	}

	// JavaBean getters for Thymeleaf / SpringEL compatibility
	public Long getId() { return id; }
	public String getCidr() { return cidr; }
	public int getIpVersion() { return ipVersion; }
	public int getPrefixLength() { return prefixLength; }
	public String getTargetScope() { return targetScope; }
	public String getStatus() { return status; }
	public String getSource() { return source; }
	public String getBatchId() { return batchId; }
	public String getReason() { return reason; }
	public Long getAsn() { return asn; }
	public String getAsnOrganization() { return asnOrganization; }
	public Instant getCreatedAt() { return createdAt; }
	public Instant getUpdatedAt() { return updatedAt; }
	public Instant getExpiresAt() { return expiresAt; }
	public Instant getRevokedAt() { return revokedAt; }
	public String getRevokedReason() { return revokedReason; }
	public long getTotalBlockedHits() { return totalBlockedHits; }
	public int getPeakDistinctIps() { return peakDistinctIps; }
	public Instant getLastHitAt() { return lastHitAt; }
	public String getDeterrenceState() { return deterrenceState; }
}
