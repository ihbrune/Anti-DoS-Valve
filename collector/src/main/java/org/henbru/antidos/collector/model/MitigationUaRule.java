package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Persistent dynamic User-Agent block rule managed by the Anti-DoS Collector.
 */
public record MitigationUaRule(
		Long id,
		String userAgentHash,
		int uaHash32,
		String rawUserAgent,
		String browserFamily,
		String targetScope,
		String status,
		String source,
		String batchId,
		String reason,
		Instant createdAt,
		Instant updatedAt,
		Instant expiresAt,
		Instant revokedAt,
		String revokedReason,
		long totalBlockedHits,
		long totalBypassedHits,
		Instant lastHitAt,
		String deterrenceState
) {
	public static final String STATUS_ACTIVE = "ACTIVE";
	public static final String STATUS_EXPIRED = "EXPIRED";
	public static final String STATUS_REVOKED = "REVOKED";

	public static final String SOURCE_MANUAL = "MANUAL";
	public static final String SOURCE_AUTO_UA = "AUTO_UA";

	public static final String DETERRENCE_OBSERVING = "OBSERVING";
	public static final String DETERRENCE_DETERRED = "DETERRED";
	public static final String DETERRENCE_PERSISTENT = "PERSISTENT";

	public MitigationUaRule(
			Long id,
			String userAgentHash,
			int uaHash32,
			String rawUserAgent,
			String browserFamily,
			String targetScope,
			String status,
			String source,
			String batchId,
			String reason,
			Instant createdAt,
			Instant updatedAt,
			Instant expiresAt,
			Instant revokedAt,
			String revokedReason,
			long totalBlockedHits,
			long totalBypassedHits,
			Instant lastHitAt
	) {
		this(id, userAgentHash, uaHash32, rawUserAgent, browserFamily, targetScope,
				status, source, batchId, reason, createdAt, updatedAt, expiresAt,
				revokedAt, revokedReason, totalBlockedHits, totalBypassedHits, lastHitAt,
				DETERRENCE_OBSERVING);
	}

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

	public String shortUserAgent() {
		if (rawUserAgent == null || rawUserAgent.isBlank() || "<EMPTY>".equalsIgnoreCase(rawUserAgent.trim())) {
			return "[Empty / Missing User-Agent]";
		}
		return rawUserAgent.length() > 96 ? rawUserAgent.substring(0, 93) + "..." : rawUserAgent;
	}

	public String hexHash32() {
		return String.format("0x%08x", uaHash32);
	}

	public String shortSha256() {
		if (userAgentHash == null) {
			return "-";
		}
		return userAgentHash.length() > 12 ? userAgentHash.substring(0, 12) : userAgentHash;
	}

	public String statusBadgeClass() {
		if (STATUS_ACTIVE.equalsIgnoreCase(status)) {
			return "bg-rose-500/20 text-rose-300 border border-rose-500/40";
		}
		if (STATUS_REVOKED.equalsIgnoreCase(status)) {
			return "bg-slate-600/30 text-slate-300 border border-slate-500/40";
		}
		return "bg-amber-500/20 text-amber-300 border border-amber-500/40";
	}

	public String sourceBadgeClass() {
		if (SOURCE_AUTO_UA.equalsIgnoreCase(source)) {
			return "bg-purple-500/20 text-purple-300 border border-purple-500/40";
		}
		return "bg-sky-500/20 text-sky-300 border border-sky-500/40";
	}

	public String deterrenceBadgeClass() {
		if (DETERRENCE_DETERRED.equalsIgnoreCase(deterrenceState)) {
			return "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
		}
		if (DETERRENCE_PERSISTENT.equalsIgnoreCase(deterrenceState)) {
			return "bg-rose-500/20 text-rose-300 border border-rose-500/40";
		}
		return "bg-amber-500/20 text-amber-300 border border-amber-500/40";
	}

	// JavaBean getters for Thymeleaf / SpringEL compatibility
	public Long getId() { return id; }
	public String getUserAgentHash() { return userAgentHash; }
	public int getUaHash32() { return uaHash32; }
	public String getRawUserAgent() { return rawUserAgent; }
	public String getBrowserFamily() { return browserFamily; }
	public String getTargetScope() { return targetScope; }
	public String getStatus() { return status; }
	public String getSource() { return source; }
	public String getBatchId() { return batchId; }
	public String getReason() { return reason; }
	public Instant getCreatedAt() { return createdAt; }
	public Instant getUpdatedAt() { return updatedAt; }
	public Instant getExpiresAt() { return expiresAt; }
	public Instant getRevokedAt() { return revokedAt; }
	public String getRevokedReason() { return revokedReason; }
	public long getTotalBlockedHits() { return totalBlockedHits; }
	public long getTotalBypassedHits() { return totalBypassedHits; }
	public Instant getLastHitAt() { return lastHitAt; }
	public String getDeterrenceState() { return deterrenceState; }
}
