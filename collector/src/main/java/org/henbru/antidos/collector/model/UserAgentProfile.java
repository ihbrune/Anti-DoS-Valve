package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Persistent long-term profile stored in {@code dim_user_agent}, retaining lifetime statistics,
 * 24-hour snapshot metrics, automated 3-pillar verdict, and non-overwritable manual overrides.
 */
public record UserAgentProfile(
		Long id,
		String userAgentHash,
		int uaHash32,
		String rawUserAgent,
		UserAgentFamily browserFamily,
		Integer parsedMajorVersion,
		boolean bot,
		Instant firstSeenAt,
		Instant lastSeenAt,
		long totalLifetimeRequests,
		long totalBlockedRequests,
		long totalMarkedRequests,
		long totalAuthenticatedSamples,
		long totalAuthenticatedRequests,
		long totalInternalRequests,
		long totalCrawlerRequests,
		long last24hRequests,
		int last24hEvents,
		long last24hBlockedRequests,
		long last24hMarkedRequests,
		int last24hDistinctSubnets,
		int last24hDistinctAsns,
		int last24hAuthSamples,
		long last24hAuthRequests,
		long last24hInternalRequests,
		long last24hCrawlerRequests,
		long last24hDatacenterRequests,
		long last24hResidentialRequests,
		long last24hReturningRequests,
		long last24hUaMismatchRequests,
		UserAgentAutoVerdict autoVerdict,
		String autoPillar,
		String autoVerdictReason,
		Instant autoEvaluatedAt,
		UserAgentManualOverride manualOverride,
		String operatorNote,
		String updatedBy,
		Instant updatedAt
) {
	private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

	public UserAgentManualOverride effectiveOverride() {
		return manualOverride != null ? manualOverride : UserAgentManualOverride.AUTO;
	}

	public UserAgentAutoVerdict effectiveAutoVerdict() {
		return autoVerdict != null ? autoVerdict : UserAgentAutoVerdict.NEUTRAL;
	}

	public boolean isEffectiveSuspicious() {
		return effectiveOverride().isEffectiveSuspicious(effectiveAutoVerdict());
	}

	public boolean isEffectiveProtected() {
		return effectiveOverride().isEffectiveProtected(effectiveAutoVerdict());
	}

	public boolean hasManualOverride() {
		return effectiveOverride().isManual();
	}

	public double internalRatioPct24h() {
		return last24hRequests > 0 ? Math.round((last24hInternalRequests * 1000.0) / last24hRequests) / 10.0 : 0.0;
	}

	public double crawlerRatioPct24h() {
		return last24hRequests > 0 ? Math.round((last24hCrawlerRequests * 1000.0) / last24hRequests) / 10.0 : 0.0;
	}

	public double sampleAuthRatioPct24h() {
		return last24hEvents > 0 ? Math.round((last24hAuthSamples * 1000.0) / last24hEvents) / 10.0 : 0.0;
	}

	public double slotAuthRatioPct24h() {
		return last24hRequests > 0 ? Math.round((last24hAuthRequests * 1000.0) / last24hRequests) / 10.0 : 0.0;
	}

	public double datacenterRatioPct24h() {
		return last24hRequests > 0 ? Math.round((last24hDatacenterRequests * 1000.0) / last24hRequests) / 10.0 : 0.0;
	}

	public String formattedFirstSeen() {
		return firstSeenAt != null ? TS_FMT.format(firstSeenAt.atZone(ZoneId.systemDefault())) : "—";
	}

	public String formattedLastSeen() {
		return lastSeenAt != null ? TS_FMT.format(lastSeenAt.atZone(ZoneId.systemDefault())) : "—";
	}
}
