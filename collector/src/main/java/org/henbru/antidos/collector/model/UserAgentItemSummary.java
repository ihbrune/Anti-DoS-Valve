package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Forensics and rate-limit statistics for a concrete client User-Agent string,
 * including origin ASNs, subnet diversity, 3-pillar heuristic assessment,
 * Stage-0 immunity status, and non-overwritable manual overrides.
 */
public record UserAgentItemSummary(
		String userAgent,
		UserAgentFamily family,
		long totalRequests,
		int eventCount,
		int blockedCount,
		int markedCount,
		int activeCount,
		int authenticatedCount,
		double blockMarkRatioPercent,
		int distinctSubnets,
		int distinctAsns,
		int datacenterCount,
		int residentialCount,
		double datacenterRatioPercent,
		boolean isSuspicious,
		String suspicionReason,
		List<UserAgentOriginSummary> topOrigins,
		boolean residentialZeroAuthAnomaly,
		boolean mitigationMatch,
		String mitigationMatchDetails,
		BrowserVersionLagAssessment versionAssessment,
		Integer parsedMajorVersion,
		Integer versionLagMajors,
		String userAgentHash,
		UserAgentAutoVerdict autoVerdict,
		UserAgentManualOverride manualOverride,
		String operatorNote,
		Instant firstSeenAt,
		Instant lastSeenAt,
		double internalRatioPercent,
		double sampleAuthRatioPercent,
		double slotAuthRatioPercent,
		double mitigatedAsnRatioPercent,
		double uaMismatchRatioPercent,
		double avgRequestsPerSlot
) {
	private static final DateTimeFormatter SHORT_DT_FMT = DateTimeFormatter.ofPattern("dd.MM. HH:mm");

	public UserAgentItemSummary(
			String userAgent,
			UserAgentFamily family,
			long totalRequests,
			int eventCount,
			int blockedCount,
			int markedCount,
			int activeCount,
			int authenticatedCount,
			double blockMarkRatioPercent,
			int distinctSubnets,
			int distinctAsns,
			int datacenterCount,
			int residentialCount,
			double datacenterRatioPercent,
			boolean isSuspicious,
			String suspicionReason,
			List<UserAgentOriginSummary> topOrigins,
			boolean residentialZeroAuthAnomaly,
			boolean mitigationMatch,
			String mitigationMatchDetails,
			BrowserVersionLagAssessment versionAssessment,
			Integer parsedMajorVersion,
			Integer versionLagMajors
	) {
		this(userAgent, family, totalRequests, eventCount, blockedCount, markedCount, activeCount,
				authenticatedCount, blockMarkRatioPercent, distinctSubnets, distinctAsns, datacenterCount,
				residentialCount, datacenterRatioPercent, isSuspicious, suspicionReason, topOrigins,
				residentialZeroAuthAnomaly, mitigationMatch, mitigationMatchDetails,
				versionAssessment, parsedMajorVersion, versionLagMajors,
				null,
				isSuspicious ? UserAgentAutoVerdict.SUSPICIOUS_SIGNATURE : (authenticatedCount > 0 ? UserAgentAutoVerdict.IMMUNE_AUTHENTICATED : UserAgentAutoVerdict.NEUTRAL),
				UserAgentManualOverride.AUTO, null, null, null,
				0.0, 0.0, 0.0, 0.0, 0.0,
				eventCount > 0 ? Math.round((totalRequests * 10.0) / eventCount) / 10.0 : 0.0);
	}

	public UserAgentItemSummary(
			String userAgent,
			UserAgentFamily family,
			long totalRequests,
			int eventCount,
			int blockedCount,
			int markedCount,
			int activeCount,
			int authenticatedCount,
			double blockMarkRatioPercent,
			int distinctSubnets,
			int distinctAsns,
			int datacenterCount,
			int residentialCount,
			double datacenterRatioPercent,
			boolean isSuspicious,
			String suspicionReason,
			List<UserAgentOriginSummary> topOrigins,
			boolean residentialZeroAuthAnomaly,
			boolean mitigationMatch,
			String mitigationMatchDetails
	) {
		this(userAgent, family, totalRequests, eventCount, blockedCount, markedCount, activeCount,
				authenticatedCount, blockMarkRatioPercent, distinctSubnets, distinctAsns, datacenterCount,
				residentialCount, datacenterRatioPercent, isSuspicious, suspicionReason, topOrigins,
				residentialZeroAuthAnomaly, mitigationMatch, mitigationMatchDetails,
				BrowserVersionLagAssessment.UNTRACKED, null, null);
	}

	public UserAgentItemSummary(
			String userAgent,
			UserAgentFamily family,
			long totalRequests,
			int eventCount,
			int blockedCount,
			int markedCount,
			int activeCount,
			int authenticatedCount,
			double blockMarkRatioPercent,
			int distinctSubnets,
			int distinctAsns,
			int datacenterCount,
			int residentialCount,
			double datacenterRatioPercent,
			boolean isSuspicious,
			String suspicionReason,
			List<UserAgentOriginSummary> topOrigins
	) {
		this(userAgent, family, totalRequests, eventCount, blockedCount, markedCount, activeCount,
				authenticatedCount, blockMarkRatioPercent, distinctSubnets, distinctAsns, datacenterCount,
				residentialCount, datacenterRatioPercent, isSuspicious, suspicionReason, topOrigins,
				false, false, null,
				BrowserVersionLagAssessment.UNTRACKED, null, null);
	}

	public String displayName() {
		return family != null ? family.displayName() : "Unknown";
	}

	public String icon() {
		return family != null ? family.icon() : "&#x2753;";
	}

	public boolean hasAuthenticatedTraffic() {
		return authenticatedCount > 0 || sampleAuthRatioPercent >= 1.0 || slotAuthRatioPercent >= 2.0;
	}

	public boolean isAutomated() {
		return family != null && family.isAutomated();
	}

	public boolean hasAutomatedSignature() {
		return (isAutomated() || (family == UserAgentFamily.EMPTY)) && !isImmune();
	}

	public boolean hasHighIncidentRate() {
		return blockMarkRatioPercent >= 50.0 && incidentCount() >= 2;
	}

	public boolean hasDatacenterConcentration() {
		return datacenterRatioPercent >= 75.0 && datacenterCount >= 2;
	}

	public boolean hasResidentialZeroAuthAnomaly() {
		return residentialZeroAuthAnomaly;
	}

	public boolean hasMitigationMatch() {
		return mitigationMatch;
	}

	public boolean hasEmptySignature() {
		return family == UserAgentFamily.EMPTY;
	}

	public int incidentCount() {
		return blockedCount + markedCount;
	}

	public boolean hasVersionAnomaly() {
		return versionAssessment == BrowserVersionLagAssessment.IMPLAUSIBLE_FUTURE
				|| versionAssessment == BrowserVersionLagAssessment.OBSOLETE_ANOMALY;
	}

	public boolean isPreReleasePreview() {
		return versionAssessment == BrowserVersionLagAssessment.PRE_RELEASE_PLAUSIBLE;
	}

	public boolean isOutdatedVersion() {
		return versionAssessment == BrowserVersionLagAssessment.OUTDATED_LAG;
	}

	public boolean isImplausibleFutureVersion() {
		return versionAssessment == BrowserVersionLagAssessment.IMPLAUSIBLE_FUTURE;
	}

	public boolean isObsoleteVersion() {
		return versionAssessment == BrowserVersionLagAssessment.OBSOLETE_ANOMALY;
	}

	public UserAgentAutoVerdict safeAutoVerdict() {
		return autoVerdict != null ? autoVerdict : UserAgentAutoVerdict.NEUTRAL;
	}

	public UserAgentManualOverride safeManualOverride() {
		return manualOverride != null ? manualOverride : UserAgentManualOverride.AUTO;
	}

	public boolean hasManualOverride() {
		return safeManualOverride().isManual();
	}

	public boolean isImmune() {
		return safeAutoVerdict().isImmune();
	}

	public boolean hasOperatorNote() {
		return operatorNote != null && !operatorNote.isBlank();
	}

	public String formattedFirstSeen() {
		return firstSeenAt != null ? SHORT_DT_FMT.format(firstSeenAt.atZone(ZoneId.systemDefault())) : null;
	}

	public String formattedLastSeen() {
		return lastSeenAt != null ? SHORT_DT_FMT.format(lastSeenAt.atZone(ZoneId.systemDefault())) : null;
	}
}
