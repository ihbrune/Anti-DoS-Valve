package org.henbru.antidos.collector.model;

import java.util.List;

/**
 * Forensics and rate-limit statistics for a concrete client User-Agent string,
 * including origin ASNs, subnet diversity, and heuristic bot/scraper suspicion.
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
		String mitigationMatchDetails
) {
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
				false, false, null);
	}

	public String displayName() {
		return family != null ? family.displayName() : "Unknown";
	}

	public String icon() {
		return family != null ? family.icon() : "&#x2753;";
	}

	public boolean hasAuthenticatedTraffic() {
		return authenticatedCount > 0;
	}

	public boolean isAutomated() {
		return family != null && family.isAutomated();
	}

	public boolean hasAutomatedSignature() {
		return isAutomated() || (family == UserAgentFamily.EMPTY);
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
}

