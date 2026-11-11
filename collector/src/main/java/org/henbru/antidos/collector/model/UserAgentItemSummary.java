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
		List<UserAgentOriginSummary> topOrigins
) {
	public String displayName() {
		return family != null ? family.displayName() : "Unknown";
	}

	public String icon() {
		return family != null ? family.icon() : "&#x2753;";
	}

	public boolean hasAuthenticatedTraffic() {
		return authenticatedCount > 0;
	}

	public int incidentCount() {
		return blockedCount + markedCount;
	}
}

