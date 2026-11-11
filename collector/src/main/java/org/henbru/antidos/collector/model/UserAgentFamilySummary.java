package org.henbru.antidos.collector.model;

/**
 * Aggregated metrics for a single User-Agent family (e.g. Chrome Desktop, HTTP Tools).
 */
public record UserAgentFamilySummary(
		UserAgentFamily family,
		long totalRequests,
		int eventCount,
		int blockedCount,
		int markedCount,
		int activeCount,
		int authenticatedCount,
		double blockMarkRatioPercent,
		double sharePercent
) {
	public String displayName() {
		return family != null ? family.displayName() : "Unknown";
	}

	public String icon() {
		return family != null ? family.icon() : "&#x2753;";
	}

	public boolean isAutomated() {
		return family != null && family.isAutomated();
	}
}

