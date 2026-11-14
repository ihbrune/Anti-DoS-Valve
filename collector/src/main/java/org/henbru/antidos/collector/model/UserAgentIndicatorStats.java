package org.henbru.antidos.collector.model;

/**
 * Aggregated counters of heuristic risk and legitimacy indicators evaluated across
 * observed User-Agents within the selected analytical window.
 */
public record UserAgentIndicatorStats(
		int totalEvaluated,
		int suspiciousCount,
		int standardCount,
		int legitimateCount,
		int residentialZeroAuthCount,
		int mitigationMatchCount,
		int highIncidentCount,
		int datacenterCount,
		int automatedCount,
		int authenticatedCount
) {
	public static UserAgentIndicatorStats empty() {
		return new UserAgentIndicatorStats(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	}
}
