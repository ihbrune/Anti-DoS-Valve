package org.henbru.antidos.collector.model;

/**
 * Aggregated metric for a specific client/traffic category in donut charts.
 *
 * @param clientType Classified client type
 * @param label Human-readable label
 * @param icon Emoji or symbol representation
 * @param totalRequests Total requests attributed to this category
 * @param blockedRequests Blocked requests within this category
 * @param subnetCount Number of distinct subnets observed
 * @param percentage Percentage of total fleet traffic
 */
public record TrafficCompositionPoint(
		ClientType clientType,
		String label,
		String icon,
		long totalRequests,
		long blockedRequests,
		long markedRequests,
		int subnetCount,
		double percentage
) {
	public TrafficCompositionPoint(
			ClientType clientType,
			String label,
			String icon,
			long totalRequests,
			long blockedRequests,
			int subnetCount,
			double percentage
	) {
		this(clientType, label, icon, totalRequests, blockedRequests, 0L, subnetCount, percentage);
	}

	public double blockedRatioPercent() {
		if (totalRequests <= 0) {
			return 0.0;
		}
		return Math.round(((double) blockedRequests / totalRequests) * 1000.0) / 10.0;
	}

	public double markedRatioPercent() {
		if (totalRequests <= 0) {
			return 0.0;
		}
		return Math.round(((double) markedRequests / totalRequests) * 1000.0) / 10.0;
	}
}
