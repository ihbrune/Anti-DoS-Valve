package org.henbru.antidos.collector.model;

/**
 * Aggregated fleet-wide metrics for dashboard display.
 */
public record FleetSummary(
		int totalEndpoints,
		int onlineEndpoints,
		int offlineEndpoints,
		int totalValvesMonitored,
		long totalRequests24h,
		long totalBlockedRequests24h,
		long distinctBlockedClients24h
) {
	public static FleetSummary empty() {
		return new FleetSummary(0, 0, 0, 0, 0, 0, 0);
	}

	public double blockRatePercentage() {
		if (totalRequests24h <= 0) {
			return 0.0;
		}
		return ((double) totalBlockedRequests24h / (double) totalRequests24h) * 100.0;
	}
}
