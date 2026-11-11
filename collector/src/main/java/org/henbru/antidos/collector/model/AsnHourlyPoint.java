package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.util.List;

/**
 * Hourly telemetry data point for an Autonomous System (ASN).
 */
public record AsnHourlyPoint(
		Instant bucketStart,
		String hourLabel,
		long totalRequests,
		int activeSubnets,
		long returningRequests,
		double returningRatioPct,
		long authenticatedRequests,
		long blockedRequests,
		double blockedRatioPct,
		long markedRequests,
		long distinctClients,
		List<String> targetedServers
) {
	public boolean hasHighReturningRatio() {
		return returningRatioPct >= 20.0;
	}

	public boolean hasBlocks() {
		return blockedRequests > 0 || markedRequests > 0;
	}
}

