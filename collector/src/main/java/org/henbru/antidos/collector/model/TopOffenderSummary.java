package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Summary record representing an IP address or subnet partition across the fleet.
 */
public record TopOffenderSummary(
		String clientKey,
		long totalBlockIncidents,
		long totalBlockedRequests,
		int distinctServersTargeted,
		String serversList,
		Instant firstSeen,
		Instant lastSeen
) {
}
