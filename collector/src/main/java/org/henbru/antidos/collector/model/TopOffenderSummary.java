package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Summary record representing an IP address, subnet partition, or autonomous system (ASN) across the fleet.
 */
public record TopOffenderSummary(
		String clientKey,
		long totalBlockIncidents,
		long totalBlockedRequests,
		int distinctServersTargeted,
		String serversList,
		Instant firstSeen,
		Instant lastSeen,
		Long asn,
		String asOrg,
		String countryCode,
		ClientType clientType,
		int distinctClientsCount
) {

	public TopOffenderSummary(
			String clientKey,
			long totalBlockIncidents,
			long totalBlockedRequests,
			int distinctServersTargeted,
			String serversList,
			Instant firstSeen,
			Instant lastSeen
	) {
		this(
				clientKey,
				totalBlockIncidents,
				totalBlockedRequests,
				distinctServersTargeted,
				serversList,
				firstSeen,
				lastSeen,
				null,
				null,
				null,
				ClientType.UNKNOWN,
				1
		);
	}

	/**
	 * Indicates a distributed residential proxy botnet pattern where requests are fanned out
	 * across many rotating IPs with low requests per IP.
	 */
	public boolean isRotatingProxyCluster() {
		return distinctClientsCount >= 3 && ((double) totalBlockedRequests / distinctClientsCount) < 15.0;
	}

	public double requestsPerClient() {
		return distinctClientsCount > 0 ? (double) totalBlockedRequests / distinctClientsCount : 0.0;
	}
}
