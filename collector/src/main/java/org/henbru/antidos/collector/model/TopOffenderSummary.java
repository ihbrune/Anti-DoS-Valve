package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Summary record representing an IP address, subnet partition, or autonomous system (ASN) across the fleet.
 */
public record TopOffenderSummary(
		String clientKey,
		long totalBlockedRequests,
		long totalMarkedRequests,
		long totalRequests,
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
			long totalBlockedRequests,
			long totalRequests,
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
		this(
				clientKey,
				totalBlockedRequests,
				0L,
				totalRequests,
				distinctServersTargeted,
				serversList,
				firstSeen,
				lastSeen,
				asn,
				asOrg,
				countryCode,
				clientType,
				distinctClientsCount
		);
	}

	public TopOffenderSummary(
			String clientKey,
			long totalBlockedRequests,
			long totalRequests,
			int distinctServersTargeted,
			String serversList,
			Instant firstSeen,
			Instant lastSeen
	) {
		this(
				clientKey,
				totalBlockedRequests,
				0L,
				totalRequests,
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
	 * Backward compatibility alias for views or callers referencing totalBlockIncidents.
	 */
	public long totalBlockIncidents() {
		return totalBlockedRequests;
	}

	public long totalMarkIncidents() {
		return totalMarkedRequests;
	}

	/**
	 * Indicates a distributed residential proxy botnet pattern where requests are fanned out
	 * across many rotating IPs with low requests per IP.
	 */
	public boolean isRotatingProxyCluster() {
		return distinctClientsCount >= 3 && ((double) totalRequests / distinctClientsCount) < 15.0;
	}

	public double requestsPerClient() {
		return distinctClientsCount > 0 ? (double) totalRequests / distinctClientsCount : 0.0;
	}

	/**
	 * Returns the canonical subnet partition (/24 for IPv4, /64 for IPv6) if this is an IP key.
	 */
	public String subnetGroup() {
		if (clientKey == null || clientKey.isBlank()) {
			return "";
		}
		if (clientKey.contains("/")) {
			return clientKey;
		}
		if (clientKey.startsWith("AS")) {
			return "";
		}
		org.henbru.antidos.collector.model.IpNetworkInfo info = org.henbru.antidos.collector.util.IpNetworkUtil.parse(clientKey);
		return info.subnetGroup() != null ? info.subnetGroup() : "";
	}
}
