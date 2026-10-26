package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Domain record representing an aggregated traffic and client-signature rollup for a subnet group
 * across a specific time bucket on a monitored server and valve.
 */
public record ClientSubnetRollup(
		Long id,
		Instant bucketStart,
		Instant bucketEnd,
		int bucketMinutes,
		String serverId,
		String valveName,
		String subnetGroup,
		long totalRequests,
		long activeRequests,
		long blockedRequests,
		int distinctClients,
		int minRequestsPerClient,
		int maxRequestsPerClient,
		int slotsActiveCount,
		Long asn,
		String asOrg,
		String countryCode,
		ClientType clientType,
		Instant createdAt,
		long returningRequests,
		long returningTrackedRequests,
		long authenticatedRequests,
		long authenticatedTrackedRequests
) {

	public ClientSubnetRollup(
			Long id,
			Instant bucketStart,
			Instant bucketEnd,
			int bucketMinutes,
			String serverId,
			String valveName,
			String subnetGroup,
			long totalRequests,
			long activeRequests,
			long blockedRequests,
			int distinctClients,
			int minRequestsPerClient,
			int maxRequestsPerClient,
			int slotsActiveCount,
			Long asn,
			String asOrg,
			String countryCode,
			ClientType clientType,
			Instant createdAt
	) {
		this(
				id,
				bucketStart,
				bucketEnd,
				bucketMinutes,
				serverId,
				valveName,
				subnetGroup,
				totalRequests,
				activeRequests,
				blockedRequests,
				distinctClients,
				minRequestsPerClient,
				maxRequestsPerClient,
				slotsActiveCount,
				asn,
				asOrg,
				countryCode,
				clientType,
				createdAt,
				0L,
				0L,
				0L,
				0L
		);
	}

	public ClientSubnetRollup(
			Long id,
			Instant bucketStart,
			Instant bucketEnd,
			int bucketMinutes,
			String serverId,
			String valveName,
			String subnetGroup,
			long totalRequests,
			long activeRequests,
			long blockedRequests,
			int distinctClients,
			int minRequestsPerClient,
			int maxRequestsPerClient,
			int slotsActiveCount,
			Long asn,
			String asOrg,
			String countryCode,
			ClientType clientType
	) {
		this(
				id,
				bucketStart,
				bucketEnd,
				bucketMinutes,
				serverId,
				valveName,
				subnetGroup,
				totalRequests,
				activeRequests,
				blockedRequests,
				distinctClients,
				minRequestsPerClient,
				maxRequestsPerClient,
				slotsActiveCount,
				asn,
				asOrg,
				countryCode,
				clientType != null ? clientType : ClientType.UNKNOWN,
				Instant.now(),
				0L,
				0L,
				0L,
				0L
		);
	}

	public ClientSubnetRollup(
			Long id,
			Instant bucketStart,
			Instant bucketEnd,
			int bucketMinutes,
			String serverId,
			String valveName,
			String subnetGroup,
			long totalRequests,
			long activeRequests,
			long blockedRequests,
			int distinctClients,
			int minRequestsPerClient,
			int maxRequestsPerClient,
			int slotsActiveCount,
			Long asn,
			String asOrg,
			String countryCode,
			ClientType clientType,
			long returningRequests,
			long returningTrackedRequests,
			long authenticatedRequests,
			long authenticatedTrackedRequests
	) {
		this(
				id,
				bucketStart,
				bucketEnd,
				bucketMinutes,
				serverId,
				valveName,
				subnetGroup,
				totalRequests,
				activeRequests,
				blockedRequests,
				distinctClients,
				minRequestsPerClient,
				maxRequestsPerClient,
				slotsActiveCount,
				asn,
				asOrg,
				countryCode,
				clientType != null ? clientType : ClientType.UNKNOWN,
				Instant.now(),
				returningRequests,
				returningTrackedRequests,
				authenticatedRequests,
				authenticatedTrackedRequests
		);
	}

	/**
	 * Calculates the average requests per observed client IP in this subnet window.
	 */
	public double averageRequestsPerClient() {
		return distinctClients > 0 ? (double) totalRequests / distinctClients : 0.0;
	}

	/**
	 * Heuristic indicator for potential distributed residential proxy / low-and-slow abuse:
	 * High number of distinct IPs, low average requests per IP, and classified as residential or unknown ISP.
	 */
	public boolean isPotentialResidentialProxy() {
		return distinctClients >= 5
				&& averageRequestsPerClient() <= 5.0
				&& (ClientType.RESIDENTIAL.equals(clientType) || ClientType.UNKNOWN.equals(clientType));
	}

	public Double returningRatio() {
		return returningTrackedRequests > 0
				? (returningRequests * 100.0 / returningTrackedRequests)
				: null;
	}

	public Double authenticatedRatio() {
		return authenticatedTrackedRequests > 0
				? (authenticatedRequests * 100.0 / authenticatedTrackedRequests)
				: null;
	}

	public boolean isReturningTracked() {
		return returningTrackedRequests > 0;
	}

	public boolean isAuthenticatedTracked() {
		return authenticatedTrackedRequests > 0;
	}
}
