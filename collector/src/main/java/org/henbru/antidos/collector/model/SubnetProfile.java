package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Domain record representing long-term frequency baselines, first-seen and dormancy metrics,
 * and recent surge ratios for an IP subnet group.
 */
public record SubnetProfile(
		String subnetGroup,
		Instant firstSeenAt,
		Instant lastSeenAt,
		int daysDormantBeforeLastSeen,
		long totalLifetimeRequests,
		long totalActiveRequests,
		long totalBlockedRequests,
		double baselineDailyAvg,
		int baselineDistinctClients,
		long peakDailyRequests,
		long last24hRequests,
		int last24hDistinctClients,
		long last24hBlockedRequests,
		double last24hSurgeFactor,
		Long asn,
		String asOrg,
		String countryCode,
		ClientType clientType,
		Instant updatedAt
) {

	public SubnetProfile(
			String subnetGroup,
			Instant firstSeenAt,
			Instant lastSeenAt,
			int daysDormantBeforeLastSeen,
			long totalLifetimeRequests,
			long totalActiveRequests,
			long totalBlockedRequests,
			double baselineDailyAvg,
			int baselineDistinctClients,
			long peakDailyRequests,
			long last24hRequests,
			int last24hDistinctClients,
			long last24hBlockedRequests,
			double last24hSurgeFactor,
			Long asn,
			String asOrg,
			String countryCode,
			ClientType clientType
	) {
		this(
				subnetGroup,
				firstSeenAt,
				lastSeenAt,
				daysDormantBeforeLastSeen,
				totalLifetimeRequests,
				totalActiveRequests,
				totalBlockedRequests,
				baselineDailyAvg,
				baselineDistinctClients,
				peakDailyRequests,
				last24hRequests,
				last24hDistinctClients,
				last24hBlockedRequests,
				last24hSurgeFactor,
				asn,
				asOrg,
				countryCode,
				clientType != null ? clientType : ClientType.UNKNOWN,
				Instant.now()
		);
	}

	/**
	 * Checks if the subnet was first observed recently within the given maximum days.
	 */
	public boolean isNewSubnet(int maxDaysOld) {
		if (daysDormantBeforeLastSeen >= 900) {
			return true;
		}
		if (firstSeenAt == null) {
			return false;
		}
		return firstSeenAt.isAfter(Instant.now().minus(maxDaysOld, ChronoUnit.DAYS));
	}

	/**
	 * Checks if this subnet broke out of an extended dormancy period.
	 */
	public boolean isDormantBreakout(int thresholdDays) {
		return daysDormantBeforeLastSeen >= thresholdDays && daysDormantBeforeLastSeen < 900;
	}

	/**
	 * Checks if current 24-hour traffic exhibits a significant surge over the historical baseline.
	 */
	public boolean isHighSurge(double thresholdMultiplier) {
		return last24hSurgeFactor >= thresholdMultiplier;
	}

	/**
	 * Calculates average requests per distinct client IP in the last 24h.
	 */
	public double averageRequestsPerClient24h() {
		return last24hDistinctClients > 0 ? (double) last24hRequests / last24hDistinctClients : 0.0;
	}

	/**
	 * Calculates the 429 block rate in the last 24h as a percentage (0.0 to 100.0).
	 */
	public double blockRate24h() {
		return last24hRequests > 0 ? ((double) last24hBlockedRequests / last24hRequests) * 100.0 : 0.0;
	}

	/**
	 * Heuristic indicator for potential distributed residential proxy pools / low-and-slow campaigns.
	 */
	public boolean isPotentialResidentialProxyPool() {
		return last24hDistinctClients >= 5
				&& averageRequestsPerClient24h() <= 20.0
				&& (ClientType.RESIDENTIAL.equals(clientType) || ClientType.UNKNOWN.equals(clientType));
	}
}
