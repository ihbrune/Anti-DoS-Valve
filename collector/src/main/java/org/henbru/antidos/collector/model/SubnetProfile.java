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
		long totalMarkedRequests,
		double baselineDailyAvg,
		int baselineDistinctClients,
		long peakDailyRequests,
		long last24hRequests,
		int last24hDistinctClients,
		long last24hBlockedRequests,
		long last24hMarkedRequests,
		double last24hSurgeFactor,
		Long asn,
		String asOrg,
		String countryCode,
		ClientType clientType,
		Instant updatedAt,
		long last24hReturningRequests,
		long last24hReturningTrackedRequests,
		long last24hAuthenticatedRequests,
		long last24hAuthenticatedTrackedRequests
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
			ClientType clientType,
			Instant updatedAt,
			long last24hReturningRequests,
			long last24hReturningTrackedRequests,
			long last24hAuthenticatedRequests,
			long last24hAuthenticatedTrackedRequests
	) {
		this(
				subnetGroup,
				firstSeenAt,
				lastSeenAt,
				daysDormantBeforeLastSeen,
				totalLifetimeRequests,
				totalActiveRequests,
				totalBlockedRequests,
				0L,
				baselineDailyAvg,
				baselineDistinctClients,
				peakDailyRequests,
				last24hRequests,
				last24hDistinctClients,
				last24hBlockedRequests,
				0L,
				last24hSurgeFactor,
				asn,
				asOrg,
				countryCode,
				clientType,
				updatedAt,
				last24hReturningRequests,
				last24hReturningTrackedRequests,
				last24hAuthenticatedRequests,
				last24hAuthenticatedTrackedRequests
		);
	}

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
			ClientType clientType,
			Instant updatedAt
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
				updatedAt,
				0L,
				0L,
				0L,
				0L
		);
	}

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
				Instant.now(),
				0L,
				0L,
				0L,
				0L
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
	 * Checks if current 24-hour traffic exhibits a significant surge over an established historical baseline.
	 * Returns false if no baseline has been established yet (baselineDailyAvg <= 0.0).
	 */
	public boolean isHighSurge(double thresholdMultiplier) {
		return baselineDailyAvg > 0.0 && last24hSurgeFactor >= thresholdMultiplier;
	}

	/**
	 * Checks if current 24-hour traffic exhibits a significant surge over an established historical baseline
	 * and satisfies the absolute de minimis volume threshold (e.g. >= 1,000 req/24h).
	 */
	public boolean isHighSurge(double thresholdMultiplier, long minRequests) {
		return baselineDailyAvg > 0.0 && last24hSurgeFactor >= thresholdMultiplier && last24hRequests >= minRequests;
	}

	/**
	 * Checks if current 24-hour traffic exhibits a high surge multiplier relative to baseline,
	 * but is below the absolute de minimis volume threshold (sub-threshold / low volume).
	 */
	public boolean isSubThresholdSurge(double thresholdMultiplier, long minRequests) {
		return baselineDailyAvg > 0.0 && last24hSurgeFactor >= thresholdMultiplier && last24hRequests < minRequests;
	}

	/**
	 * Returns true if this subnet profile has no established baseline yet (Phase 1 / brand new).
	 */
	public boolean isInitializing() {
		return baselineDailyAvg <= 0.0 || last24hSurgeFactor <= 0.0;
	}

	/**
	 * Returns true if this subnet profile is in the early baseline phase (< 7 days of observation).
	 */
	public boolean isEarlyBaseline() {
		if (firstSeenAt == null) return true;
		return ChronoUnit.HOURS.between(firstSeenAt, Instant.now()) < (7 * 24);
	}

	/**
	 * Returns the number of days this subnet has been tracked (1..30).
	 */
	public int daysOfHistory() {
		if (firstSeenAt == null) return 1;
		long days = ChronoUnit.DAYS.between(firstSeenAt, Instant.now());
		return (int) Math.min(30, Math.max(1, days));
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
	 * Calculates the soft marking rate in the last 24h as a percentage (0.0 to 100.0).
	 */
	public double markRate24h() {
		return last24hRequests > 0 ? ((double) last24hMarkedRequests / last24hRequests) * 100.0 : 0.0;
	}

	/**
	 * Heuristic indicator for potential distributed residential proxy pools / low-and-slow campaigns.
	 * Excludes multi-user human ISP / CGNAT subnets when visitor cookie tracking confirms a high returning
	 * visitor ratio (>= 40% across >= 20 tracked requests).
	 */
	public boolean isPotentialResidentialProxyPool() {
		Double retRatio = returningRatio24h();
		boolean isHighReturningHumanNat = last24hReturningTrackedRequests >= 20 && retRatio != null && retRatio >= 40.0;
		return last24hDistinctClients >= 5
				&& averageRequestsPerClient24h() <= 20.0
				&& !isHighReturningHumanNat
				&& (ClientType.RESIDENTIAL.equals(clientType) || ClientType.UNKNOWN.equals(clientType));
	}

	/**
	 * Heuristic indicator for headless scrapers or cookie-less bots based on low visitor cookie
	 * retention (< 15% across at least 20 tracked requests) combined with rate-limit or marking triggers.
	 */
	public boolean isLikelyAutomatedScraper24h() {
		Double retRatio = returningRatio24h();
		return last24hReturningTrackedRequests >= 20
				&& retRatio != null
				&& retRatio < 15.0
				&& (last24hBlockedRequests > 0 || last24hMarkedRequests > 0 || last24hRequests >= 100);
	}

	/**
	 * Heuristic indicator for legitimate multi-user human NAT / CGNAT subnets based on high visitor
	 * cookie retention (>= 50% across at least 20 tracked requests) without hard 429 blocks.
	 */
	public boolean isLikelyHumanNat24h() {
		Double retRatio = returningRatio24h();
		return last24hReturningTrackedRequests >= 20
				&& retRatio != null
				&& retRatio >= 50.0
				&& last24hBlockedRequests == 0;
	}

	public Double returningRatio24h() {
		return last24hReturningTrackedRequests > 0
				? (last24hReturningRequests * 100.0 / last24hReturningTrackedRequests)
				: null;
	}

	public Double authenticatedRatio24h() {
		return last24hAuthenticatedTrackedRequests > 0
				? (last24hAuthenticatedRequests * 100.0 / last24hAuthenticatedTrackedRequests)
				: null;
	}

	public boolean isReturningTracked24h() {
		return last24hReturningTrackedRequests > 0;
	}

	public boolean isAuthenticatedTracked24h() {
		return last24hAuthenticatedTrackedRequests > 0;
	}
}
