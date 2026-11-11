package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.util.List;

/**
 * Data transfer object encapsulating the full hourly timeline, metrics, subnet distribution,
 * and observed User-Agent signatures for an ASN.
 */
public record AsnDrilldownDto(
		long asn,
		String asOrg,
		String countryCode,
		ClientType clientType,
		int lookbackHours,
		Instant fromTime,
		Instant toTime,
		long totalRequests,
		long totalBlocked,
		long totalMarked,
		long totalReturning,
		double overallReturningPct,
		long totalAuthenticated,
		int distinctSubnets,
		long totalDistinctClients,
		int distinctUserAgents,
		List<AsnHourlyPoint> hourlyPoints,
		List<AsnSubnetSummary> topSubnets,
		List<AsnUserAgentSummary> topUserAgents
) {
	public double overallBlockedPct() {
		return totalRequests > 0 ? (totalBlocked * 100.0 / totalRequests) : 0.0;
	}

	public long peakHourRequests() {
		return hourlyPoints.stream()
				.mapToLong(AsnHourlyPoint::totalRequests)
				.max()
				.orElse(0L);
	}

	public double userAgentsPerSubnet() {
		return distinctSubnets > 0 ? (double) distinctUserAgents / distinctSubnets : 0.0;
	}

	/**
	 * Detects coordinated scraping/botnet pools that rotate across many subnets
	 * but share a very small, fixed set of synthetic User-Agents.
	 */
	public boolean isSyntheticUaPool() {
		return distinctSubnets >= 5 && distinctUserAgents > 0 && distinctUserAgents <= 10;
	}

	/**
	 * Indicates standard human/consumer ISP behavior with high User-Agent diversity.
	 */
	public boolean isNaturalUserPool() {
		return distinctUserAgents >= 50;
	}
}
