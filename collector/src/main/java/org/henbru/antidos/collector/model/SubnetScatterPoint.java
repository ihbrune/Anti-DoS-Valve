package org.henbru.antidos.collector.model;

/**
 * 2D cluster metric for a subnet group in residential proxy and distributed botnet scatterplots.
 *
 * @param subnetGroup CIDR subnet partition (e.g. 198.51.100.0/24 or 2001:db8:1::/64)
 * @param distinctClients Number of unique client IPs in this subnet (X-axis)
 * @param averageRequestsPerClient Average requests per client IP in this subnet (Y-axis)
 * @param totalRequests Total requests originating from this subnet
 * @param blockedRequests Blocked requests originating from this subnet (bubble size)
 * @param isPotentialResidentialProxy Heuristic indicator for distributed residential attacks
 * @param asn Autonomous system number (if resolved)
 * @param asOrg Autonomous system organization / ISP
 * @param countryCode Two-letter country code (ISO 3166-1)
 * @param clientType Classified client type
 * @param classification Risk classification badge (e.g. HIGH_RISK_RESIDENTIAL, DATACENTER_SCRAPER, BENIGN)
 */
public record SubnetScatterPoint(
		String subnetGroup,
		int distinctClients,
		double averageRequestsPerClient,
		long totalRequests,
		long blockedRequests,
		boolean isPotentialResidentialProxy,
		Long asn,
		String asOrg,
		String countryCode,
		ClientType clientType,
		String classification
) {
	public double blockedRatioPercent() {
		if (totalRequests <= 0) {
			return 0.0;
		}
		return Math.round(((double) blockedRequests / totalRequests) * 1000.0) / 10.0;
	}

	public double bubbleRadius() {
		// Bubble radius between 5 and 26 pixels based on request volume
		if (totalRequests <= 10) return 5.0;
		double logVal = Math.log10(totalRequests);
		return Math.min(26.0, Math.max(5.0, 5.0 + logVal * 4.5));
	}
}
