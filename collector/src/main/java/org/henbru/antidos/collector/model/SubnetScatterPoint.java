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
 * @param hasNote Whether this cluster has an associated operator note (Subnet or ASN)
 * @param noteVerdict Effective categorization verdict name
 * @param noteVerdictIcon Emoji icon for effective verdict
 * @param noteVerdictDisplayName Human-readable name for effective verdict
 * @param noteVerdictColor Hex color for effective verdict
 * @param noteSnippet Brief excerpt of operator note
 * @param subnetNoteVerdict Verdict of subnet-specific note (if present)
 * @param subnetNoteIcon Emoji icon of subnet-specific note
 * @param subnetNoteSnippet Excerpt of subnet note
 * @param asnNoteVerdict Verdict of ASN-specific note (if present)
 * @param asnNoteIcon Emoji icon of ASN note
 * @param asnNoteSnippet Excerpt of ASN note
 */
public record SubnetScatterPoint(
		String subnetGroup,
		int distinctClients,
		double averageRequestsPerClient,
		long totalRequests,
		long blockedRequests,
		long markedRequests,
		boolean isPotentialResidentialProxy,
		Long asn,
		String asOrg,
		String countryCode,
		ClientType clientType,
		String classification,
		boolean hasNote,
		String noteVerdict,
		String noteVerdictIcon,
		String noteVerdictDisplayName,
		String noteVerdictColor,
		String noteSnippet,
		String subnetNoteVerdict,
		String subnetNoteIcon,
		String subnetNoteSnippet,
		String asnNoteVerdict,
		String asnNoteIcon,
		String asnNoteSnippet,
		Double returningRatio
) {
	public SubnetScatterPoint(
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
			String classification,
			boolean hasNote,
			String noteVerdict,
			String noteVerdictIcon,
			String noteVerdictDisplayName,
			String noteVerdictColor,
			String noteSnippet,
			String subnetNoteVerdict,
			String subnetNoteIcon,
			String subnetNoteSnippet,
			String asnNoteVerdict,
			String asnNoteIcon,
			String asnNoteSnippet
	) {
		this(subnetGroup, distinctClients, averageRequestsPerClient, totalRequests, blockedRequests, 0L,
				isPotentialResidentialProxy, asn, asOrg, countryCode, clientType, classification,
				hasNote, noteVerdict, noteVerdictIcon, noteVerdictDisplayName, noteVerdictColor, noteSnippet,
				subnetNoteVerdict, subnetNoteIcon, subnetNoteSnippet, asnNoteVerdict, asnNoteIcon, asnNoteSnippet, null);
	}

	public SubnetScatterPoint(
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
		this(subnetGroup, distinctClients, averageRequestsPerClient, totalRequests, blockedRequests, 0L,
				isPotentialResidentialProxy, asn, asOrg, countryCode, clientType, classification,
				false, null, null, null, null, null, null, null, null, null, null, null, null);
	}

	public double blockedRatioPercent() {
		if (totalRequests <= 0) {
			return 0.0;
		}
		return Math.round(((double) blockedRequests / totalRequests) * 1000.0) / 10.0;
	}

	public double markedRatioPercent() {
		if (totalRequests <= 0) {
			return 0.0;
		}
		return Math.round(((double) markedRequests / totalRequests) * 1000.0) / 10.0;
	}

	public double bubbleRadius() {
		// Bubble radius between 5 and 26 pixels based on request volume
		if (totalRequests <= 10) return 5.0;
		double logVal = Math.log10(totalRequests);
		return Math.min(26.0, Math.max(5.0, 5.0 + logVal * 4.5));
	}
}
