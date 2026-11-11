package org.henbru.antidos.collector.model;

/**
 * Summary of a specific origin network (subnet and ASN) where a User-Agent was observed.
 */
public record UserAgentOriginSummary(
		String subnetGroup,
		Long asn,
		String asOrg,
		long requests,
		int events
) {
	public String formattedAsn() {
		if (asn == null || asn <= 0) return "Unknown ASN";
		return "AS" + asn + (asOrg != null && !asOrg.isBlank() ? " (" + asOrg + ")" : "");
	}
}

