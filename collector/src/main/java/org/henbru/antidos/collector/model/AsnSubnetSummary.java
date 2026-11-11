package org.henbru.antidos.collector.model;

/**
 * Subnet summary for an ASN deep-dive inspection.
 */
public record AsnSubnetSummary(
		String subnetGroup,
		long totalRequests,
		long blockedRequests,
		long markedRequests,
		long returningRequests,
		double returningRatioPct,
		long authenticatedRequests,
		long distinctClients,
		String countryCode,
		ClientType clientType
) {
	public double blockedRatioPct() {
		return totalRequests > 0 ? (blockedRequests * 100.0 / totalRequests) : 0.0;
	}
}

