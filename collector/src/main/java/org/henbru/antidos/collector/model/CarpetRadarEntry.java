package org.henbru.antidos.collector.model;

import java.util.List;

/**
 * Real-time Carpet Attack Radar entry evaluating an ASN against auto-mitigation safety guardrails.
 */
public record CarpetRadarEntry(
		long asn,
		String asOrg,
		String countryCode,
		int activeSubnets,
		long totalRequests,
		long returningRequests,
		double returningRatioPct,
		long authenticatedRequests,
		long uaMismatchRequests,
		boolean isProtectedAsn,
		boolean hasActiveRules,
		String status,
		String statusReason,
		String badgeClass,
		String icon,
		List<String> topSubnets
) {
	public CarpetRadarEntry(
			long asn,
			String asOrg,
			String countryCode,
			int activeSubnets,
			long totalRequests,
			long returningRequests,
			double returningRatioPct,
			long authenticatedRequests,
			boolean isProtectedAsn,
			boolean hasActiveRules,
			String status,
			String statusReason,
			String badgeClass,
			String icon,
			List<String> topSubnets
	) {
		this(asn, asOrg, countryCode, activeSubnets, totalRequests, returningRequests,
				returningRatioPct, authenticatedRequests, 0L, isProtectedAsn, hasActiveRules,
				status, statusReason, badgeClass, icon, topSubnets);
	}

	public boolean isQualified() {
		return "QUALIFIED".equals(status);
	}

	public boolean isSuppressed() {
		return status != null && status.startsWith("SUPPRESSED");
	}
}

