package org.henbru.antidos.collector.advisor;

import org.henbru.antidos.collector.model.ClientType;

/**
 * Concrete diagnostic finding identifying a rate limiting misconfiguration, false positive risk,
 * or defense optimization with actionable Tomcat configuration recommendations.
 */
public record AdvisorFinding(
		String id,
		AdvisorCategory category,
		AdvisorSeverity severity,
		String title,
		String serverId,
		String valveName,
		String targetSubnet,
		String entityName,
		ClientType clientType,
		long totalRequests,
		long blockedRequests,
		double blockPercentage,
		int peakRequestsPerClient,
		Integer currentLimit,
		Integer currentSlotLength,
		String currentAlwaysAllowedIps,
		String explanation,
		String recommendation,
		String suggestedConfigXml,
		String suggestedRegex
) {
	public Long extractAsn() {
		if (targetSubnet != null && targetSubnet.startsWith("ASN ")) {
			int spaceIdx = targetSubnet.indexOf(' ', 4);
			String numPart = spaceIdx > 4 ? targetSubnet.substring(4, spaceIdx).trim() : targetSubnet.substring(4).trim();
			try {
				long val = Long.parseLong(numPart);
				return val > 0 ? val : null;
			} catch (NumberFormatException ignored) {
			}
		}
		return null;
	}

	public boolean isDirectCidrTarget() {
		return targetSubnet != null
				&& !targetSubnet.startsWith("ASN ")
				&& (targetSubnet.contains("/") || targetSubnet.contains(".") || targetSubnet.contains(":"));
	}
}
