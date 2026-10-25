package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Entity representing persistent Valve runtime configuration and telemetry limits
 * discovered from Anti-DoS Valve instances across the fleet.
 */
public record MonitoredValve(
		String serverId,
		String valveName,
		String description,
		int pipelineOrder,
		String monitorMode,
		boolean simulationMode,
		boolean serverWideBlocking,
		int httpStatusCode,
		int allowedRequestsPerSlot,
		int slotLength,
		int numberOfSlots,
		float shareOfRetainedFormerRequests,
		int ipv4SubnetMask,
		int ipv6SubnetMask,
		int maxIPCacheSize,
		int maxBlockedIPCacheSize,
		String relevantPaths,
		String nonRelevantPaths,
		String alwaysAllowedIPs,
		String alwaysForbiddenIPs,
		String statusUri,
		String statusAllowedIPs,
		Instant lastUpdatedAt,
		int configHash
) {
	public boolean isBlocking() {
		return !"MARKING".equalsIgnoreCase(monitorMode);
	}

	public String formattedDecay() {
		return Math.round(shareOfRetainedFormerRequests * 100) + "%";
	}

	public String formattedWindow() {
		return (slotLength * numberOfSlots) + "s (" + numberOfSlots + " x " + slotLength + "s)";
	}

	public boolean hasPathFilters() {
		return (relevantPaths != null && !relevantPaths.isBlank())
				|| (nonRelevantPaths != null && !nonRelevantPaths.isBlank());
	}

	public boolean hasIpLists() {
		return (alwaysAllowedIPs != null && !alwaysAllowedIPs.isBlank())
				|| (alwaysForbiddenIPs != null && !alwaysForbiddenIPs.isBlank());
	}
}
