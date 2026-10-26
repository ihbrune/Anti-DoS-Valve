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
		String collectorIntegration,
		boolean visitorCookieEnabled,
		String visitorCookieName,
		Instant lastUpdatedAt,
		int configHash
) {
	/**
	 * Backwards-compatible constructor defaulting visitorCookieEnabled to false and visitorCookieName to "_adv".
	 */
	public MonitoredValve(
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
			String collectorIntegration,
			Instant lastUpdatedAt,
			int configHash
	) {
		this(serverId, valveName, description, pipelineOrder, monitorMode, simulationMode,
				serverWideBlocking, httpStatusCode, allowedRequestsPerSlot, slotLength, numberOfSlots,
				shareOfRetainedFormerRequests, ipv4SubnetMask, ipv6SubnetMask, maxIPCacheSize,
				maxBlockedIPCacheSize, relevantPaths, nonRelevantPaths, alwaysAllowedIPs,
				alwaysForbiddenIPs, statusUri, statusAllowedIPs, collectorIntegration,
				false, "_adv", lastUpdatedAt, configHash);
	}

	/**
	 * Backwards-compatible constructor defaulting collectorIntegration to "auto" and visitor cookie tracking to false.
	 */
	public MonitoredValve(
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
		this(serverId, valveName, description, pipelineOrder, monitorMode, simulationMode,
				serverWideBlocking, httpStatusCode, allowedRequestsPerSlot, slotLength, numberOfSlots,
				shareOfRetainedFormerRequests, ipv4SubnetMask, ipv6SubnetMask, maxIPCacheSize,
				maxBlockedIPCacheSize, relevantPaths, nonRelevantPaths, alwaysAllowedIPs,
				alwaysForbiddenIPs, statusUri, statusAllowedIPs, "auto",
				false, "_adv", lastUpdatedAt, configHash);
	}

	public boolean isBlocking() {
		return !"MARKING".equalsIgnoreCase(monitorMode);
	}

	public String formattedDecay() {
		return Math.round(shareOfRetainedFormerRequests * 100) + "%";
	}

	public String formattedWindow() {
		return (slotLength * numberOfSlots) + "s (" + numberOfSlots + " x " + slotLength + "s)";
	}

	public String formattedSubnetMasks() {
		return "/" + ipv4SubnetMask + " (IPv4) &bull; /" + ipv6SubnetMask + " (IPv6)";
	}

	public String collectorIntegration() {
		return collectorIntegration != null && !collectorIntegration.isBlank() ? collectorIntegration : "auto";
	}

	public String collectorIntegrationBadgeClass() {
		String mode = collectorIntegration().toLowerCase();
		return switch (mode) {
			case "true" -> "badge-success";
			case "false" -> "badge-secondary";
			default -> "badge-info";
		};
	}

	public String collectorIntegrationLabel() {
		String mode = collectorIntegration().toLowerCase();
		return switch (mode) {
			case "true" -> "ALWAYS ON";
			case "false" -> "DISABLED";
			default -> "AUTO";
		};
	}

	public String visitorCookieName() {
		return visitorCookieName != null && !visitorCookieName.isBlank() ? visitorCookieName : "_adv";
	}

	public String visitorCookieBadgeClass() {
		return visitorCookieEnabled ? "badge-success" : "badge-secondary";
	}

	public String visitorCookieLabel() {
		return visitorCookieEnabled ? "ACTIVE (" + visitorCookieName() + ")" : "OFF";
	}

	public boolean hasPathFilters() {
		return (relevantPaths != null && !relevantPaths.isBlank())
				|| (nonRelevantPaths != null && !nonRelevantPaths.isBlank());
	}

	public boolean hasIpLists() {
		return (alwaysAllowedIPs != null && !alwaysAllowedIPs.isBlank())
				|| (alwaysForbiddenIPs != null && !alwaysForbiddenIPs.isBlank());
	}

	/**
	 * @return true if this valve is designated as a Honeypot trap (name contains "HONEYPOT")
	 */
	public boolean isHoneypot() {
		return valveName != null && valveName.toUpperCase().contains("HONEYPOT");
	}
}
