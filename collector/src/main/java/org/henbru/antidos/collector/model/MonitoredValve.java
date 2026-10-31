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
		boolean authTrackingEnabled,
		String authTrackingMode,
		String authCookieName,
		String authLoginPaths,
		int authSessionTtlSeconds,
		int maxAuthCacheSize,
		Instant lastUpdatedAt,
		int configHash,
		boolean isActive
) {
	/**
	 * Backwards-compatible constructor without authTracking fields.
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
			boolean visitorCookieEnabled,
			String visitorCookieName,
			Instant lastUpdatedAt,
			int configHash,
			boolean isActive
	) {
		this(serverId, valveName, description, pipelineOrder, monitorMode, simulationMode,
				serverWideBlocking, httpStatusCode, allowedRequestsPerSlot, slotLength, numberOfSlots,
				shareOfRetainedFormerRequests, ipv4SubnetMask, ipv6SubnetMask, maxIPCacheSize,
				maxBlockedIPCacheSize, relevantPaths, nonRelevantPaths, alwaysAllowedIPs,
				alwaysForbiddenIPs, statusUri, statusAllowedIPs, collectorIntegration,
				visitorCookieEnabled, visitorCookieName,
				false, "OFF", null, null, 900, 50000,
				lastUpdatedAt, configHash, isActive);
	}

	/**
	 * Backwards-compatible constructor defaulting isActive to true.
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
			boolean visitorCookieEnabled,
			String visitorCookieName,
			Instant lastUpdatedAt,
			int configHash
	) {
		this(serverId, valveName, description, pipelineOrder, monitorMode, simulationMode,
				serverWideBlocking, httpStatusCode, allowedRequestsPerSlot, slotLength, numberOfSlots,
				shareOfRetainedFormerRequests, ipv4SubnetMask, ipv6SubnetMask, maxIPCacheSize,
				maxBlockedIPCacheSize, relevantPaths, nonRelevantPaths, alwaysAllowedIPs,
				alwaysForbiddenIPs, statusUri, statusAllowedIPs, collectorIntegration,
				visitorCookieEnabled, visitorCookieName, lastUpdatedAt, configHash, true);
	}

	/**
	 * Backwards-compatible constructor defaulting visitorCookieEnabled to false, visitorCookieName to "_adv", and isActive to true.
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
				false, "_adv", lastUpdatedAt, configHash, true);
	}

	/**
	 * Backwards-compatible constructor defaulting collectorIntegration to "auto", visitor cookie tracking to false, and isActive to true.
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
				false, "_adv", lastUpdatedAt, configHash, true);
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

	public String authTrackingMode() {
		return authTrackingMode != null && !authTrackingMode.isBlank() ? authTrackingMode : "OFF";
	}

	public String authTrackingBadgeClass() {
		return authTrackingEnabled ? "badge-success" : "badge-secondary";
	}

	public String authTrackingLabel() {
		if (!authTrackingEnabled) {
			return "OFF";
		}
		if (authCookieName != null && !authCookieName.isBlank()) {
			return authTrackingMode() + " (" + authCookieName + ")";
		}
		return authTrackingMode();
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
