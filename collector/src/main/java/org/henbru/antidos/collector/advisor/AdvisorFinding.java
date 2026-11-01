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
) {}
