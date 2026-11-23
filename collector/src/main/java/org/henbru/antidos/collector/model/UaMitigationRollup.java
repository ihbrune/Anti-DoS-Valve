package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Aggregated hourly time-bucket record representing dynamic User-Agent mitigation blocks and telemetry.
 */
public record UaMitigationRollup(
		Long id,
		Instant bucketStart,
		String serverId,
		String valveName,
		long totalRequests,
		long blockedRequests,
		long markedRequests,
		int distinctUaRules,
		Instant createdAt
) {
	public UaMitigationRollup(
			Instant bucketStart,
			String serverId,
			String valveName,
			long totalRequests,
			long blockedRequests,
			long markedRequests,
			int distinctUaRules
	) {
		this(null, bucketStart, serverId, valveName, totalRequests, blockedRequests, markedRequests, distinctUaRules, Instant.now());
	}
}
