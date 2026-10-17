package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Details of an individual blocked client IP or subnet partition recorded during a slot.
 */
public record BlockedClientEvent(
		Long id,
		String serverId,
		String valveName,
		long slotKey,
		Instant slotTime,
		String clientKey,
		int requestCount,
		int retainedCount,
		boolean locked,
		boolean completed,
		Instant lastUpdatedAt
) {
	public int totalEffectiveCount() {
		return requestCount + retainedCount;
	}
}
