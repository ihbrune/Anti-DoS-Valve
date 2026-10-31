package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Aggregated telemetry snapshot for a specific time slot on a monitored Valve.
 */
public record SlotSnapshot(
		Long id,
		String serverId,
		String valveName,
		long slotKey,
		Instant startTime,
		Instant endTime,
		long totalRequests,
		int activeCounters,
		int blockedCounters,
		int markedCounters,
		boolean completed,
		Instant lastPolledAt
) {

	/**
	 * Backward-compatible constructor defaulting markedCounters to 0.
	 */
	public SlotSnapshot(
			Long id,
			String serverId,
			String valveName,
			long slotKey,
			Instant startTime,
			Instant endTime,
			long totalRequests,
			int activeCounters,
			int blockedCounters,
			boolean completed,
			Instant lastPolledAt
	) {
		this(id, serverId, valveName, slotKey, startTime, endTime, totalRequests,
				activeCounters, blockedCounters, 0, completed, lastPolledAt);
	}
}
