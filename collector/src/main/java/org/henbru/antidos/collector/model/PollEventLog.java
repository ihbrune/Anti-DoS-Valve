package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Audit log entry capturing an individual polling attempt against a monitored endpoint node.
 */
public record PollEventLog(
		Long id,
		String serverId,
		String url,
		Instant pollTime,
		String status, // "SUCCESS", "WARNING", "ERROR"
		int httpStatusCode,
		long responseTimeMs,
		int valvesPolled,
		int slotsIngested,
		int eventsIngested,
		int blockedEventsIngested,
		int markedEventsIngested,
		String details,
		String errorMessage
) {
	/**
	 * Backward-compatible constructor for 13-parameter signature.
	 */
	public PollEventLog(
			Long id,
			String serverId,
			String url,
			Instant pollTime,
			String status,
			int httpStatusCode,
			long responseTimeMs,
			int valvesPolled,
			int slotsIngested,
			int eventsIngested,
			int blockedEventsIngested,
			String details,
			String errorMessage
	) {
		this(id, serverId, url, pollTime, status, httpStatusCode, responseTimeMs,
				valvesPolled, slotsIngested, eventsIngested, blockedEventsIngested, 0, details, errorMessage);
	}

	/**
	 * Backward-compatible constructor for previous 12-parameter signature.
	 */
	public PollEventLog(
			Long id,
			String serverId,
			String url,
			Instant pollTime,
			String status,
			int httpStatusCode,
			long responseTimeMs,
			int valvesPolled,
			int slotsIngested,
			int eventsIngested,
			String details,
			String errorMessage
	) {
		this(id, serverId, url, pollTime, status, httpStatusCode, responseTimeMs,
				valvesPolled, slotsIngested, eventsIngested, 0, 0, details, errorMessage);
	}

	public int activeEventsIngested() {
		return Math.max(0, eventsIngested - blockedEventsIngested - markedEventsIngested);
	}
}
