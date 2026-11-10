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
		String errorMessage,
		long payloadBytes,
		int serverGenerationMs
) {
	/**
	 * Backward-compatible constructor for 14-parameter signature.
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
			int markedEventsIngested,
			String details,
			String errorMessage
	) {
		this(id, serverId, url, pollTime, status, httpStatusCode, responseTimeMs,
				valvesPolled, slotsIngested, eventsIngested, blockedEventsIngested, markedEventsIngested,
				details, errorMessage, 0L, 0);
	}

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
				valvesPolled, slotsIngested, eventsIngested, blockedEventsIngested, 0,
				details, errorMessage, 0L, 0);
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
				valvesPolled, slotsIngested, eventsIngested, 0, 0,
				details, errorMessage, 0L, 0);
	}

	public int activeEventsIngested() {
		return Math.max(0, eventsIngested - blockedEventsIngested - markedEventsIngested);
	}

	public String formattedPayloadSize() {
		if (payloadBytes <= 0) {
			return "0 B";
		}
		if (payloadBytes < 1024) {
			return payloadBytes + " B";
		}
		if (payloadBytes < 1024 * 1024) {
			return String.format(java.util.Locale.US, "%.1f KB", payloadBytes / 1024.0);
		}
		return String.format(java.util.Locale.US, "%.2f MB", payloadBytes / (1024.0 * 1024.0));
	}
}
