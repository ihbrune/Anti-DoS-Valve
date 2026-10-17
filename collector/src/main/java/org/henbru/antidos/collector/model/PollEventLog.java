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
		String details,
		String errorMessage
) {}
