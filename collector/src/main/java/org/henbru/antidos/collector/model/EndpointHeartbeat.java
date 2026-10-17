package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Health and connectivity status of a monitored AntiDoSValve endpoint.
 */
public record EndpointHeartbeat(
		String serverId,
		String url,
		boolean online,
		Instant lastPollAt,
		Instant lastSuccessAt,
		String lastError,
		long responseTimeMs,
		int valvesCount
) {
	public static EndpointHeartbeat initial(String serverId, String url) {
		return new EndpointHeartbeat(serverId, url, false, null, null, null, 0, 0);
	}

	public EndpointHeartbeat success(Instant now, long responseTimeMs, int valvesCount) {
		return new EndpointHeartbeat(serverId, url, true, now, now, null, responseTimeMs, valvesCount);
	}

	public EndpointHeartbeat failure(Instant now, String error) {
		return new EndpointHeartbeat(serverId, url, false, now, lastSuccessAt, error, 0, valvesCount);
	}
}
