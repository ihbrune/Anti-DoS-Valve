package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Single aggregated time bucket for traffic timeline charts.
 *
 * @param bucketStart Start timestamp of the aggregated bucket
 * @param totalRequests Total incoming requests processed
 * @param activeRequests Allowed / benign requests
 * @param blockedRequests Blocked abusive requests (HTTP 429)
 */
public record TimelinePoint(
		Instant bucketStart,
		long totalRequests,
		long activeRequests,
		long blockedRequests,
		long markedRequests
) {
	public TimelinePoint(
			Instant bucketStart,
			long totalRequests,
			long activeRequests,
			long blockedRequests
	) {
		this(bucketStart, totalRequests, activeRequests, blockedRequests, 0L);
	}

	public double blockedRatioPercent() {
		if (totalRequests <= 0) {
			return 0.0;
		}
		return Math.round(((double) blockedRequests / totalRequests) * 1000.0) / 10.0;
	}

	public double markedRatioPercent() {
		if (totalRequests <= 0) {
			return 0.0;
		}
		return Math.round(((double) markedRequests / totalRequests) * 1000.0) / 10.0;
	}
}
