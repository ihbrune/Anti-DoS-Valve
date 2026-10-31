package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.util.List;

/**
 * Composite payload containing timeline, composition, and scatterplot analytical models
 * for dynamic visualization in the collector dashboard and REST clients.
 */
public record AnalyticsDashboardDto(
		Instant windowFrom,
		Instant windowTo,
		int hours,
		List<TimelinePoint> timeline,
		List<TrafficCompositionPoint> composition,
		List<SubnetScatterPoint> scatterPoints,
		long totalRequests,
		long totalActive,
		long totalBlocked,
		long totalMarked,
		double blockedRatioPercent,
		double markedRatioPercent
) {
	public AnalyticsDashboardDto(
			Instant windowFrom,
			Instant windowTo,
			int hours,
			List<TimelinePoint> timeline,
			List<TrafficCompositionPoint> composition,
			List<SubnetScatterPoint> scatterPoints,
			long totalRequests,
			long totalActive,
			long totalBlocked,
			double blockedRatioPercent
	) {
		this(windowFrom, windowTo, hours, timeline, composition, scatterPoints,
				totalRequests, totalActive, totalBlocked, 0L, blockedRatioPercent, 0.0);
	}
}
