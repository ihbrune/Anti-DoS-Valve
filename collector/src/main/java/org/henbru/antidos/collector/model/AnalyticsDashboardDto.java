package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.util.List;
import org.henbru.antidos.collector.advisor.AdvisorReport;

/**
 * Composite payload containing timeline, composition, scatterplot analytical models,
 * and expert configuration advisor diagnostics for dynamic visualization in the
 * collector dashboard and REST clients.
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
		double markedRatioPercent,
		AdvisorReport advisorReport,
		String scatterGroupBy,
		String scatterTrafficFilter,
		String scatterAuthFilter
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
			long totalMarked,
			double blockedRatioPercent,
			double markedRatioPercent,
			AdvisorReport advisorReport
	) {
		this(windowFrom, windowTo, hours, timeline, composition, scatterPoints,
				totalRequests, totalActive, totalBlocked, totalMarked, blockedRatioPercent, markedRatioPercent, advisorReport,
				"SUBNET", "ALL", "ALL");
	}

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
			long totalMarked,
			double blockedRatioPercent,
			double markedRatioPercent
	) {
		this(windowFrom, windowTo, hours, timeline, composition, scatterPoints,
				totalRequests, totalActive, totalBlocked, totalMarked, blockedRatioPercent, markedRatioPercent, null,
				"SUBNET", "ALL", "ALL");
	}

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
				totalRequests, totalActive, totalBlocked, 0L, blockedRatioPercent, 0.0, null,
				"SUBNET", "ALL", "ALL");
	}
}
