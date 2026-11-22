package org.henbru.antidos.collector.model;

import java.util.List;

/**
 * Analytical model aggregating sampled User-Agents, semantic family distributions,
 * 3-pillar heuristic assessments, and current heuristic threshold settings across the fleet.
 */
public record UserAgentAnalyticsDto(
		long totalSampledRequests,
		int totalSampledEvents,
		int distinctUserAgents,
		int distinctFamilies,
		int totalBlockedEvents,
		int totalMarkedEvents,
		int totalActiveEvents,
		int totalAuthenticatedSamples,
		boolean hasLowSamplingConfidence,
		String confidenceMessage,
		List<UserAgentFamilySummary> families,
		List<UserAgentItemSummary> userAgents,
		UserAgentIndicatorStats indicatorStats,
		BrowserReferenceOverviewDto browserReference,
		EffectiveUaHeuristicSettings heuristicSettings
) {
	public UserAgentAnalyticsDto(
			long totalSampledRequests,
			int totalSampledEvents,
			int distinctUserAgents,
			int distinctFamilies,
			int totalBlockedEvents,
			int totalMarkedEvents,
			int totalActiveEvents,
			int totalAuthenticatedSamples,
			boolean hasLowSamplingConfidence,
			String confidenceMessage,
			List<UserAgentFamilySummary> families,
			List<UserAgentItemSummary> userAgents,
			UserAgentIndicatorStats indicatorStats,
			BrowserReferenceOverviewDto browserReference
	) {
		this(totalSampledRequests, totalSampledEvents, distinctUserAgents, distinctFamilies,
				totalBlockedEvents, totalMarkedEvents, totalActiveEvents, totalAuthenticatedSamples,
				hasLowSamplingConfidence, confidenceMessage, families, userAgents,
				indicatorStats, browserReference, EffectiveUaHeuristicSettings.defaults());
	}

	public UserAgentAnalyticsDto(
			long totalSampledRequests,
			int totalSampledEvents,
			int distinctUserAgents,
			int distinctFamilies,
			int totalBlockedEvents,
			int totalMarkedEvents,
			int totalActiveEvents,
			int totalAuthenticatedSamples,
			boolean hasLowSamplingConfidence,
			String confidenceMessage,
			List<UserAgentFamilySummary> families,
			List<UserAgentItemSummary> userAgents,
			UserAgentIndicatorStats indicatorStats
	) {
		this(totalSampledRequests, totalSampledEvents, distinctUserAgents, distinctFamilies,
				totalBlockedEvents, totalMarkedEvents, totalActiveEvents, totalAuthenticatedSamples,
				hasLowSamplingConfidence, confidenceMessage, families, userAgents,
				indicatorStats, BrowserReferenceOverviewDto.empty(), EffectiveUaHeuristicSettings.defaults());
	}

	public UserAgentAnalyticsDto(
			long totalSampledRequests,
			int totalSampledEvents,
			int distinctUserAgents,
			int distinctFamilies,
			int totalBlockedEvents,
			int totalMarkedEvents,
			int totalActiveEvents,
			int totalAuthenticatedSamples,
			boolean hasLowSamplingConfidence,
			String confidenceMessage,
			List<UserAgentFamilySummary> families,
			List<UserAgentItemSummary> userAgents
	) {
		this(totalSampledRequests, totalSampledEvents, distinctUserAgents, distinctFamilies,
				totalBlockedEvents, totalMarkedEvents, totalActiveEvents, totalAuthenticatedSamples,
				hasLowSamplingConfidence, confidenceMessage, families, userAgents,
				UserAgentIndicatorStats.empty(), BrowserReferenceOverviewDto.empty(), EffectiveUaHeuristicSettings.defaults());
	}

	public static UserAgentAnalyticsDto empty(boolean hasLowConfidence, String confidenceMessage) {
		return new UserAgentAnalyticsDto(0L, 0, 0, 0, 0, 0, 0, 0, hasLowConfidence, confidenceMessage,
				List.of(), List.of(), UserAgentIndicatorStats.empty(),
				BrowserReferenceOverviewDto.empty(), EffectiveUaHeuristicSettings.defaults());
	}
}
