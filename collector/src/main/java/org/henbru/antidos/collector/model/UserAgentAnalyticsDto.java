package org.henbru.antidos.collector.model;

import java.util.List;

/**
 * Analytical model aggregating sampled User-Agents, semantic family distributions,
 * and bot/scraper suspicion heuristics across the fleet.
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
		BrowserReferenceOverviewDto browserReference
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
			UserAgentIndicatorStats indicatorStats
	) {
		this(totalSampledRequests, totalSampledEvents, distinctUserAgents, distinctFamilies,
				totalBlockedEvents, totalMarkedEvents, totalActiveEvents, totalAuthenticatedSamples,
				hasLowSamplingConfidence, confidenceMessage, families, userAgents,
				indicatorStats, BrowserReferenceOverviewDto.empty());
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
				UserAgentIndicatorStats.empty(), BrowserReferenceOverviewDto.empty());
	}

	public static UserAgentAnalyticsDto empty(boolean hasLowConfidence, String confidenceMessage) {
		return new UserAgentAnalyticsDto(0L, 0, 0, 0, 0, 0, 0, 0, hasLowConfidence, confidenceMessage, List.of(), List.of(), UserAgentIndicatorStats.empty(), BrowserReferenceOverviewDto.empty());
	}
}

