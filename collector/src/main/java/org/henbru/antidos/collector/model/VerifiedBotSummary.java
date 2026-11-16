package org.henbru.antidos.collector.model;

/**
 * Summary record of verified search engine indexing robots and commercial AI crawlers
 * identified via cryptographic reverse DNS and official IP range feeds.
 */
public record VerifiedBotSummary(
		String botName,
		String clientType,
		Long asn,
		int distinctIps,
		long totalRequests,
		long totalBlockedRequests,
		long totalMarkedRequests
) {
}
