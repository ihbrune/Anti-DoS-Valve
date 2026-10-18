package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Metadata and synchronization state of a configured crawler/bot IP feed.
 */
public record CrawlerFeed(
		String feedKey,
		String name,
		String category,
		String url,
		Instant lastSyncedAt,
		String status,
		int prefixCount,
		String lastError
) {
}
