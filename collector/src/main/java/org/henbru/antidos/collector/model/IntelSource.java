package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Metadata record for a configured IP intelligence source (e.g. crawler feed, Tor exit list, MMDB, static list).
 */
public record IntelSource(
		String sourceKey,
		String sourceType, // 'FEED', 'STATIC', 'MMDB', 'MANUAL'
		String name,
		String category,
		String url,
		long version,
		Instant lastSyncedAt,
		String status,
		int prefixCount,
		String lastError
) {
}
