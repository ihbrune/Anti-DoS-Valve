package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.util.List;

/**
 * Summary DTO grouping all browser family references for UI display and version heuristics.
 */
public record BrowserReferenceOverviewDto(
		List<BrowserFamilyReference> families,
		Instant lastSynced,
		boolean syncSuccessful,
		String statusMessage
) {
	public static BrowserReferenceOverviewDto empty() {
		return new BrowserReferenceOverviewDto(List.of(), null, false, "Not initialized");
	}
}
