package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.util.List;

/**
 * Authoritative release reference for a major browser family (Chrome, Edge, Firefox, Safari),
 * including current stable, preview horizon, and the top 5 most recent versions.
 */
public record BrowserFamilyReference(
		String familyName,
		String icon,
		int latestStableMajor,
		int maxPreviewMajor,
		int minSupportedMajor,
		String sourceName,
		boolean automatedSync,
		String sourceNotice,
		Instant lastSynced,
		List<BrowserVersionEntry> topVersions
) {}
