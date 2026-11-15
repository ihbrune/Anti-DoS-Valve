package org.henbru.antidos.collector.model;

/**
 * Representation of an individual browser version, its release channel, and support tier.
 */
public record BrowserVersionEntry(
		String family,
		int majorVersion,
		String fullVersion,
		String channel,
		String releaseDate,
		String source,
		boolean isPreview,
		boolean isSupportedLegacy
) {
	public String channelBadgeClass() {
		if (isPreview) return "badge-neutral";
		if ("STABLE".equalsIgnoreCase(channel)) return "badge-success";
		if (isSupportedLegacy) return "badge-info";
		return "badge-neutral";
	}
}
