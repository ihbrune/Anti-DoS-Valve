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
	/**
	 * Returns a concise version label for badge presentation in the UI.
	 * For Safari, displays point releases (e.g. "26.1", "26.2 STP", "18.2") rather than repeating "26".
	 * For Chrome/Firefox/Edge, displays the standard major version integer (e.g. "157", "153").
	 */
	public String displayVersion() {
		if ("Safari".equalsIgnoreCase(family)) {
			if (fullVersion != null && !fullVersion.isBlank()) {
				String v = fullVersion.trim();
				// If fullVersion contains a space, check if the second token is a preview indicator like STP
				String[] tokens = v.split("\\s+");
				if (tokens.length >= 2 && ("STP".equalsIgnoreCase(tokens[1]) || "Preview".equalsIgnoreCase(tokens[1]))) {
					return tokens[0] + " " + tokens[1];
				}
				return tokens[0];
			}
		}
		return String.valueOf(majorVersion);
	}

	public String channelBadgeClass() {
		if (isPreview) return "badge-neutral";
		if ("STABLE".equalsIgnoreCase(channel)) return "badge-success";
		if ("PREVIOUS".equalsIgnoreCase(channel)) return "badge-neutral";
		if (isSupportedLegacy) return "badge-info";
		return "badge-neutral";
	}
}
