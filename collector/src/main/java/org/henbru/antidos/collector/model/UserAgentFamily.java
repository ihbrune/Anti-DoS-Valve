package org.henbru.antidos.collector.model;

/**
 * Categorization of client User-Agent strings into semantic families
 * distinguishing standard browsers, mobile devices, automated tools, and web crawlers.
 */
public enum UserAgentFamily {
	CHROME_DESKTOP("Chrome Desktop", "&#x1F310;", false),
	CHROME_MOBILE("Chrome Mobile", "&#x1F4F1;", false),
	SAFARI_DESKTOP("Safari Desktop", "&#x1F9ED;", false),
	SAFARI_MOBILE("Mobile Safari", "&#x1F4F1;", false),
	FIREFOX_DESKTOP("Firefox Desktop", "&#x1F98A;", false),
	FIREFOX_MOBILE("Firefox Mobile", "&#x1F4F1;", false),
	EDGE_DESKTOP("Edge Desktop", "&#x1F310;", false),
	EDGE_MOBILE("Edge Mobile", "&#x1F4F1;", false),
	OPERA("Opera", "&#x1F310;", false),
	AUTOMATED_TOOL("HTTP Tool / Script", "&#x1F9F0;", true),
	BOT_CRAWLER("Bot / Crawler", "&#x1F916;", true),
	OTHER_BROWSER("Other Browser", "&#x1F310;", false),
	UNKNOWN("Unknown / Custom", "&#x2753;", false),
	EMPTY("Empty / Missing", "&#x2753;", true);

	private final String displayName;
	private final String icon;
	private final boolean automated;

	UserAgentFamily(String displayName, String icon, boolean automated) {
		this.displayName = displayName;
		this.icon = icon;
		this.automated = automated;
	}

	public String displayName() {
		return displayName;
	}

	public String icon() {
		return icon;
	}

	public boolean isAutomated() {
		return automated;
	}
}

