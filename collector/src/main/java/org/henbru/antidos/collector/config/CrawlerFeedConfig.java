package org.henbru.antidos.collector.config;

import java.util.Locale;
import java.util.Set;

/**
 * Configuration for a single verified crawler or bot IP range feed.
 */
public class CrawlerFeedConfig {

	public static final Set<String> VALID_CATEGORIES = Set.of("SEARCH_ENGINE", "AI_CRAWLER", "TOR_EXIT_NODE");

	private String key;
	private String name;
	private String category = "SEARCH_ENGINE";
	private String url;
	private boolean enabled = true;

	public CrawlerFeedConfig() {
	}

	public CrawlerFeedConfig(String key, String name, String category, String url) {
		this(key, name, category, url, true);
	}

	public CrawlerFeedConfig(String key, String name, String category, String url, boolean enabled) {
		this.key = key;
		this.name = name;
		this.category = category;
		this.url = url;
		this.enabled = enabled;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getCategory() {
		return category;
	}

	public void setCategory(String category) {
		this.category = category;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public boolean hasValidCategory() {
		return category != null && VALID_CATEGORIES.contains(category.trim().toUpperCase(Locale.ROOT));
	}

	public String getNormalizedCategory() {
		return hasValidCategory() ? category.trim().toUpperCase(Locale.ROOT) : null;
	}
}
