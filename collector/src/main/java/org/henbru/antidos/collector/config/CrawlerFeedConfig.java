package org.henbru.antidos.collector.config;

/**
 * Configuration for a single verified crawler or bot IP range feed.
 */
public class CrawlerFeedConfig {

	private String key;
	private String name;
	private String category = "SEARCH_ENGINE";
	private String url;

	public CrawlerFeedConfig() {
	}

	public CrawlerFeedConfig(String key, String name, String category, String url) {
		this.key = key;
		this.name = name;
		this.category = category;
		this.url = url;
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
}
