package org.henbru.antidos.collector.config;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for IP enrichment, Geo/ASN lookups, and crawler synchronization.
 */
public class EnrichmentConfig {

	private boolean enabled = true;
	private String asnDatabasePath;
	private String countryDatabasePath;
	private String customHostingAsnsFile = "custom-hosting-asns.txt";
	private List<Long> customHostingAsns = new ArrayList<>();
	private boolean crawlerSyncEnabled = true;
	private String crawlerSyncCron = "0 0 4 * * *"; // Daily at 04:00 AM
	private List<CrawlerFeedConfig> crawlerFeeds = new ArrayList<>();

	public EnrichmentConfig() {
		// Populate default feeds out-of-the-box
		crawlerFeeds.add(new CrawlerFeedConfig(
				"googlebot", "Googlebot", "SEARCH_ENGINE",
				"https://developers.google.com/search/apis/ipranges/googlebot.json"));
		crawlerFeeds.add(new CrawlerFeedConfig(
				"bingbot", "Bingbot", "SEARCH_ENGINE",
				"https://www.bing.com/toolbox/bingbot.json"));
		crawlerFeeds.add(new CrawlerFeedConfig(
				"openai-gptbot", "OpenAI GPTBot", "AI_CRAWLER",
				"https://openai.com/gptbot.json"));
		crawlerFeeds.add(new CrawlerFeedConfig(
				"openai-chatgpt-user", "ChatGPT User", "AI_CRAWLER",
				"https://openai.com/chatgpt-user.json"));
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getAsnDatabasePath() {
		return asnDatabasePath;
	}

	public void setAsnDatabasePath(String asnDatabasePath) {
		this.asnDatabasePath = asnDatabasePath;
	}

	public String getCountryDatabasePath() {
		return countryDatabasePath;
	}

	public void setCountryDatabasePath(String countryDatabasePath) {
		this.countryDatabasePath = countryDatabasePath;
	}

	public String getCustomHostingAsnsFile() {
		return customHostingAsnsFile;
	}

	public void setCustomHostingAsnsFile(String customHostingAsnsFile) {
		this.customHostingAsnsFile = customHostingAsnsFile;
	}

	public List<Long> getCustomHostingAsns() {
		return customHostingAsns;
	}

	public void setCustomHostingAsns(List<Long> customHostingAsns) {
		this.customHostingAsns = customHostingAsns != null ? customHostingAsns : new ArrayList<>();
	}

	public boolean isCrawlerSyncEnabled() {
		return crawlerSyncEnabled;
	}

	public void setCrawlerSyncEnabled(boolean crawlerSyncEnabled) {
		this.crawlerSyncEnabled = crawlerSyncEnabled;
	}

	public String getCrawlerSyncCron() {
		return crawlerSyncCron;
	}

	public void setCrawlerSyncCron(String crawlerSyncCron) {
		this.crawlerSyncCron = crawlerSyncCron;
	}

	public List<CrawlerFeedConfig> getCrawlerFeeds() {
		return crawlerFeeds;
	}

	public void setCrawlerFeeds(List<CrawlerFeedConfig> crawlerFeeds) {
		this.crawlerFeeds = crawlerFeeds != null ? crawlerFeeds : new ArrayList<>();
	}
}
