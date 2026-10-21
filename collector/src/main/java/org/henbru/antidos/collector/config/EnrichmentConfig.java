package org.henbru.antidos.collector.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
	private int ttlDays = 30; // MaxMind GeoLite2 compliance and metadata freshness TTL in days
	private Map<String, CrawlerFeedConfig> crawlerFeeds = createDefaultCrawlerFeeds();

	public static Map<String, CrawlerFeedConfig> createDefaultCrawlerFeeds() {
		Map<String, CrawlerFeedConfig> map = new LinkedHashMap<>();
		map.put("googlebot", new CrawlerFeedConfig("googlebot", "Googlebot", "SEARCH_ENGINE", "https://developers.google.com/search/apis/ipranges/googlebot.json"));
		map.put("bingbot", new CrawlerFeedConfig("bingbot", "Bingbot", "SEARCH_ENGINE", "https://www.bing.com/toolbox/bingbot.json"));
		map.put("applebot", new CrawlerFeedConfig("applebot", "Applebot", "SEARCH_ENGINE", "https://search.developer.apple.com/applebot.json"));
		map.put("openai-gptbot", new CrawlerFeedConfig("openai-gptbot", "OpenAI GPTBot", "AI_CRAWLER", "https://openai.com/gptbot.json"));
		map.put("openai-chatgpt-user", new CrawlerFeedConfig("openai-chatgpt-user", "ChatGPT User", "AI_CRAWLER", "https://openai.com/chatgpt-user.json"));
		map.put("tor-exit-nodes", new CrawlerFeedConfig("tor-exit-nodes", "Tor Bulk Exit Nodes", "TOR_EXIT_NODE", "https://check.torproject.org/torbulkexitlist"));
		return map;
	}

	public EnrichmentConfig() {
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

	public int getTtlDays() {
		return ttlDays;
	}

	public void setTtlDays(int ttlDays) {
		this.ttlDays = ttlDays;
	}

	public Map<String, CrawlerFeedConfig> getCrawlerFeeds() {
		for (Map.Entry<String, CrawlerFeedConfig> entry : crawlerFeeds.entrySet()) {
			if (entry.getValue() != null && (entry.getValue().getKey() == null || entry.getValue().getKey().isBlank())) {
				entry.getValue().setKey(entry.getKey());
			}
		}
		return crawlerFeeds;
	}

	public void setCrawlerFeeds(Map<String, CrawlerFeedConfig> crawlerFeeds) {
		if (crawlerFeeds != null) {
			this.crawlerFeeds = crawlerFeeds;
		}
	}

	public List<CrawlerFeedConfig> getCrawlerFeedsList() {
		return new ArrayList<>(getCrawlerFeeds().values());
	}
}
