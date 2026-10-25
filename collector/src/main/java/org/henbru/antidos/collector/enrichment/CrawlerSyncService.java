package org.henbru.antidos.collector.enrichment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.CrawlerFeedConfig;
import org.henbru.antidos.collector.model.BotIpRange;
import org.henbru.antidos.collector.model.CrawlerFeed;
import org.henbru.antidos.collector.model.IntelRange;
import org.henbru.antidos.collector.model.IntelSource;
import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.henbru.antidos.collector.storage.BotIpRangeRepository;
import org.henbru.antidos.collector.storage.CrawlerFeedRepository;
import org.henbru.antidos.collector.storage.IntelRangeRepository;
import org.henbru.antidos.collector.storage.IntelSourceRepository;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service for periodically fetching, validating, and updating verified bot and crawler IP ranges
 * from remote JSON feeds (Googlebot, Bingbot, OpenAI, Anthropic, etc.).
 */
@Service
public class CrawlerSyncService {

	private static final Logger log = LoggerFactory.getLogger(CrawlerSyncService.class);

	private final CollectorProperties properties;
	private final CrawlerFeedRepository crawlerFeedRepository;
	private final BotIpRangeRepository botIpRangeRepository;
	private final IntelSourceRepository intelSourceRepository;
	private final IntelRangeRepository intelRangeRepository;
	private final IntelRegistry intelRegistry;
	private final HttpClient httpClient;
	private final ObjectMapper objectMapper;

	@Autowired
	public CrawlerSyncService(
			CollectorProperties properties,
			CrawlerFeedRepository crawlerFeedRepository,
			BotIpRangeRepository botIpRangeRepository,
			IntelSourceRepository intelSourceRepository,
			IntelRangeRepository intelRangeRepository,
			IntelRegistry intelRegistry,
			ObjectMapper objectMapper) {
		this.properties = properties;
		this.crawlerFeedRepository = crawlerFeedRepository;
		this.botIpRangeRepository = botIpRangeRepository;
		this.intelSourceRepository = intelSourceRepository;
		this.intelRangeRepository = intelRangeRepository;
		this.intelRegistry = intelRegistry;
		this.objectMapper = objectMapper;
		this.httpClient = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(10))
				.followRedirects(HttpClient.Redirect.NORMAL)
				.build();
		if (properties != null && properties.getEnrichment() != null) {
			this.maxAttempts = properties.getEnrichment().getCrawlerSyncMaxAttempts();
			this.retryBackoffMs = properties.getEnrichment().getCrawlerSyncRetryBackoffMs();
		}
	}

	public CrawlerSyncService(
			CollectorProperties properties,
			CrawlerFeedRepository crawlerFeedRepository,
			BotIpRangeRepository botIpRangeRepository,
			ObjectMapper objectMapper) {
		this(properties, crawlerFeedRepository, botIpRangeRepository, null, null, null, objectMapper);
	}

	/**
	 * Synchronizes all configured crawler feeds and cleans up orphaned feeds from the database.
	 */
	public void syncAll() {
		if (!properties.getEnrichment().isEnabled() || !properties.getEnrichment().isCrawlerSyncEnabled()) {
			log.debug("Crawler sync is disabled in configuration");
			return;
		}

		List<CrawlerFeedConfig> configs = properties.getEnrichment().getCrawlerFeedsList();
		if (configs == null || configs.isEmpty()) {
			return;
		}

		// 1. Cleanup orphaned feeds no longer in configuration
		cleanupOrphans(configs);

		// 2. Sync each active feed
		for (CrawlerFeedConfig config : configs) {
			try {
				syncFeed(config);
			} catch (Exception e) {
				log.warn("Error syncing crawler feed '{}': {}", config.getName(), e.getMessage());
			}
		}
	}

	/**
	 * Synchronizes an individual crawler feed by key (e.g. for manual ad-hoc UI triggers).
	 */
	public boolean syncFeedByKey(String feedKey) {
		List<CrawlerFeedConfig> configs = properties.getEnrichment().getCrawlerFeedsList();
		if (configs == null) {
			return false;
		}
		for (CrawlerFeedConfig config : configs) {
			if (config.getKey().equalsIgnoreCase(feedKey)) {
				return syncFeed(config);
			}
		}
		return false;
	}

	private static final int DEFAULT_MAX_ATTEMPTS = 3;
	private static final long DEFAULT_RETRY_BACKOFF_MS = 5000L;

	private int maxAttempts = DEFAULT_MAX_ATTEMPTS;
	private long retryBackoffMs = DEFAULT_RETRY_BACKOFF_MS;

	void configureRetry(int maxAttempts, long retryBackoffMs) {
		this.maxAttempts = maxAttempts;
		this.retryBackoffMs = retryBackoffMs;
	}

	public boolean syncFeed(CrawlerFeedConfig config) {
		if (config == null) {
			return false;
		}

		if (!config.isEnabled()) {
			log.info("Crawler feed '{}' is disabled in configuration, skipping sync.", config.getName());
			crawlerFeedRepository.upsert(new CrawlerFeed(
					config.getKey(),
					config.getName(),
					config.getCategory(),
					config.getUrl(),
					null,
					"DISABLED",
					0,
					"Feed is disabled in configuration"
			));
			botIpRangeRepository.replaceRangesForFeed(config.getKey(), List.of());
			if (intelRangeRepository != null && intelSourceRepository != null) {
				intelRangeRepository.replaceRangesForSource(config.getKey(), List.of());
				intelSourceRepository.upsert(new IntelSource(
						config.getKey(),
						"FEED",
						config.getName(),
						config.getNormalizedCategory(),
						config.getUrl(),
						1,
						Instant.now(),
						"DISABLED",
						0,
						"Feed is disabled in configuration"
				));
				if (intelRegistry != null) {
					intelRegistry.reload();
				}
			}
			return false;
		}

		if (!config.hasValidCategory()) {
			String error = "Unknown category '" + config.getCategory() + "'. Allowed: " + CrawlerFeedConfig.VALID_CATEGORIES;
			log.warn("Crawler feed '{}' has invalid/unknown category '{}'. Allowed: {}. Feed will be skipped.",
					config.getName(), config.getCategory(), CrawlerFeedConfig.VALID_CATEGORIES);
			crawlerFeedRepository.upsert(new CrawlerFeed(
					config.getKey(),
					config.getName(),
					config.getCategory(),
					config.getUrl(),
					null,
					"INVALID_CONFIG",
					0,
					error
			));
			botIpRangeRepository.replaceRangesForFeed(config.getKey(), List.of());
			if (intelRangeRepository != null && intelSourceRepository != null) {
				intelRangeRepository.replaceRangesForSource(config.getKey(), List.of());
				intelSourceRepository.upsert(new IntelSource(
						config.getKey(),
						"FEED",
						config.getName(),
						config.getNormalizedCategory(),
						config.getUrl(),
						1,
						Instant.now(),
						"INVALID_CONFIG",
						0,
						error
				));
				if (intelRegistry != null) {
					intelRegistry.reload();
				}
			}
			return false;
		}

		log.info("Synchronizing crawler feed '{}' from {}", config.getName(), config.getUrl());

		// Ensure feed metadata entry exists in database
		crawlerFeedRepository.upsert(new CrawlerFeed(
				config.getKey(),
				config.getName(),
				config.getNormalizedCategory(),
				config.getUrl(),
				null,
				"SYNCING",
				0,
				null
		));

		int attempts = this.maxAttempts;
		HttpResponse<String> response = null;
		Exception lastException = null;

		for (int attempt = 1; attempt <= attempts; attempt++) {
			try {
				HttpRequest request = HttpRequest.newBuilder()
						.uri(URI.create(config.getUrl()))
						.timeout(Duration.ofSeconds(15))
						.header("User-Agent", "AntiDoS-Collector/1.7 (+https://github.com/henbru/Anti-DoS-Valve)")
						.GET()
						.build();

				response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

				if (response.statusCode() >= 200 && response.statusCode() < 300) {
					if (attempt > 1) {
						log.info("Crawler feed '{}' recovered and succeeded on attempt {}/{}",
								config.getName(), attempt, attempts);
					}
					lastException = null;
					break;
				}

				log.warn("Attempt {}/{} to download crawler feed '{}' returned HTTP {}",
						attempt, attempts, config.getName(), response.statusCode());

			} catch (java.io.IOException | InterruptedException | RuntimeException e) {
				lastException = e;
				log.warn("Attempt {}/{} to download crawler feed '{}' failed: {}",
						attempt, attempts, config.getName(), e.getMessage());
				if (e instanceof InterruptedException) {
					Thread.currentThread().interrupt();
					break;
				}
			}

			if (attempt < attempts) {
				try {
					Thread.sleep(retryBackoffMs * attempt);
				} catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					break;
				}
			}
		}

		if (response == null || response.statusCode() < 200 || response.statusCode() >= 300) {
			String error = response != null
					? "HTTP " + response.statusCode()
					: (lastException != null ? lastException.getClass().getSimpleName() + ": " + lastException.getMessage() : "Request failed");
			log.warn("All {} attempts to download crawler feed '{}' failed: {}. Retaining previously cached IP ranges.",
					attempts, config.getName(), error);
			crawlerFeedRepository.recordSyncFailure(config.getKey(), error);
			if (intelSourceRepository != null) {
				intelSourceRepository.recordSyncFailure(config.getKey(), error);
			}
			return false;
		}

		List<String> cidrs = extractCidrs(response.body());
		if (cidrs.isEmpty()) {
			String error = "Feed returned 0 valid CIDR prefixes or IP addresses";
			log.warn("Crawler feed '{}' returned 0 valid prefixes: {}. Retaining previously cached IP ranges.",
					config.getName(), error);
			crawlerFeedRepository.recordSyncFailure(config.getKey(), error);
			if (intelSourceRepository != null) {
				intelSourceRepository.recordSyncFailure(config.getKey(), error);
			}
			return false;
		}

		List<BotIpRange> ranges = new ArrayList<>();
		for (String cidr : cidrs) {
			IpNetworkInfo net = IpNetworkUtil.parse(cidr);
			ranges.add(new BotIpRange(
					null,
					config.getKey(),
					cidr,
					net.version(),
					net.v4Start(),
					net.v4End(),
					net.v6Start(),
					net.v6End(),
					Instant.now()
			));
		}

		botIpRangeRepository.replaceRangesForFeed(config.getKey(), ranges);
		crawlerFeedRepository.updateSyncStatus(config.getKey(), "SUCCESS", ranges.size(), null, Instant.now());

		if (intelRangeRepository != null && intelSourceRepository != null) {
			List<IntelRange> intelRanges = new ArrayList<>(ranges.size());
			for (BotIpRange r : ranges) {
				IpNetworkInfo net = IpNetworkUtil.parse(r.cidr());
				intelRanges.add(new IntelRange(
						null,
						config.getKey(),
						r.cidr(),
						r.ipVersion(),
						net.prefix(),
						r.ipV4Start(),
						r.ipV4End(),
						r.ipV6Start(),
						r.ipV6End(),
						null,
						null,
						config.getNormalizedCategory(),
						config.getName(),
						1,
						Instant.now()
				));
			}
			intelRangeRepository.replaceRangesForSource(config.getKey(), intelRanges);
			intelSourceRepository.upsert(new IntelSource(
					config.getKey(),
					"FEED",
					config.getName(),
					config.getNormalizedCategory(),
					config.getUrl(),
					1,
					Instant.now(),
					"SUCCESS",
					intelRanges.size(),
					null
			));
			if (intelRegistry != null) {
				intelRegistry.reload();
			}
		}

		log.info("Successfully updated crawler feed '{}': {} prefixes stored", config.getName(), ranges.size());
		return true;
	}

	/**
	 * Retries synchronization for any enabled crawler feeds currently in FAILED state.
	 *
	 * @return the number of feeds that successfully recovered
	 */
	public int syncFailedFeeds() {
		if (!properties.getEnrichment().isEnabled() || !properties.getEnrichment().isCrawlerSyncEnabled()) {
			return 0;
		}

		List<CrawlerFeed> allFeeds = crawlerFeedRepository.findAll();
		List<CrawlerFeedConfig> configs = properties.getEnrichment().getCrawlerFeedsList();
		if (configs == null || configs.isEmpty() || allFeeds.isEmpty()) {
			return 0;
		}

		java.util.Map<String, CrawlerFeedConfig> configMap = new java.util.HashMap<>();
		for (CrawlerFeedConfig c : configs) {
			if (c.getKey() != null) {
				configMap.put(c.getKey().toLowerCase(), c);
			}
		}

		int recovered = 0;
		for (CrawlerFeed feed : allFeeds) {
			if ("FAILED".equalsIgnoreCase(feed.status())) {
				CrawlerFeedConfig cfg = configMap.get(feed.feedKey().toLowerCase());
				if (cfg != null && cfg.isEnabled()) {
					log.info("Executing automatic catch-up sync for failed crawler feed '{}'...", cfg.getName());
					try {
						if (syncFeed(cfg)) {
							recovered++;
							log.info("Failed crawler feed '{}' successfully recovered during catch-up sync", cfg.getName());
						}
					} catch (Exception e) {
						log.warn("Catch-up sync for feed '{}' failed: {}", cfg.getName(), e.getMessage());
					}
				}
			}
		}
		return recovered;
	}

	/**
	 * Removes database records for feeds that are no longer configured in collector-config.yaml.
	 */
	public void cleanupOrphans(List<CrawlerFeedConfig> configs) {
		List<String> activeKeys = configs.stream().map(c -> c.getKey()).toList();
		int deletedRanges = botIpRangeRepository.deleteNotInFeedKeys(activeKeys);
		int deletedFeeds = crawlerFeedRepository.deleteNotIn(activeKeys);

		if (intelRangeRepository != null && intelSourceRepository != null) {
			intelRangeRepository.deleteNotInSourceKeys(activeKeys);
			intelSourceRepository.deleteNotIn(activeKeys);
			if (intelRegistry != null) {
				intelRegistry.reload();
			}
		}

		if (deletedFeeds > 0 || deletedRanges > 0) {
			log.info("Cleaned up orphaned crawler feeds: purged {} feeds and {} associated IP ranges",
					deletedFeeds, deletedRanges);
		}
	}

	List<String> extractCidrs(String rawBody) {
		Set<String> result = new HashSet<>();
		if (rawBody == null || rawBody.trim().isEmpty()) {
			return List.of();
		}

		String trimmed = rawBody.trim();
		if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
			// Parse JSON
			try {
				JsonNode root = objectMapper.readTree(trimmed);
				findCidrsInJson(root, result);
			} catch (com.fasterxml.jackson.core.JsonProcessingException e) {
				log.warn("Could not parse crawler feed as JSON, attempting plaintext fallback: {}", e.getMessage());
				parsePlaintextLines(trimmed, result);
			}
		} else {
			// Plaintext list
			parsePlaintextLines(trimmed, result);
		}

		return new ArrayList<>(result);
	}

	private void findCidrsInJson(JsonNode node, Set<String> result) {
		if (node.isObject()) {
			node.fields().forEachRemaining(entry -> {
				String key = entry.getKey().toLowerCase();
				JsonNode val = entry.getValue();
				if ((key.contains("prefix") || key.contains("cidr") || key.contains("ip")) && val.isTextual()) {
					String text = val.asText().trim();
					if (isValidCidrOrIp(text)) {
						result.add(canonicalCidr(text));
					}
				} else {
					findCidrsInJson(val, result);
				}
			});
		} else if (node.isArray()) {
			for (JsonNode child : node) {
				if (child.isTextual()) {
					String text = child.asText().trim();
					if (isValidCidrOrIp(text)) {
						result.add(canonicalCidr(text));
					}
				} else {
					findCidrsInJson(child, result);
				}
			}
		}
	}

	private void parsePlaintextLines(String text, Set<String> result) {
		String[] lines = text.split("\\r?\\n");
		for (String line : lines) {
			String clean = line.trim();
			if (!clean.isEmpty() && !clean.startsWith("#") && isValidCidrOrIp(clean)) {
				result.add(canonicalCidr(clean));
			}
		}
	}

	boolean isValidCidrOrIp(String s) {
		if (s == null) {
			return false;
		}
		String clean = s.trim();
		if (clean.isEmpty()) {
			return false;
		}
		if (clean.contains("/")) {
			return clean.contains(".") || clean.contains(":");
		}
		IpNetworkInfo net = IpNetworkUtil.parse(clean);
		return net.v4Start() != null || net.v6Start() != null;
	}

	String canonicalCidr(String s) {
		String clean = s.trim();
		if (clean.contains("/")) {
			return clean;
		}
		if (clean.contains(":")) {
			return clean + "/128";
		}
		return clean + "/32";
	}
}
