package org.henbru.antidos.collector.enrichment;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.CrawlerFeedConfig;
import org.henbru.antidos.collector.storage.BotIpRangeRepository;
import org.henbru.antidos.collector.storage.CrawlerFeedRepository;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CrawlerSyncServiceTest {

	@Test
	void testExtractCidrsFromGoogleJson() {
		String json = """
				{
				  "creationTime": "2024-05-01T12:00:00.000",
				  "prefixes": [
				    { "ipv4Prefix": "66.249.64.0/27" },
				    { "ipv4Prefix": "66.249.66.160/27" },
				    { "ipv6Prefix": "2001:4860:4801:2000::/64" }
				  ]
				}
				""";

		CrawlerSyncService service = new CrawlerSyncService(
				new CollectorProperties(),
				mock(CrawlerFeedRepository.class),
				mock(BotIpRangeRepository.class),
				new ObjectMapper()
		);

		List<String> cidrs = service.extractCidrs(json);
		assertEquals(3, cidrs.size());
		assertTrue(cidrs.contains("66.249.64.0/27"));
		assertTrue(cidrs.contains("66.249.66.160/27"));
		assertTrue(cidrs.contains("2001:4860:4801:2000::/64"));
	}

	@Test
	void testExtractCidrsFromPlaintext() {
		String plaintext = """
				# Some crawler IP list
				192.0.2.0/24
				198.51.100.0/24
				
				# IPv6
				2001:db8::/32
				""";

		CrawlerSyncService service = new CrawlerSyncService(
				new CollectorProperties(),
				mock(CrawlerFeedRepository.class),
				mock(BotIpRangeRepository.class),
				new ObjectMapper()
		);

		List<String> cidrs = service.extractCidrs(plaintext);
		assertEquals(3, cidrs.size());
		assertTrue(cidrs.contains("192.0.2.0/24"));
		assertTrue(cidrs.contains("198.51.100.0/24"));
		assertTrue(cidrs.contains("2001:db8::/32"));
	}

	@Test
	void testCleanupOrphans() {
		CrawlerFeedRepository feedRepo = mock(CrawlerFeedRepository.class);
		BotIpRangeRepository rangeRepo = mock(BotIpRangeRepository.class);

		CrawlerSyncService service = new CrawlerSyncService(
				new CollectorProperties(),
				feedRepo,
				rangeRepo,
				new ObjectMapper()
		);

		List<CrawlerFeedConfig> activeConfigs = List.of(
				new CrawlerFeedConfig("googlebot", "Googlebot", "SEARCH_ENGINE", "http://example.com/google.json")
		);

		service.cleanupOrphans(activeConfigs);

		verify(rangeRepo).deleteNotInFeedKeys(List.of("googlebot"));
		verify(feedRepo).deleteNotIn(List.of("googlebot"));
	}

	@Test
	void testExtractCidrsFromTorBulkExitListPlaintext() {
		String torPlaintext = """
				# Tor Bulk Exit List - https://check.torproject.org/torbulkexitlist
				185.220.101.4
				185.220.101.5
				# Another comment
				203.0.113.50
				""";

		CrawlerSyncService service = new CrawlerSyncService(
				new CollectorProperties(),
				mock(CrawlerFeedRepository.class),
				mock(BotIpRangeRepository.class),
				new ObjectMapper()
		);

		List<String> cidrs = service.extractCidrs(torPlaintext);
		assertEquals(3, cidrs.size());
		assertTrue(cidrs.contains("185.220.101.4/32"));
		assertTrue(cidrs.contains("185.220.101.5/32"));
		assertTrue(cidrs.contains("203.0.113.50/32"));
	}

	@Test
	void testSyncFeedWithInvalidCategoryIsRejectedAndLogged() {
		CrawlerFeedRepository feedRepo = mock(CrawlerFeedRepository.class);
		BotIpRangeRepository rangeRepo = mock(BotIpRangeRepository.class);

		CrawlerSyncService service = new CrawlerSyncService(
				new CollectorProperties(),
				feedRepo,
				rangeRepo,
				new ObjectMapper()
		);

		CrawlerFeedConfig badConfig = new CrawlerFeedConfig("bad-feed", "Bad Feed", "INVALID_CAT", "http://example.com/feed.txt");
		boolean result = service.syncFeed(badConfig);

		assertFalse(result, "Feed with invalid category must not be synchronized");
		verify(feedRepo).upsert(argThat(feed ->
				"INVALID_CONFIG".equals(feed.status()) &&
				feed.lastError() != null && feed.lastError().contains("Unknown category 'INVALID_CAT'")
		));
		verify(rangeRepo).replaceRangesForFeed("bad-feed", List.of());
	}

	@Test
	void testSyncFeedDisabledFeedIsSkipped() {
		CrawlerFeedRepository feedRepo = mock(CrawlerFeedRepository.class);
		BotIpRangeRepository rangeRepo = mock(BotIpRangeRepository.class);

		CrawlerSyncService service = new CrawlerSyncService(
				new CollectorProperties(),
				feedRepo,
				rangeRepo,
				new ObjectMapper()
		);

		CrawlerFeedConfig disabledConfig = new CrawlerFeedConfig("disabled-feed", "Disabled Feed", "SEARCH_ENGINE", "http://example.com/feed.txt", false);
		boolean result = service.syncFeed(disabledConfig);

		assertFalse(result, "Disabled feed must not be synchronized");
		verify(feedRepo).upsert(argThat(feed -> "DISABLED".equals(feed.status())));
		verify(rangeRepo).replaceRangesForFeed("disabled-feed", List.of());
	}

	@Test
	void testExtractCidrsFromApplebotJson() {
		String appleJson = """
				{
				  "creationTime": "2024-03-01T00:00:00",
				  "prefixes": [
				    { "ipv4Prefix": "17.58.98.0/24" },
				    { "ipv4Prefix": "17.58.101.0/24" },
				    { "ipv6Prefix": "2620:149:a40::/48" }
				  ]
				}
				""";

		CrawlerSyncService service = new CrawlerSyncService(
				new CollectorProperties(),
				mock(CrawlerFeedRepository.class),
				mock(BotIpRangeRepository.class),
				new ObjectMapper()
		);

		List<String> cidrs = service.extractCidrs(appleJson);
		assertEquals(3, cidrs.size());
		assertTrue(cidrs.contains("17.58.98.0/24"));
		assertTrue(cidrs.contains("17.58.101.0/24"));
		assertTrue(cidrs.contains("2620:149:a40::/48"));
	}

	@Test
	void testDefaultCrawlerFeedsContainsApplebot() {
		var defaults = org.henbru.antidos.collector.config.EnrichmentConfig.createDefaultCrawlerFeeds();
		assertTrue(defaults.containsKey("applebot"));
		var appleConfig = defaults.get("applebot");
		assertEquals("Applebot", appleConfig.getName());
		assertEquals("SEARCH_ENGINE", appleConfig.getCategory());
		assertEquals("https://search.developer.apple.com/applebot.json", appleConfig.getUrl());
		assertTrue(appleConfig.isEnabled());
	}
}
