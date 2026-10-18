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
}
