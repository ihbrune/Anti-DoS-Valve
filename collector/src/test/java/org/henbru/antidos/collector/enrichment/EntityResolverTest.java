package org.henbru.antidos.collector.enrichment;

import java.time.Instant;
import java.util.List;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.EnrichmentStatus;
import org.henbru.antidos.collector.model.IntelRange;
import org.henbru.antidos.collector.model.IntelSource;
import org.henbru.antidos.collector.model.NetworkEntity;
import org.henbru.antidos.collector.storage.IntelRangeRepository;
import org.henbru.antidos.collector.storage.IntelSourceRepository;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class EntityResolverTest {

	@Autowired
	private EntityResolver entityResolver;

	@Autowired
	private IntelRegistry intelRegistry;

	@Autowired
	private IntelSourceRepository intelSourceRepository;

	@Autowired
	private IntelRangeRepository intelRangeRepository;

	@BeforeEach
	void setUp() {
		entityResolver.clearCache();

		// Configure test Tor and Googlebot sources
		Instant now = Instant.now();
		intelSourceRepository.upsert(new IntelSource(
				"tor-test", "FEED", "Tor Exit Nodes", "TOR_EXIT_NODE", "https://tor.test", 1L, now, "SUCCESS", 1, null
		));
		intelRangeRepository.replaceRangesForSource("tor-test", List.of(
				new IntelRange(
						null, "tor-test", "185.220.101.5/32", 4, 32,
						IpNetworkUtil.ipv4ToLong("185.220.101.5"),
						IpNetworkUtil.ipv4ToLong("185.220.101.5"),
						null, null, 24940L, "DE", "TOR_EXIT_NODE", "Tor Exit Node", 1L, now
				)
		));

		intelSourceRepository.upsert(new IntelSource(
				"crawler-test", "FEED", "Googlebot", "SEARCH_ENGINE", "https://google.test", 1L, now, "SUCCESS", 1, null
		));
		intelRangeRepository.replaceRangesForSource("crawler-test", List.of(
				new IntelRange(
						null, "crawler-test", "66.249.66.0/24", 4, 24,
						IpNetworkUtil.ipv4ToLong("66.249.66.0"),
						IpNetworkUtil.ipv4ToLong("66.249.66.255"),
						null, null, 15169L, "US", "SEARCH_ENGINE", "Googlebot", 1L, now
				)
		));

		intelRegistry.reload();
	}

	@Test
	void testResolvePrivateNetwork() {
		NetworkEntity entity = entityResolver.getOrCreate("192.168.1.100", Instant.now());
		assertEquals(ClientType.PRIVATE_NETWORK, entity.clientType());
		assertEquals("PRIVATE_NETWORK", entity.tags());
		assertEquals("Private Network (RFC 1918)", entity.asOrg());
		assertEquals(EnrichmentStatus.ENRICHED, entity.enrichmentStatus());
	}

	@Test
	void testResolveTorExitNode() {
		NetworkEntity entity = entityResolver.getOrCreate("185.220.101.5", Instant.now());
		NetworkEntity resolved = entityResolver.resolve(entity);

		assertEquals(ClientType.TOR_EXIT_NODE, resolved.clientType());
		assertTrue(resolved.tags() != null && resolved.tags().contains("TOR_EXIT_NODE"));
		assertEquals(EnrichmentStatus.ENRICHED, resolved.enrichmentStatus());
	}

	@Test
	void testResolveVerifiedCrawler() {
		NetworkEntity entity = entityResolver.getOrCreate("66.249.66.42", Instant.now());
		NetworkEntity resolved = entityResolver.resolve(entity);

		assertEquals(ClientType.SEARCH_ENGINE, resolved.clientType());
		assertTrue(resolved.tags() != null && resolved.tags().contains("SEARCH_ENGINE"));
		assertEquals("Googlebot", resolved.asOrg());
		assertEquals(EnrichmentStatus.ENRICHED, resolved.enrichmentStatus());
	}

	@Test
	void testEntityCache() {
		NetworkEntity first = entityResolver.getOrCreate("203.0.113.199", Instant.now());
		assertNotNull(first.id());

		NetworkEntity second = entityResolver.getOrCreate("203.0.113.199", Instant.now());
		assertSame(first, second, "Should return cached entity instance");
	}
}
