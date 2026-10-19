package org.henbru.antidos.collector.enrichment;

import java.util.Optional;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.IpEnrichmentResult;
import org.henbru.antidos.collector.storage.BotIpRangeRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class DefaultIpEnrichmentServiceTest {

	private CollectorProperties properties;
	private AsnClassifierService asnClassifierService;
	private BotIpRangeRepository botIpRangeRepository;
	private DefaultIpEnrichmentService enrichmentService;

	@BeforeEach
	public void setUp() {
		properties = new CollectorProperties();
		properties.getEnrichment().setEnabled(true);

		asnClassifierService = Mockito.mock(AsnClassifierService.class);
		botIpRangeRepository = Mockito.mock(BotIpRangeRepository.class);
		when(botIpRangeRepository.findBotForIp(anyString())).thenReturn(Optional.empty());

		enrichmentService = new DefaultIpEnrichmentService(properties, asnClassifierService, botIpRangeRepository);
	}

	@Test
	void testEnrichPrivateIpv4() {
		IpEnrichmentResult r1 = enrichmentService.enrich("10.68.1.1");
		assertEquals(ClientType.PRIVATE_NETWORK, r1.clientType());
		assertEquals("Private Network (RFC 1918)", r1.asOrg());
		assertNull(r1.asn());
		assertNull(r1.countryCode());

		IpEnrichmentResult r2 = enrichmentService.enrich("10.68.0.0/16");
		assertEquals(ClientType.PRIVATE_NETWORK, r2.clientType());
		assertEquals("Private Network (RFC 1918)", r2.asOrg());

		IpEnrichmentResult r3 = enrichmentService.enrich("192.168.178.1");
		assertEquals(ClientType.PRIVATE_NETWORK, r3.clientType());

		IpEnrichmentResult r4 = enrichmentService.enrich("172.20.5.1");
		assertEquals(ClientType.PRIVATE_NETWORK, r4.clientType());
	}

	@Test
	void testEnrichPrivateIpv6AndLoopback() {
		IpEnrichmentResult r1 = enrichmentService.enrich("::1");
		assertEquals(ClientType.PRIVATE_NETWORK, r1.clientType());
		assertEquals("Loopback / Localhost", r1.asOrg());

		IpEnrichmentResult r2 = enrichmentService.enrich("127.0.0.1");
		assertEquals(ClientType.PRIVATE_NETWORK, r2.clientType());
		assertEquals("Loopback / Localhost", r2.asOrg());

		IpEnrichmentResult r3 = enrichmentService.enrich("fd00:10:68::42");
		assertEquals(ClientType.PRIVATE_NETWORK, r3.clientType());
		assertEquals("Unique Local Address (RFC 4193)", r3.asOrg());
	}

	@Test
	void testEnrichDisabledReturnsUnknown() {
		properties.getEnrichment().setEnabled(false);
		IpEnrichmentResult res = enrichmentService.enrich("10.68.1.1");
		assertEquals(ClientType.UNKNOWN, res.clientType());
	}

	@Test
	void testEnrichTorExitNode() {
		when(botIpRangeRepository.findBotForIp("185.220.101.4")).thenReturn(
				Optional.of(new org.henbru.antidos.collector.storage.BotIpRangeRepository.BotMatch(
						"tor-exit-nodes", "Tor Bulk Exit Nodes", "TOR_EXIT_NODE"
				))
		);

		IpEnrichmentResult res = enrichmentService.enrich("185.220.101.4");
		assertEquals(ClientType.TOR_EXIT_NODE, res.clientType());
		assertEquals("Tor Bulk Exit Nodes", res.asOrg());
	}
}
