package org.henbru.antidos.collector.enrichment;

import java.util.ArrayList;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.InternalNetworkConfig;
import org.henbru.antidos.collector.model.InternalNetworkMatch;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InternalNetworkServiceTest {

	private CollectorProperties properties;
	private InternalNetworkService service;

	@BeforeEach
	void setUp() {
		properties = new CollectorProperties();
		List<InternalNetworkConfig> list = new ArrayList<>();
		list.add(new InternalNetworkConfig("198.51.100.0/24", "Corporate Campus", "HQ & Campus WLAN"));
		list.add(new InternalNetworkConfig("203.0.113.*", "Branch Office", "Regional Branch"));
		list.add(new InternalNetworkConfig("2001:db8:1::/48", "Internal IPv6 Net", "Data Center"));
		properties.setInternalNetworks(list);

		service = new InternalNetworkService(properties);
	}

	@Test
	void testNormalizeWildcardOrCidr() {
		assertEquals("198.51.100.0/24", InternalNetworkService.normalizeWildcardOrCidr("198.51.100.0/24"));
		assertEquals("198.51.100.0/24", InternalNetworkService.normalizeWildcardOrCidr("198.51.100.*"));
		assertEquals("198.51.0.0/16", InternalNetworkService.normalizeWildcardOrCidr("198.51.*.*"));
		assertEquals("198.51.0.0/16", InternalNetworkService.normalizeWildcardOrCidr("198.51.*"));
		assertEquals("10.0.0.0/8", InternalNetworkService.normalizeWildcardOrCidr("10.*"));
		assertEquals("10.0.0.0/8", InternalNetworkService.normalizeWildcardOrCidr("10.*.*.*"));
		assertEquals("198.51.100.5/32", InternalNetworkService.normalizeWildcardOrCidr("198.51.100.5"));
		assertEquals("2001:db8::/32", InternalNetworkService.normalizeWildcardOrCidr("2001:db8::/32"));
		assertEquals("2001:db8::1/128", InternalNetworkService.normalizeWildcardOrCidr("2001:db8::1"));
		assertEquals("", InternalNetworkService.normalizeWildcardOrCidr(null));
		assertEquals("", InternalNetworkService.normalizeWildcardOrCidr("  "));
	}

	@Test
	void testFindMatchIpv4Cidr() {
		InternalNetworkMatch match = service.findMatch("198.51.100.42");
		assertNotNull(match);
		assertEquals("198.51.100.0/24", match.cidr());
		assertEquals("Corporate Campus", match.name());
		assertEquals("HQ & Campus WLAN", match.description());
		assertTrue(service.isInternalNetwork("198.51.100.42"));

		// Boundary tests
		assertNotNull(service.findMatch("198.51.100.0"));
		assertNotNull(service.findMatch("198.51.100.255"));
		assertNull(service.findMatch("198.51.101.0"));
		assertNull(service.findMatch("198.51.99.255"));
	}

	@Test
	void testFindMatchWildcardNotation() {
		// "203.0.113.*" normalized to "203.0.113.0/24"
		InternalNetworkMatch match = service.findMatch("203.0.113.77");
		assertNotNull(match);
		assertEquals("203.0.113.0/24", match.cidr());
		assertEquals("Branch Office", match.name());
		assertEquals("Regional Branch", match.description());

		// With port
		InternalNetworkMatch matchWithPort = service.findMatch("203.0.113.77:8080");
		assertNotNull(matchWithPort);
		assertEquals("Branch Office", matchWithPort.name());
	}

	@Test
	void testFindMatchIpv6() {
		InternalNetworkMatch match = service.findMatch("2001:db8:1::cafe");
		assertNotNull(match);
		assertEquals("Internal IPv6 Net", match.name());

		assertNull(service.findMatch("2001:db8:2::1"));
	}

	@Test
	void testUnmatchedAndNullHandling() {
		assertNull(service.findMatch(null));
		assertNull(service.findMatch(""));
		assertNull(service.findMatch("   "));
		assertNull(service.findMatch("invalid-ip"));
		assertNull(service.findMatch("8.8.8.8"));
		assertFalse(service.isInternalNetwork("8.8.8.8"));
	}

	@Test
	void testReloadDynamicUpdate() {
		assertTrue(service.isInternalNetwork("198.51.100.1"));
		assertFalse(service.isInternalNetwork("192.0.2.1"));

		// Clear configured networks and reload
		properties.getInternalNetworks().clear();
		properties.getInternalNetworks().add(new InternalNetworkConfig("192.0.2.0/24", "New Net", "Desc"));
		service.reload();

		assertFalse(service.isInternalNetwork("198.51.100.1"));
		assertTrue(service.isInternalNetwork("192.0.2.1"));
		assertEquals("New Net", service.findMatch("192.0.2.1").name());
	}
}

