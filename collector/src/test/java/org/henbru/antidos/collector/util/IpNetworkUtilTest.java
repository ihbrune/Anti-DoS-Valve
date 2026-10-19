package org.henbru.antidos.collector.util;

import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IpNetworkUtilTest {

	@Test
	void testParseIPv4SingleHost() {
		IpNetworkInfo info = IpNetworkUtil.parse("192.168.1.42");
		assertEquals(4, info.version());
		assertEquals(32, info.prefix());
		long expected = IpNetworkUtil.ipv4ToLong("192.168.1.42");
		assertEquals(expected, info.v4Start());
		assertEquals(expected, info.v4End());
		assertNull(info.v6Start());
		assertNull(info.v6End());
		assertEquals("192.168.1.0/24", info.subnetGroup());
	}

	@Test
	void testParseIPv4Subnet24() {
		IpNetworkInfo info = IpNetworkUtil.parse("192.168.1.0/24");
		assertEquals(4, info.version());
		assertEquals(24, info.prefix());
		assertEquals(IpNetworkUtil.ipv4ToLong("192.168.1.0"), info.v4Start());
		assertEquals(IpNetworkUtil.ipv4ToLong("192.168.1.255"), info.v4End());
		assertEquals("192.168.1.0/24", info.subnetGroup());
	}

	@Test
	void testParseIPv4Subnet16() {
		IpNetworkInfo info = IpNetworkUtil.parse("10.0.0.0/16");
		assertEquals(4, info.version());
		assertEquals(16, info.prefix());
		assertEquals(IpNetworkUtil.ipv4ToLong("10.0.0.0"), info.v4Start());
		assertEquals(IpNetworkUtil.ipv4ToLong("10.0.255.255"), info.v4End());
		assertEquals("10.0.0.0/16", info.subnetGroup());
	}

	@Test
	void testParseIPv6SingleHost() {
		IpNetworkInfo info = IpNetworkUtil.parse("2001:db8:85a3:8d3::1");
		assertEquals(6, info.version());
		assertEquals(128, info.prefix());
		assertNull(info.v4Start());
		assertNull(info.v4End());
		assertNotNull(info.v6Start());
		assertEquals(info.v6Start(), info.v6End());
		assertEquals("20010db885a308d3", info.v6Start());
		assertEquals("2001:db8:85a3:8d3::/64", info.subnetGroup());
	}

	@Test
	void testParseIPv6Subnet64() {
		IpNetworkInfo info = IpNetworkUtil.parse("2001:db8:85a3:8d3::/64");
		assertEquals(6, info.version());
		assertEquals(64, info.prefix());
		assertEquals("20010db885a308d3", info.v6Start());
		assertEquals("20010db885a308d3", info.v6End());
		assertEquals("2001:db8:85a3:8d3::/64", info.subnetGroup());
	}

	@Test
	void testParseIPv6Subnet48() {
		IpNetworkInfo info = IpNetworkUtil.parse("2001:db8:85a3::/48");
		assertEquals(6, info.version());
		assertEquals(48, info.prefix());
		assertEquals("20010db885a30000", info.v6Start());
		assertEquals("20010db885a3ffff", info.v6End());
		assertEquals("2001:db8:85a3::/48", info.subnetGroup());
	}

	@Test
	void testParseSearchQueryShorthand() {
		IpNetworkUtil.SearchCriteria c1 = IpNetworkUtil.parseSearchQuery("192.168.1.");
		assertTrue(c1.isIpSearch());
		assertEquals(4, c1.ipVersion());
		assertEquals(IpNetworkUtil.ipv4ToLong("192.168.1.0"), c1.v4Start());
		assertEquals(IpNetworkUtil.ipv4ToLong("192.168.1.255"), c1.v4End());

		IpNetworkUtil.SearchCriteria c2 = IpNetworkUtil.parseSearchQuery("10.");
		assertTrue(c2.isIpSearch());
		assertEquals(4, c2.ipVersion());
		assertEquals(IpNetworkUtil.ipv4ToLong("10.0.0.0"), c2.v4Start());
		assertEquals(IpNetworkUtil.ipv4ToLong("10.255.255.255"), c2.v4End());

		// Shorthand prefix without trailing dot, e.g. "52.167.114" -> /24, "10.0" -> /16
		IpNetworkUtil.SearchCriteria cShort24 = IpNetworkUtil.parseSearchQuery("52.167.114");
		assertTrue(cShort24.isIpSearch());
		assertEquals(4, cShort24.ipVersion());
		assertEquals(IpNetworkUtil.ipv4ToLong("52.167.114.0"), cShort24.v4Start());
		assertEquals(IpNetworkUtil.ipv4ToLong("52.167.114.255"), cShort24.v4End());

		IpNetworkUtil.SearchCriteria cShort16 = IpNetworkUtil.parseSearchQuery("10.0");
		assertTrue(cShort16.isIpSearch());
		assertEquals(4, cShort16.ipVersion());
		assertEquals(IpNetworkUtil.ipv4ToLong("10.0.0.0"), cShort16.v4Start());
		assertEquals(IpNetworkUtil.ipv4ToLong("10.0.255.255"), cShort16.v4End());

		IpNetworkUtil.SearchCriteria c3 = IpNetworkUtil.parseSearchQuery("test-host");
		assertFalse(c3.isIpSearch());
		assertTrue(c3.hasFilter());
		assertEquals("test-host", c3.rawQuery());
	}

	@Test
	void testPrivateOrLocalIPv4() {
		// RFC 1918
		assertTrue(IpNetworkUtil.isPrivateOrLocal("10.68.1.1"));
		assertEquals("Private Network (RFC 1918)", IpNetworkUtil.getPrivateNetworkDescription("10.68.1.1"));
		assertTrue(IpNetworkUtil.isPrivateOrLocal("10.68.0.0/16"));
		assertEquals("Private Network (RFC 1918)", IpNetworkUtil.getPrivateNetworkDescription("10.68.0.0/16"));
		assertTrue(IpNetworkUtil.isPrivateOrLocal("172.16.0.1"));
		assertTrue(IpNetworkUtil.isPrivateOrLocal("172.31.255.255"));
		assertTrue(IpNetworkUtil.isPrivateOrLocal("192.168.1.100"));
		assertEquals("Private Network (RFC 1918)", IpNetworkUtil.getPrivateNetworkDescription("192.168.1.100"));

		// Public boundary around 172.16/12
		assertFalse(IpNetworkUtil.isPrivateOrLocal("172.15.255.255"));
		assertFalse(IpNetworkUtil.isPrivateOrLocal("172.32.0.1"));

		// Loopback & Link-Local
		assertTrue(IpNetworkUtil.isPrivateOrLocal("127.0.0.1"));
		assertEquals("Loopback / Localhost", IpNetworkUtil.getPrivateNetworkDescription("127.0.0.1"));
		assertTrue(IpNetworkUtil.isPrivateOrLocal("169.254.10.20"));
		assertEquals("Link-Local", IpNetworkUtil.getPrivateNetworkDescription("169.254.10.20"));

		// CGNAT / Shared Address Space (RFC 6598)
		assertTrue(IpNetworkUtil.isPrivateOrLocal("100.64.1.1"));
		assertEquals("Shared Address Space (RFC 6598)", IpNetworkUtil.getPrivateNetworkDescription("100.64.1.1"));

		// Public IPv4
		assertFalse(IpNetworkUtil.isPrivateOrLocal("8.8.8.8"));
		assertNull(IpNetworkUtil.getPrivateNetworkDescription("8.8.8.8"));
		assertFalse(IpNetworkUtil.isPrivateOrLocal("142.250.185.206"));
	}

	@Test
	void testPrivateOrLocalIPv6() {
		// Loopback & Link-Local
		assertTrue(IpNetworkUtil.isPrivateOrLocal("::1"));
		assertEquals("Loopback / Localhost", IpNetworkUtil.getPrivateNetworkDescription("::1"));
		assertTrue(IpNetworkUtil.isPrivateOrLocal("[::1]"));
		assertEquals("Loopback / Localhost", IpNetworkUtil.getPrivateNetworkDescription("[::1]"));
		assertTrue(IpNetworkUtil.isPrivateOrLocal("fe80::1ff:fe23:4567"));
		assertEquals("Link-Local", IpNetworkUtil.getPrivateNetworkDescription("fe80::1ff:fe23:4567"));

		// Unique Local Address (ULA RFC 4193)
		assertTrue(IpNetworkUtil.isPrivateOrLocal("fd00:10:68::1"));
		assertEquals("Unique Local Address (RFC 4193)", IpNetworkUtil.getPrivateNetworkDescription("fd00:10:68::1"));
		assertTrue(IpNetworkUtil.isPrivateOrLocal("fc00::1"));
		assertEquals("Unique Local Address (RFC 4193)", IpNetworkUtil.getPrivateNetworkDescription("fc00::1"));

		// Public IPv6
		assertFalse(IpNetworkUtil.isPrivateOrLocal("2001:db8:85a3::1"));
		assertNull(IpNetworkUtil.getPrivateNetworkDescription("2001:db8:85a3::1"));
		assertFalse(IpNetworkUtil.isPrivateOrLocal("2a01:4f8:c010:d56::1"));
	}

	@Test
	void testPrivateOrLocalNonIp() {
		assertFalse(IpNetworkUtil.isPrivateOrLocal(null));
		assertFalse(IpNetworkUtil.isPrivateOrLocal(""));
		assertFalse(IpNetworkUtil.isPrivateOrLocal("   "));
		assertFalse(IpNetworkUtil.isPrivateOrLocal("some-random-hostname"));
		assertNull(IpNetworkUtil.getPrivateNetworkDescription("some-random-hostname"));
	}
}
