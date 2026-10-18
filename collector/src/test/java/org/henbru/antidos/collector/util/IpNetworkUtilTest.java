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

		IpNetworkUtil.SearchCriteria c3 = IpNetworkUtil.parseSearchQuery("test-host");
		assertFalse(c3.isIpSearch());
		assertTrue(c3.hasFilter());
		assertEquals("test-host", c3.rawQuery());
	}
}
