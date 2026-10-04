package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.core.StandardEngine;
import org.junit.jupiter.api.Test;

/**
 * Unit test for the valve implementation
 */
class AntiDoSValveTest {

	@Test
	void testMonitorMode() {
		AntiDoSValve valve = new AntiDoSValve();

		assertTrue(valve.isMonitorModeValid());
		assertTrue(valve.isMonitorModeDefault());
		assertFalse(valve.isMonitorModeMarking());

		valve.setMonitorMode("xyz");
		assertFalse(valve.isMonitorModeValid());
		assertFalse(valve.isMonitorModeDefault());
		assertFalse(valve.isMonitorModeMarking());
		
		valve.setMonitorMode(AntiDoSValve.DEFAULT_MONITOR_MODE);
		assertTrue(valve.isMonitorModeValid());
		assertTrue(valve.isMonitorModeDefault());
		assertFalse(valve.isMonitorModeMarking());
		
		valve.setMonitorMode(AntiDoSValve.MARKING_MONITOR_MODE);
		assertTrue(valve.isMonitorModeValid());
		assertFalse(valve.isMonitorModeDefault());
		assertTrue(valve.isMonitorModeMarking());		
	}

	@Test
	void testAlwaysAllowedIPs() {
		AntiDoSValve valve = new AntiDoSValve();

		assertTrue(valve.isAlwaysAllowedIPsValid());

		valve.setAlwaysAllowedIPs("[a-z....");
		assertFalse(valve.isAlwaysAllowedIPsValid());

		valve.setAlwaysAllowedIPs(null);
		assertTrue(valve.isAlwaysAllowedIPsValid());

		assertFalse(valve.isIPAddressInAlwaysAllowed("127.0.0.1"));

		valve.setAlwaysAllowedIPs("127\\.\\d+\\.\\d+\\.\\d+");
		assertTrue(valve.isAlwaysAllowedIPsValid());

		assertTrue(valve.isIPAddressInAlwaysAllowed("127.0.0.1"));
		assertTrue(valve.isIPAddressInAlwaysAllowed("127.210.110.132"));
		assertFalse(valve.isIPAddressInAlwaysAllowed("127..0.1"));
		assertFalse(valve.isIPAddressInAlwaysAllowed("127.0.1"));
		assertFalse(valve.isIPAddressInAlwaysAllowed("129.70.12.1"));

		valve.setAlwaysAllowedIPs("129\\.70\\.\\d+\\.\\d+");
		assertTrue(valve.isAlwaysAllowedIPsValid());

		assertFalse(valve.isIPAddressInAlwaysAllowed("127.0.0.1"));
		assertFalse(valve.isIPAddressInAlwaysAllowed("127.210.110.132"));
		assertTrue(valve.isIPAddressInAlwaysAllowed("129.70.12.1"));
	}

	@Test
	void testAlwaysForbiddenIPs() {
		AntiDoSValve valve = new AntiDoSValve();

		assertTrue(valve.isAlwaysForbiddenIPsValid());

		valve.setAlwaysForbiddenIPs("[a-z....");
		assertFalse(valve.isAlwaysForbiddenIPsValid());

		valve.setAlwaysForbiddenIPs(null);
		assertTrue(valve.isAlwaysForbiddenIPsValid());

		assertFalse(valve.isIPAddressInAlwaysForbidden("127.0.0.1"));

		valve.setAlwaysForbiddenIPs("127\\.\\d+\\.\\d+\\.\\d+");
		assertTrue(valve.isAlwaysForbiddenIPsValid());

		assertTrue(valve.isIPAddressInAlwaysForbidden("127.0.0.1"));
		assertTrue(valve.isIPAddressInAlwaysForbidden("127.210.110.132"));
		assertFalse(valve.isIPAddressInAlwaysForbidden("127..0.1"));
		assertFalse(valve.isIPAddressInAlwaysForbidden("127.0.1"));
		assertFalse(valve.isIPAddressInAlwaysForbidden("129.70.12.1"));

		valve.setAlwaysForbiddenIPs("129\\.70\\.\\d+\\.\\d+");
		assertTrue(valve.isAlwaysForbiddenIPsValid());

		assertFalse(valve.isIPAddressInAlwaysForbidden("127.0.0.1"));
		assertFalse(valve.isIPAddressInAlwaysForbidden("127.210.110.132"));
		assertTrue(valve.isIPAddressInAlwaysForbidden("129.70.12.1"));
	}

	@Test
	void testAlwaysAllowedIPsArePrefered() {
		AntiDoSValve valve = new AntiDoSValve();

		assertTrue(valve.isRequestAllowed("127.0.0.1", "/xyz"));

		valve.setAlwaysForbiddenIPs("127\\.\\d+\\.\\d+\\.\\d+");
		assertTrue(valve.isIPAddressInAlwaysForbidden("127.0.0.1"));

		assertFalse(valve.isRequestAllowed("127.0.0.1", "/xyz"));

		valve.setAlwaysAllowedIPs("127\\.\\d+\\.\\d+\\.\\d+");
		assertTrue(valve.isIPAddressInAlwaysAllowed("127.0.0.1"));

		assertFalse(valve.isRequestAllowed("127.0.0.1", "/xyz"));

	}

	@Test
	void testRelevantPaths() {
		AntiDoSValve valve = new AntiDoSValve();

		assertTrue(valve.isRelevantPathsValid());

		valve.setRelevantPaths("[a-z....");
		assertFalse(valve.isRelevantPathsValid());

		valve.setRelevantPaths(null);
		assertTrue(valve.isRelevantPathsValid());

		assertFalse(valve.isRequestURIInRelevantPaths("/path1/p.html"));

		valve.setRelevantPaths("/path1");
		assertTrue(valve.isRelevantPathsValid());

		assertTrue(valve.isRequestURIInRelevantPaths("/path1"));
		assertFalse(valve.isRequestURIInRelevantPaths("/path1/p.html"));
		assertFalse(valve.isRequestURIInRelevantPaths("/sub/path1/p.html"));

		valve.setRelevantPaths("/path1.*");
		assertTrue(valve.isRelevantPathsValid());

		assertTrue(valve.isRequestURIInRelevantPaths("/path1"));
		assertTrue(valve.isRequestURIInRelevantPaths("/path1/p.html"));
		assertFalse(valve.isRequestURIInRelevantPaths("/sub/path1/p.html"));

		valve.setRelevantPaths("/path1.*|/sub/.*");
		assertTrue(valve.isRelevantPathsValid());

		assertTrue(valve.isRequestURIInRelevantPaths("/path1"));
		assertTrue(valve.isRequestURIInRelevantPaths("/path1/p.html"));
		assertTrue(valve.isRequestURIInRelevantPaths("/sub/path1/p.html"));

	}

	@Test
	void testNonRelevantPaths() {
		AntiDoSValve valve = new AntiDoSValve();

		assertTrue(valve.isNonRelevantPathsValid());

		valve.setNonRelevantPaths("[a-z....");
		assertFalse(valve.isNonRelevantPathsValid());

		valve.setNonRelevantPaths(null);
		assertTrue(valve.isNonRelevantPathsValid());

		assertFalse(valve.isRequestURIInNonRelevantPaths("/path1/p.html"));

		valve.setNonRelevantPaths("/path1");
		assertTrue(valve.isNonRelevantPathsValid());

		assertTrue(valve.isRequestURIInNonRelevantPaths("/path1"));
		assertFalse(valve.isRequestURIInNonRelevantPaths("/path1/p.html"));
		assertFalse(valve.isRequestURIInNonRelevantPaths("/sub/path1/p.html"));

		valve.setNonRelevantPaths("/path1.*");
		assertTrue(valve.isNonRelevantPathsValid());

		assertTrue(valve.isRequestURIInNonRelevantPaths("/path1"));
		assertTrue(valve.isRequestURIInNonRelevantPaths("/path1/p.html"));
		assertFalse(valve.isRequestURIInNonRelevantPaths("/sub/path1/p.html"));

		valve.setNonRelevantPaths("/path1.*|/sub/.*");
		assertTrue(valve.isNonRelevantPathsValid());

		assertTrue(valve.isRequestURIInNonRelevantPaths("/path1"));
		assertTrue(valve.isRequestURIInNonRelevantPaths("/path1/p.html"));
		assertTrue(valve.isRequestURIInNonRelevantPaths("/sub/path1/p.html"));

	}

	@Test
	void testRelevantAndNonRelevantPaths() {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "REL NON REL TEST");
		valve.setAllowedRequestsPerSlot(3);
		valve.reloadMonitor();

		valve.setRelevantPaths("/path1.*");
		assertTrue(valve.isRequestURIInRelevantPaths("/path1"));
		assertTrue(valve.isRequestURIInRelevantPaths("/path1/m"));
		assertTrue(valve.isRequestURIInRelevantPaths("/path1/n"));
		assertTrue(valve.isRequestURIInRelevantPaths("/path1/o"));

		assertTrue(valve.isRequestAllowed("127.0.0.1", "/path1"));
		assertTrue(valve.isRequestAllowed("127.0.0.1", "/path1"));
		assertTrue(valve.isRequestAllowed("127.0.0.1", "/path1"));
		assertFalse(valve.isRequestAllowed("127.0.0.1", "/path1"));
		assertFalse(valve.isRequestAllowed("127.0.0.1", "/path1/m"));
		assertFalse(valve.isRequestAllowed("127.0.0.1", "/path1/n"));
		assertFalse(valve.isRequestAllowed("127.0.0.1", "/path1/o"));

		valve.setNonRelevantPaths("/path1/n");
		assertFalse(valve.isRequestURIInNonRelevantPaths("/path1"));
		assertFalse(valve.isRequestURIInNonRelevantPaths("/path1/m"));
		assertTrue(valve.isRequestURIInNonRelevantPaths("/path1/n"));
		assertFalse(valve.isRequestURIInNonRelevantPaths("/path1/o"));

		assertFalse(valve.isRequestAllowed("127.0.0.1", "/path1"));
		assertFalse(valve.isRequestAllowed("127.0.0.1", "/path1/m"));
		assertTrue(valve.isRequestAllowed("127.0.0.1", "/path1/n"));
		assertFalse(valve.isRequestAllowed("127.0.0.1", "/path1/o"));

	}

	@Test
	void testIPAddressStatus() throws LifecycleException {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "IP STATUS TEST");
		valve.reloadMonitor();

		String ipUnbekannt = "-";
		assertEquals(ipUnbekannt, valve.getIPAddressStatus("127.0.0.1"));

		valve.setRelevantPaths("/xyz");
		valve.isRequestAllowed("127.0.0.1", "/xyz");

		String ipStatus = valve.getIPAddressStatus("127.0.0.1");
		assertNotNull(ipStatus);
		assertFalse(ipUnbekannt.equals(ipStatus));
	}

	@Test
	void testBlocking() throws LifecycleException {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "BLOCK TEST");
		valve.setAllowedRequestsPerSlot(3);
		valve.reloadMonitor();

		valve.setRelevantPaths("/xyz");

		assertTrue(valve.isRequestAllowed("127.0.0.1", "/xyz"));
		assertTrue(valve.isRequestAllowed("127.0.0.1", "/xyz"));
		assertTrue(valve.isRequestAllowed("127.0.0.1", "/xyz"));
		assertFalse(valve.isRequestAllowed("127.0.0.1", "/xyz"));

		assertTrue(valve.isRequestAllowed("127.0.0.2", "/xyz"));
		assertTrue(valve.isRequestAllowed("127.0.0.2", "/xyz"));
		assertTrue(valve.isRequestAllowed("127.0.0.2", "/xyz"));
		assertFalse(valve.isRequestAllowed("127.0.0.2", "/xyz"));
	}

	@Test
	void testReloadAntiDoSMonitor() throws LifecycleException {
		AntiDoSValve valve = new AntiDoSValve();
		assertNotNull(valve.reloadMonitor());

		setValidAntiDoSMonitorconfiguration(valve, "RELOAD TEST");
		assertNull(valve.reloadMonitor());
	}

	@Test
	void testMultiAntiDoSMonitors() throws LifecycleException {
		AntiDoSValve valve1 = new AntiDoSValve();
		assertNotNull(valve1.reloadMonitor());

		AntiDoSValve valve2 = new AntiDoSValve();
		assertNotNull(valve2.reloadMonitor());

		setValidAntiDoSMonitorconfiguration(valve1, "MULTI TEST - Instanz1");
		assertNull(valve1.reloadMonitor());
		assertNotNull(valve2.reloadMonitor());
	}

	@Test
	void testBlockingMulti() throws LifecycleException {
		AntiDoSValve valve1 = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve1, "BLOCK TEST1");
		valve1.setAllowedRequestsPerSlot(3);
		valve1.reloadMonitor();
		valve1.setRelevantPaths("/xyz");

		AntiDoSValve valve2 = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve2, "BLOCK TEST2");
		valve2.setAllowedRequestsPerSlot(4);
		valve2.reloadMonitor();
		valve2.setRelevantPaths("/xyz");

		assertTrue(valve1.isRequestAllowed("127.0.0.1", "/xyz"));
		assertTrue(valve1.isRequestAllowed("127.0.0.1", "/xyz"));
		assertTrue(valve1.isRequestAllowed("127.0.0.1", "/xyz"));
		assertFalse(valve1.isRequestAllowed("127.0.0.1", "/xyz"));

		assertTrue(valve2.isRequestAllowed("127.0.0.1", "/xyz"));
		assertTrue(valve2.isRequestAllowed("127.0.0.1", "/xyz"));
		assertTrue(valve2.isRequestAllowed("127.0.0.1", "/xyz"));
		assertTrue(valve2.isRequestAllowed("127.0.0.1", "/xyz"));
		assertFalse(valve2.isRequestAllowed("127.0.0.1", "/xyz"));

		valve2.reloadMonitor();
		valve2.setRelevantPaths("/xyz2");

		assertTrue(valve1.isRequestAllowed("127.0.0.1", "/xyz2"));
		assertTrue(valve1.isRequestAllowed("127.0.0.1", "/xyz2"));
		assertTrue(valve1.isRequestAllowed("127.0.0.1", "/xyz2"));
		assertTrue(valve1.isRequestAllowed("127.0.0.1", "/xyz2"));

		assertTrue(valve2.isRequestAllowed("127.0.0.1", "/xyz2"));
		assertTrue(valve2.isRequestAllowed("127.0.0.1", "/xyz2"));
		assertTrue(valve2.isRequestAllowed("127.0.0.1", "/xyz2"));
		assertTrue(valve2.isRequestAllowed("127.0.0.1", "/xyz2"));
		assertFalse(valve2.isRequestAllowed("127.0.0.1", "/xyz2"));

	}

	@Test
	void testHttpStatusCode() {
		AntiDoSValve valve = new AntiDoSValve();

		// Default should be 429 (Too Many Requests)
		assertEquals(429, valve.getHttpStatusCode());
		assertEquals(AntiDoSValve.DEFAULT_HTTP_STATUS_CODE, valve.getHttpStatusCode());
		assertTrue(valve.isHttpStatusCodeValid());

		// Legacy behavior: 403 (Forbidden)
		valve.setHttpStatusCode(AntiDoSValve.LEGACY_HTTP_STATUS_CODE);
		assertEquals(403, valve.getHttpStatusCode());
		assertTrue(valve.isHttpStatusCodeValid());

		// Custom status code
		valve.setHttpStatusCode(503);
		assertEquals(503, valve.getHttpStatusCode());
		assertTrue(valve.isHttpStatusCodeValid());

		// Invalid status codes
		valve.setHttpStatusCode(99);
		assertFalse(valve.isHttpStatusCodeValid());

		valve.setHttpStatusCode(600);
		assertFalse(valve.isHttpStatusCodeValid());

		valve.setHttpStatusCode(-1);
		assertFalse(valve.isHttpStatusCodeValid());

		// String setter
		valve.setHttpStatusCode("403");
		assertEquals(403, valve.getHttpStatusCode());
		valve.setHttpStatusCode("");
		assertEquals(AntiDoSValve.DEFAULT_HTTP_STATUS_CODE, valve.getHttpStatusCode());
		valve.setHttpStatusCode("   ");
		assertEquals(AntiDoSValve.DEFAULT_HTTP_STATUS_CODE, valve.getHttpStatusCode());
		valve.setHttpStatusCode((String) null);
		assertEquals(AntiDoSValve.DEFAULT_HTTP_STATUS_CODE, valve.getHttpStatusCode());
	}

	@Test
	void testHttpStatusCodeLifecycleValidation() {
		AntiDoSValve valve = new AntiDoSValve();
		valve.setContainer(new StandardEngine());
		setValidAntiDoSMonitorconfiguration(valve, "STATUS_CODE_VALIDATION_TEST");
		valve.setHttpStatusCode(999);
		assertFalse(valve.isHttpStatusCodeValid());

		LifecycleException thrown = assertThrows(LifecycleException.class, () -> valve.start());
		assertTrue(thrown.getMessage().contains("httpStatusCode is invalid"));
	}

	@Test
	void testMaxBlockedIPCacheSizeConfiguration() {
		AntiDoSValve valve = new AntiDoSValve();
		assertEquals(-1, valve.getMaxBlockedIPCacheSize());

		valve.setMaxBlockedIPCacheSize(500);
		assertEquals(500, valve.getMaxBlockedIPCacheSize());

		setValidAntiDoSMonitorconfiguration(valve, "BLOCKED_CACHE_CONFIG_TEST");
		assertNull(valve.reloadMonitor());
		String status = valve.getMonitorStatus();
		assertNotNull(status);
		assertTrue(status.contains("maxBlockedCountersPerSlot: 500"));

		// When not set (or -1), defaults to maxIPCacheSize (100)
		valve.setMaxBlockedIPCacheSize(-1);
		assertNull(valve.reloadMonitor());
		status = valve.getMonitorStatus();
		assertNotNull(status);
		assertTrue(status.contains("maxBlockedCountersPerSlot: 100"));

		// String setter with valid number, empty string, spaces, and null
		valve.setMaxBlockedIPCacheSize("750");
		assertEquals(750, valve.getMaxBlockedIPCacheSize());

		valve.setMaxBlockedIPCacheSize("");
		assertEquals(-1, valve.getMaxBlockedIPCacheSize());

		valve.setMaxBlockedIPCacheSize("   ");
		assertEquals(-1, valve.getMaxBlockedIPCacheSize());

		valve.setMaxBlockedIPCacheSize((String) null);
		assertEquals(-1, valve.getMaxBlockedIPCacheSize());
	}

	@Test
	void testIpv4SubnetMaskConfiguration() {
		AntiDoSValve valve = new AntiDoSValve();
		assertEquals(32, valve.getIpv4SubnetMask());
		assertTrue(valve.isIpv4SubnetMaskValid());

		valve.setIpv4SubnetMask(24);
		assertEquals(24, valve.getIpv4SubnetMask());
		assertTrue(valve.isIpv4SubnetMaskValid());

		valve.setIpv4SubnetMask("/16");
		assertEquals(16, valve.getIpv4SubnetMask());

		valve.setIpv4SubnetMask("255.255.255.0");
		assertEquals(24, valve.getIpv4SubnetMask());

		valve.setIpv4SubnetMask("32");
		assertEquals(32, valve.getIpv4SubnetMask());

		valve.setIpv4SubnetMask("-1");
		assertEquals(32, valve.getIpv4SubnetMask());

		valve.setIpv4SubnetMask(0);
		assertFalse(valve.isIpv4SubnetMaskValid());

		valve.setIpv4SubnetMask(33);
		assertFalse(valve.isIpv4SubnetMaskValid());

		IllegalArgumentException exInvalid = assertThrows(IllegalArgumentException.class,
				() -> valve.setIpv4SubnetMask("invalid"));
		assertTrue(exInvalid.getMessage().contains("Invalid subnet mask"));

		IllegalArgumentException exNonContig = assertThrows(IllegalArgumentException.class,
				() -> valve.setIpv4SubnetMask("255.255.0.255"));
		assertTrue(exNonContig.getMessage().contains("non-contiguous"));
	}

	@Test
	void testIpv6SubnetMaskConfiguration() {
		AntiDoSValve valve = new AntiDoSValve();
		assertEquals(128, valve.getIpv6SubnetMask());
		assertTrue(valve.isIpv6SubnetMaskValid());

		valve.setIpv6SubnetMask(64);
		assertEquals(64, valve.getIpv6SubnetMask());
		assertTrue(valve.isIpv6SubnetMaskValid());

		valve.setIpv6SubnetMask("/48");
		assertEquals(48, valve.getIpv6SubnetMask());

		valve.setIpv6SubnetMask(0);
		assertFalse(valve.isIpv6SubnetMaskValid());

		valve.setIpv6SubnetMask(129);
		assertFalse(valve.isIpv6SubnetMaskValid());

		IllegalArgumentException exInvalid6 = assertThrows(IllegalArgumentException.class,
				() -> valve.setIpv6SubnetMask("invalid"));
		assertTrue(exInvalid6.getMessage().contains("Invalid subnet mask"));
	}

	@Test
	void testSubnetMaskLifecycleValidation() {
		AntiDoSValve valve = new AntiDoSValve();
		valve.setContainer(new StandardEngine());
		setValidAntiDoSMonitorconfiguration(valve, "SUBNET_LIFECYCLE_TEST");

		valve.setIpv4SubnetMask(35);
		LifecycleException thrown4 = assertThrows(LifecycleException.class, () -> valve.start());
		assertTrue(thrown4.getMessage().contains("ipv4SubnetMask is invalid"));

		valve.setIpv4SubnetMask(24);
		valve.setIpv6SubnetMask(200);
		LifecycleException thrown6 = assertThrows(LifecycleException.class, () -> valve.start());
		assertTrue(thrown6.getMessage().contains("ipv6SubnetMask is invalid"));
	}

	@Test
	void testIpv4SubnetAggregationBlocking() {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "IPV4_SUBNET_TEST");
		valve.setAllowedRequestsPerSlot(2);
		valve.setIpv4SubnetMask(24);
		valve.setRelevantPaths(".*");
		assertNull(valve.reloadMonitor());

		assertEquals("192.168.1.0/24", valve.resolveCounterName("192.168.1.10"));
		assertEquals("192.168.1.0/24", valve.resolveCounterName("192.168.1.250"));

		// 1st request from 192.168.1.10 -> allowed (counter: 1)
		assertTrue(valve.isRequestAllowed("192.168.1.10", "/api"));
		assertFalse(valve.isIPAddressBlocked("192.168.1.10")); // 2nd request from subnet -> allowed (counter: 2)

		// 3rd request from another IP in same /24 -> blocked! (exceeds allowedRequestsPerSlot=2)
		assertFalse(valve.isRequestAllowed("192.168.1.50", "/api"));
		assertTrue(valve.isIPAddressBlocked("192.168.1.99"));

		// Another subnet (192.168.2.x) should not be blocked
		assertTrue(valve.isRequestAllowed("192.168.2.10", "/api"));
	}

	@Test
	void testIpv6SubnetAggregationBlocking() {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "IPV6_SUBNET_TEST");
		valve.setAllowedRequestsPerSlot(2);
		valve.setIpv6SubnetMask(64);
		valve.setRelevantPaths(".*");
		assertNull(valve.reloadMonitor());

		// IPs in same /64
		String ip1 = "2001:db8:abcd:0012:0000:0000:0000:0001";
		String ip2 = "2001:db8:abcd:12::2";
		assertEquals(valve.resolveCounterName(ip1), valve.resolveCounterName(ip2));

		assertTrue(valve.isRequestAllowed(ip1, "/api")); // count 1
		assertFalse(valve.isIPAddressBlocked(ip2)); // count 2
		// 3rd request in same /64 -> blocked!
		assertFalse(valve.isRequestAllowed("2001:db8:abcd:12::99", "/api"));

		// Different /64 -> allowed
		assertTrue(valve.isRequestAllowed("2001:db8:abcd:13::1", "/api"));
	}

	@Test
	void testWhitelistPrecedenceWithSubnetAggregation() {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "WHITELIST_SUBNET_TEST");
		valve.setAllowedRequestsPerSlot(1);
		valve.setIpv4SubnetMask(24);
		valve.setAlwaysAllowedIPs("192\\.168\\.1\\.99");
		valve.setRelevantPaths(".*");
		assertNull(valve.reloadMonitor());

		// Trigger block on 192.168.1.0/24 subnet
		valve.isIPAddressBlocked("192.168.1.1");
		valve.isIPAddressBlocked("192.168.1.2"); // blocked now

		// Normal IP in subnet is blocked
		assertFalse(valve.isRequestAllowed("192.168.1.3", "/api"));

		// Whitelisted IP in same subnet is still allowed
		assertTrue(valve.isRequestAllowed("192.168.1.99", "/api"));
	}

	@Test
	void testServerWideBlockingDisabledByDefault() {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "SERVER_WIDE_DEFAULT_TEST");
		valve.setAllowedRequestsPerSlot(2);
		valve.setRelevantPaths("/login.*");
		assertNull(valve.reloadMonitor());
		assertFalse(valve.isServerWideBlocking());

		// 2 requests allowed on /login
		assertTrue(valve.isRequestAllowed("192.168.1.5", "/login"));
		assertTrue(valve.isRequestAllowed("192.168.1.5", "/login"));
		// 3rd request blocked on /login
		assertFalse(valve.isRequestAllowed("192.168.1.5", "/login"));

		// By default (serverWideBlocking=false), other unmonitored paths remain accessible
		assertTrue(valve.isRequestAllowed("192.168.1.5", "/public/index.html"));
	}

	@Test
	void testServerWideBlockingBlocksUnmonitoredPathsWhenLocked() {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "SERVER_WIDE_BLOCK_TEST");
		valve.setAllowedRequestsPerSlot(2);
		valve.setRelevantPaths("/login.*");
		valve.setServerWideBlocking(true);
		assertNull(valve.reloadMonitor());
		assertTrue(valve.isServerWideBlocking());

		// Block IP on /login
		assertTrue(valve.isRequestAllowed("192.168.1.10", "/login"));
		assertTrue(valve.isRequestAllowed("192.168.1.10", "/login"));
		assertFalse(valve.isRequestAllowed("192.168.1.10", "/login")); // locked

		// Server-wide blocking is active: unmonitored paths are blocked too!
		assertFalse(valve.isRequestAllowed("192.168.1.10", "/public/index.html"));
		assertFalse(valve.isRequestAllowed("192.168.1.10", "/api/data"));

		// Other innocent IP is NOT blocked on any path
		assertTrue(valve.isRequestAllowed("192.168.1.20", "/public/index.html"));
		assertTrue(valve.isRequestAllowed("192.168.1.20", "/login"));
	}

	@Test
	void testServerWideBlockingRespectsNonRelevantPaths() {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "SERVER_WIDE_NON_REL_TEST");
		valve.setAllowedRequestsPerSlot(1);
		valve.setRelevantPaths("/login.*");
		valve.setNonRelevantPaths("/status|/error.*");
		valve.setServerWideBlocking(true);
		assertNull(valve.reloadMonitor());

		// Block IP
		assertTrue(valve.isRequestAllowed("192.168.1.30", "/login"));
		assertFalse(valve.isRequestAllowed("192.168.1.30", "/login")); // locked

		// Regular unmonitored path is blocked:
		assertFalse(valve.isRequestAllowed("192.168.1.30", "/other"));

		// Whitelisted nonRelevantPaths remain accessible even when blocked server-wide:
		assertTrue(valve.isRequestAllowed("192.168.1.30", "/status"));
		assertTrue(valve.isRequestAllowed("192.168.1.30", "/error/429.html"));
	}

	@Test
	void testServerWideBlockingDoesNotIncrementCountersOnUnmonitoredPaths() {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "SERVER_WIDE_NO_COUNT_TEST");
		valve.setAllowedRequestsPerSlot(5);
		valve.setRelevantPaths("/login.*");
		valve.setServerWideBlocking(true);
		assertNull(valve.reloadMonitor());

		AntiDoSMonitor monitor = valve.provideMonitor();
		assertNotNull(monitor);

		long initialRequests = monitor.getTotalrequests();

		// Requests to unmonitored path by innocent IP
		for (int i = 0; i < 10; i++) {
			assertTrue(valve.isRequestAllowed("192.168.1.40", "/public/asset" + i));
		}

		// Total requests in monitor MUST not have increased
		assertEquals(initialRequests, monitor.getTotalrequests());
		assertEquals("-", valve.getIPAddressStatus("192.168.1.40"));
		assertFalse(valve.isIPAddressCurrentlyBlocked("192.168.1.40"));
	}

	@Test
	void testIsIPAddressCurrentlyBlockedValidation() {
		AntiDoSValve valve = new AntiDoSValve();
		IllegalArgumentException exNull = assertThrows(IllegalArgumentException.class,
				() -> valve.isIPAddressCurrentlyBlocked(null));
		assertNotNull(exNull.getMessage());
		IllegalArgumentException exEmpty = assertThrows(IllegalArgumentException.class,
				() -> valve.isIPAddressCurrentlyBlocked(""));
		assertNotNull(exEmpty.getMessage());
	}

	@Test
	void testConcurrentProvideMonitorReturnsConsistentInstance() throws Exception {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "CONCURRENT_PROVIDE_MONITOR_TEST");

		int threadCount = 20;
		java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(threadCount);
		java.util.concurrent.CountDownLatch startLatch = new java.util.concurrent.CountDownLatch(1);
		java.util.concurrent.CountDownLatch doneLatch = new java.util.concurrent.CountDownLatch(threadCount);
		AntiDoSMonitor[] instances = new AntiDoSMonitor[threadCount];

		for (int i = 0; i < threadCount; i++) {
			final int index = i;
			executor.submit(() -> {
				try {
					startLatch.await();
					instances[index] = valve.provideMonitor();
				} catch (InterruptedException ignored) {
				} finally {
					doneLatch.countDown();
				}
			});
		}

		startLatch.countDown();
		assertTrue(doneLatch.await(3, java.util.concurrent.TimeUnit.SECONDS));
		executor.shutdownNow();

		assertNotNull(instances[0]);
		for (int i = 1; i < threadCount; i++) {
			assertSame(instances[0], instances[i], "All threads must receive the exact same monitor instance");
		}
	}

	@Test
	void testMaxBlockLogsPerSecondConfiguration() {
		AntiDoSValve valve = new AntiDoSValve();
		assertEquals(AntiDoSLogThrottler.DEFAULT_MAX_LOGS_PER_SECOND, valve.getMaxBlockLogsPerSecond());

		valve.setMaxBlockLogsPerSecond(5);
		assertEquals(5, valve.getMaxBlockLogsPerSecond());

		// Provide monitor and verify delegation
		setValidAntiDoSMonitorconfiguration(valve, "LOG_THROTTLER_VALVE_TEST");
		AntiDoSMonitor monitor = valve.provideMonitor();
		assertNotNull(monitor);
		assertEquals(5, monitor.getMaxBlockLogsPerSecond());

		// Change after monitor exists
		valve.setMaxBlockLogsPerSecond(-1);
		assertEquals(-1, valve.getMaxBlockLogsPerSecond());
		assertEquals(-1, monitor.getMaxBlockLogsPerSecond());

		// Reload monitor preserves configured setting
		valve.reloadMonitor();
		AntiDoSMonitor reloaded = valve.provideMonitor();
		assertEquals(-1, reloaded.getMaxBlockLogsPerSecond());
	}

	@Test
	void testProvideRetryAfterSeconds() {
		AntiDoSValve valve = new AntiDoSValve();
		valve.setSlotLength(10);
		assertEquals(10, valve.getSlotLength());

		// At start of slot (t = 0s)
		assertEquals(10, valve.provideRetryAfterSeconds(0L));

		// 1 second in (t = 1s -> 9s remaining)
		assertEquals(9, valve.provideRetryAfterSeconds(1000L));

		// Mid-slot with fractional second (t = 5.5s -> 4.5s remaining, ceil to 5s)
		assertEquals(5, valve.provideRetryAfterSeconds(5500L));

		// 9 seconds in (t = 9s -> 1s remaining)
		assertEquals(1, valve.provideRetryAfterSeconds(9000L));

		// 9.999 seconds in (t = 9.999s -> 1ms remaining, ceil to 1s minimum)
		assertEquals(1, valve.provideRetryAfterSeconds(9999L));

		// Slot roll at t = 10s -> fresh 10s slot
		assertEquals(10, valve.provideRetryAfterSeconds(10000L));

		// 1ms into new slot at t = 10.001s -> ceil to 10s
		assertEquals(10, valve.provideRetryAfterSeconds(10001L));

		// Unconfigured fallback (default to 30s)
		AntiDoSValve unconfigured = new AntiDoSValve();
		assertEquals(30, unconfigured.provideRetryAfterSeconds(0L));
		assertEquals(20, unconfigured.provideRetryAfterSeconds(10000L));
	}

	private static void setValidAntiDoSMonitorconfiguration(AntiDoSValve valve, String monitorName) {
		valve.setContainer(new StandardEngine());
		valve.setMonitorName(monitorName);
		valve.setNumberOfSlots(10);
		valve.setSlotLength(30);
		valve.setShareOfRetainedFormerRequests("1");
		valve.setAllowedRequestsPerSlot(50);
		valve.setMaxIPCacheSize(100);
	}

	@Test
	void testStatusUriConfig() {
		AntiDoSValve valve = new AntiDoSValve();
		assertNull(valve.getStatusUri());

		valve.setStatusUri("antidos-status");
		assertEquals("/antidos-status", valve.getStatusUri());

		valve.setStatusUri("/custom/status");
		assertEquals("/custom/status", valve.getStatusUri());

		valve.setStatusUri("  ");
		assertNull(valve.getStatusUri());

		valve.setStatusUri(null);
		assertNull(valve.getStatusUri());
	}

	@Test
	void testStatusAllowedIPsConfig() throws LifecycleException {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "STATUS_IP_TEST");

		assertTrue(valve.isStatusAllowedIPsValid());
		assertNull(valve.getStatusAllowedIPs());

		valve.setStatusAllowedIPs("127\\.0\\.0\\.1|::1|10\\..*");
		assertTrue(valve.isStatusAllowedIPsValid());
		assertEquals("127\\.0\\.0\\.1|::1|10\\..*", valve.getStatusAllowedIPs());

		// Test invalid regex
		valve.setStatusAllowedIPs("[invalid-regex");
		assertFalse(valve.isStatusAllowedIPsValid());

		// LifecycleException thrown during start
		LifecycleException thrown = assertThrows(LifecycleException.class, () -> valve.init());
		assertTrue(thrown.getMessage().contains("statusAllowedIPs is invalid"));

		// Reset to null
		valve.setStatusAllowedIPs(null);
		assertTrue(valve.isStatusAllowedIPsValid());
	}

	@Test
	void testStatusPasswordAndRandomTokenGeneration() {
		AntiDoSValve valve = new AntiDoSValve();
		assertNull(valve.getStatusPassword());

		// When configured explicitly
		valve.setStatusPassword("superSecretAdmin123");
		assertEquals("superSecretAdmin123", valve.getStatusPassword());
		assertEquals("superSecretAdmin123", valve.getEffectiveStatusPassword());

		// When unconfigured, falls back to generated random HEX token
		valve.setStatusPassword(null);
		AntiDoSValve.resetGeneratedStatusToken();
		String token1 = valve.getEffectiveStatusPassword();
		assertNotNull(token1);
		assertTrue(token1.length() >= 16 && token1.length() <= 20,
				"Token length should be between 16 and 20, was: " + token1.length());
		assertTrue(token1.matches("^[0-9a-f]+$"), "Token must consist strictly of hex digits (0-9a-f): " + token1);

		// Token is shared and idempotent across calls
		String token2 = valve.getEffectiveStatusPassword();
		assertEquals(token1, token2);
		assertEquals(token1, AntiDoSValve.getOrGenerateStatusToken());

		// Another valve gets the exact same shared token
		AntiDoSValve valve2 = new AntiDoSValve();
		assertEquals(token1, valve2.getEffectiveStatusPassword());

		// After reset, a fresh token is generated
		AntiDoSValve.resetGeneratedStatusToken();
		String token3 = valve.getEffectiveStatusPassword();
		assertNotNull(token3);
		assertTrue(token3.matches("^[0-9a-f]+$"));
	}

	@Test
	void testActiveValvesLifecycle() throws LifecycleException {
		AntiDoSValve.clearActiveValves();
		AntiDoSValve valve1 = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve1, "LIFECYCLE_VALVE_1");
		valve1.setStatusUri("/antidos-status");

		AntiDoSValve valve2 = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve2, "LIFECYCLE_VALVE_2");

		valve1.start();
		assertTrue(AntiDoSValve.getActiveValves().contains(valve1));
		assertEquals(1, AntiDoSValve.getActiveValves().size());

		valve2.start();
		assertTrue(AntiDoSValve.getActiveValves().contains(valve2));
		assertEquals(2, AntiDoSValve.getActiveValves().size());

		valve1.stop();
		assertFalse(AntiDoSValve.getActiveValves().contains(valve1));
		assertTrue(AntiDoSValve.getActiveValves().contains(valve2));
		assertEquals(1, AntiDoSValve.getActiveValves().size());

		valve2.stop();
		assertFalse(AntiDoSValve.getActiveValves().contains(valve2));
		assertTrue(AntiDoSValve.getActiveValves().isEmpty());
	}

	@Test
	void testBuildStatusHtmlAndJson() throws Exception {
		AntiDoSValve.clearActiveValves();
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "DASHBOARD_TEST");
		valve.setRelevantPaths("/api/.*");
		valve.setNonRelevantPaths("/api/public");
		valve.setIpv4SubnetMask(24);
		valve.start();

		// HTML Generation
		String html = valve.buildStatusHtml(null);
		assertNotNull(html);
		assertTrue(html.contains("<!DOCTYPE html>"));
		assertTrue(html.contains("Anti-DoS Valve Monitor"));
		assertTrue(html.contains("DASHBOARD_TEST"));
		assertTrue(html.contains("/api/.*"));
		assertTrue(html.contains("/api/public"));
		assertTrue(html.contains("MODE: BLOCKING"));
		assertTrue(html.contains("/24"));
		assertTrue(html.contains("ui-monospace"));

		// Filter matching valve
		String htmlFiltered = valve.buildStatusHtml("DASHBOARD_TEST");
		assertTrue(htmlFiltered.contains("DASHBOARD_TEST"));

		// Filter non-existent valve
		String htmlNotFound = valve.buildStatusHtml("UNKNOWN_VALVE");
		assertTrue(htmlNotFound.contains("No valves matched the filter: UNKNOWN_VALVE"));

		// HTML Escaping test
		AntiDoSValve xssValve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(xssValve, "<script>alert('xss')</script>");
		xssValve.start();
		String xssHtml = xssValve.buildStatusHtml("<script>alert('xss')</script>");
		assertFalse(xssHtml.contains("<script>alert('xss')</script>"));
		assertTrue(xssHtml.contains("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"));
		xssValve.stop();

		// JSON Generation
		String json = valve.buildStatusJson(null);
		assertNotNull(json);
		assertTrue(json.contains("\"serverTime\":"));
		assertTrue(json.contains("\"totalActiveValves\":"));
		assertTrue(json.contains("\"monitorName\": \"DASHBOARD_TEST\""));
		assertTrue(json.contains("\"relevantPaths\": \"/api/.*\""));
		assertTrue(json.contains("\"allowedRequestsPerSlot\": 50"));
		assertTrue(json.contains("\"ipv4SubnetMask\": 24"));

		valve.stop();
	}

	@Test
	void testBuildDashboardUrl() {
		assertEquals("?", AntiDoSValve.buildDashboardUrl(null, null, null, null));
		assertEquals("?token=myToken", AntiDoSValve.buildDashboardUrl("myToken", null, null, null));
		assertEquals("?token=myToken&amp;valve=myValve", AntiDoSValve.buildDashboardUrl("myToken", "myValve", null, null));
		assertEquals("?token=myToken&amp;valve=myValve&amp;view=details", AntiDoSValve.buildDashboardUrl("myToken", "myValve", "details", null));
		assertEquals("?token=myToken&amp;valve=myValve&amp;view=details&amp;format=json", AntiDoSValve.buildDashboardUrl("myToken", "myValve", "details", "json"));
		// URL encoding check for special characters
		assertEquals("?token=pass%2Bword%261%3D2&amp;valve=Valve%231", AntiDoSValve.buildDashboardUrl("pass+word&1=2", "Valve#1", null, null));
		// Non-HTML separator check
		assertEquals("?token=myToken&valve=myValve", AntiDoSValve.buildDashboardUrl("myToken", "myValve", null, null, false));
	}

	@Test
	void testStatusRelevantPathsDisplayBugFix() throws Exception {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "RELEVANT_PATHS_TEST");
		valve.setRelevantPaths(null); // Explicitly unconfigured
		valve.start();

		String html = valve.buildStatusHtml("RELEVANT_PATHS_TEST");
		assertTrue(html.contains("none (no requests monitored)"));
		assertFalse(html.contains("all requests"));

		String htmlDetails = valve.buildStatusHtmlDetails("RELEVANT_PATHS_TEST", null);
		assertTrue(htmlDetails.contains("none (no requests monitored)"));
		assertFalse(htmlDetails.contains("all requests"));

		valve.stop();
	}

	@Test
	void testStatusDetailsHtmlAndJson() throws Exception {
		AntiDoSValve.clearActiveValves();
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "DETAILS_TEST");
		valve.setRelevantPaths("/api/.*");
		valve.setAllowedRequestsPerSlot(5);
		valve.start();

		// Generate some requests:
		// 10.0.0.1 -> 2 requests (active)
		valve.isIPAddressBlocked("10.0.0.1");
		valve.isIPAddressBlocked("10.0.0.1");

		// 10.0.0.2 -> 6 requests (exceeds limit 5 -> blocked)
		for (int i = 0; i < 6; i++) {
			valve.isIPAddressBlocked("10.0.0.2");
		}

		String token = "secretToken123";

		// HTML Details view
		String detailsHtml = valve.buildStatusHtmlDetails("DETAILS_TEST", token);
		assertNotNull(detailsHtml);
		assertTrue(detailsHtml.contains("AntiDoSValve [DETAILS_TEST] Details"));
		assertTrue(detailsHtml.contains("Slot Ring Buffer Timeline"));
		assertTrue(detailsHtml.contains("CURRENT"));
		assertTrue(detailsHtml.contains("Blocked Clients (Current Slot)"));
		assertTrue(detailsHtml.contains("Top Active Clients (Current Slot)"));
		assertTrue(detailsHtml.contains("10.0.0.2"));
		assertTrue(detailsHtml.contains("10.0.0.1"));
		assertTrue(detailsHtml.contains("BLOCKED"));

		// Check links carry token
		assertTrue(detailsHtml.contains("?token=" + token));
		assertTrue(detailsHtml.contains("Back to Overview"));
		assertTrue(detailsHtml.contains("Refresh"));
		assertTrue(detailsHtml.contains("JSON Details"));

		// JSON Details view
		String detailsJson = valve.buildStatusJsonDetails("DETAILS_TEST");
		assertNotNull(detailsJson);
		assertTrue(detailsJson.contains("\"monitorName\": \"DETAILS_TEST\""));
		assertTrue(detailsJson.contains("\"slots\": ["));
		assertTrue(detailsJson.contains("\"blockedClients\": ["));
		assertTrue(detailsJson.contains("\"topActiveClients\": ["));
		assertTrue(detailsJson.contains("\"key\": \"10.0.0.2\""));
		assertTrue(detailsJson.contains("\"key\": \"10.0.0.1\""));

		// Unknown valve error handling
		String notFoundHtml = valve.buildStatusHtmlDetails("NON_EXISTENT", token);
		assertTrue(notFoundHtml.contains("Valve not found: NON_EXISTENT"));
		assertTrue(notFoundHtml.contains("href=\"?token=" + token + "\""));

		String notFoundJson = valve.buildStatusJsonDetails("NON_EXISTENT");
		assertTrue(notFoundJson.contains("Valve not found: NON_EXISTENT"));

		valve.stop();
	}

	@Test
	void testStatusRequestTokenPropagationInLinks() throws Exception {
		AntiDoSValve.clearActiveValves();
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "PROPAGATE_TEST");
		valve.setStatusUri("/antidos-status");
		valve.setStatusPassword("mySuperSecretToken");
		valve.start();

		// Overview request via token parameter
		TestRequest reqOverview = new TestRequest("/antidos-status", "127.0.0.1");
		reqOverview.setParameter("token", "mySuperSecretToken");
		TestResponse respOverview = new TestResponse();
		valve.handleStatusRequest(reqOverview, respOverview, "127.0.0.1");
		assertEquals(-1, respOverview.getErrorCode());
		String overviewHtml = respOverview.getOutput();
		assertTrue(overviewHtml.contains("token=mySuperSecretToken"));
		assertTrue(overviewHtml.contains("view=details"));
		assertTrue(overviewHtml.contains("format=json"));

		// Details request with view=details
		TestRequest reqDetails = new TestRequest("/antidos-status", "127.0.0.1");
		reqDetails.setParameter("token", "mySuperSecretToken");
		reqDetails.setParameter("view", "details");
		reqDetails.setParameter("valve", "PROPAGATE_TEST");
		TestResponse respDetails = new TestResponse();
		valve.handleStatusRequest(reqDetails, respDetails, "127.0.0.1");
		assertEquals(-1, respDetails.getErrorCode());
		String detailsHtml = respDetails.getOutput();
		assertTrue(detailsHtml.contains("AntiDoSValve [PROPAGATE_TEST] Details"));
		assertTrue(detailsHtml.contains("token=mySuperSecretToken"));

		// Details request with details=true parameter
		TestRequest reqDetailsBool = new TestRequest("/antidos-status", "127.0.0.1");
		reqDetailsBool.setParameter("token", "mySuperSecretToken");
		reqDetailsBool.setParameter("details", "true");
		reqDetailsBool.setParameter("valve", "PROPAGATE_TEST");
		TestResponse respDetailsBool = new TestResponse();
		valve.handleStatusRequest(reqDetailsBool, respDetailsBool, "127.0.0.1");
		assertEquals(-1, respDetailsBool.getErrorCode());
		assertTrue(respDetailsBool.getOutput().contains("AntiDoSValve [PROPAGATE_TEST] Details"));

		valve.stop();
	}

	@Test
	void testStatusRequestIPWhitelist() throws Exception {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "IP_WHITELIST_TEST");
		valve.setStatusUri("/antidos-status");
		valve.setStatusAllowedIPs("127\\.0\\.0\\.1");
		valve.setStatusPassword("secret123");
		valve.start();

		// Unauthorized IP -> 404
		TestRequest reqForbidden = new TestRequest("/antidos-status", "192.168.1.50");
		reqForbidden.setParameter("token", "secret123");
		TestResponse respForbidden = new TestResponse();
		valve.handleStatusRequest(reqForbidden, respForbidden, "192.168.1.50");
		assertEquals(404, respForbidden.getErrorCode());

		// Authorized IP with valid token -> 200
		TestRequest reqAllowed = new TestRequest("/antidos-status", "127.0.0.1");
		reqAllowed.setParameter("token", "secret123");
		TestResponse respAllowed = new TestResponse();
		valve.handleStatusRequest(reqAllowed, respAllowed, "127.0.0.1");
		assertEquals(-1, respAllowed.getErrorCode()); // no error sent
		assertTrue(respAllowed.getOutput().contains("Anti-DoS Valve Monitor"));

		valve.stop();
	}

	@Test
	void testStatusRequestAsymmetricRateLimiting() throws Exception {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "RATE_LIMIT_STATUS_TEST");
		valve.setStatusUri("/antidos-status");
		valve.setStatusPassword("myAdminToken");
		valve.setAllowedRequestsPerSlot(2); // threshold = 2 requests
		valve.setSlotLength(60);
		valve.start();

		String attackerIp = "198.51.100.25";

		// Attempt 1 with WRONG token: 401 Unauthorized, recorded in monitor
		TestRequest req1 = new TestRequest("/antidos-status", attackerIp);
		req1.setParameter("token", "wrongPassword");
		TestResponse resp1 = new TestResponse();
		valve.handleStatusRequest(req1, resp1, attackerIp);
		assertEquals(401, resp1.getErrorCode());
		assertFalse(valve.isIPAddressCurrentlyBlocked(attackerIp));

		// Attempt 2 with WRONG token: 401 Unauthorized, reaches limit of 2 requests
		TestRequest req2 = new TestRequest("/antidos-status", attackerIp);
		req2.setParameter("token", "wrongPassword");
		TestResponse resp2 = new TestResponse();
		valve.handleStatusRequest(req2, resp2, attackerIp);
		assertEquals(401, resp2.getErrorCode());

		// Attempt 3 with WRONG token: 3rd request exceeds limit -> IP is now blocked!
		TestRequest req3 = new TestRequest("/antidos-status", attackerIp);
		req3.setParameter("token", "wrongPassword");
		TestResponse resp3 = new TestResponse();
		valve.handleStatusRequest(req3, resp3, attackerIp);
		assertEquals(401, resp3.getErrorCode());
		assertTrue(valve.isIPAddressCurrentlyBlocked(attackerIp));

		// Next request with WRONG token from blocked IP: rejected directly with 429 Too Many Requests
		TestRequest reqBlockedWrong = new TestRequest("/antidos-status", attackerIp);
		reqBlockedWrong.setParameter("token", "wrongPasswordAgain");
		TestResponse respBlockedWrong = new TestResponse();
		valve.handleStatusRequest(reqBlockedWrong, respBlockedWrong, attackerIp);
		assertEquals(429, respBlockedWrong.getErrorCode());

		// But an Administrator with the VALID token can access the dashboard EVEN IF their IP is currently blocked (e.g. while testing application endpoints):
		TestRequest reqAdminBlockedIp = new TestRequest("/antidos-status", attackerIp);
		reqAdminBlockedIp.setParameter("token", "myAdminToken");
		TestResponse respAdminBlockedIp = new TestResponse();
		valve.handleStatusRequest(reqAdminBlockedIp, respAdminBlockedIp, attackerIp);
		assertEquals(-1, respAdminBlockedIp.getErrorCode()); // 200 OK
		assertTrue(respAdminBlockedIp.getOutput().contains("RATE_LIMIT_STATUS_TEST"));

		// Legitimate Admin from clean IP: requests are NOT counted against the rate limit
		String adminIp = "192.168.1.10";
		for (int i = 0; i < 5; i++) {
			TestRequest reqAdmin = new TestRequest("/antidos-status", adminIp);
			reqAdmin.setParameter("token", "myAdminToken");
			TestResponse respAdmin = new TestResponse();
			valve.handleStatusRequest(reqAdmin, respAdmin, adminIp);
			assertEquals(-1, respAdmin.getErrorCode()); // 200 OK (no error)
		}
		// Admin is NOT blocked despite 5 requests (well above limit of 2)
		assertFalse(valve.isIPAddressCurrentlyBlocked(adminIp));

		valve.stop();
	}

	@Test
	void testStatusRequestAuthenticationMethods() throws Exception {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "AUTH_METHODS_TEST");
		valve.setStatusUri("/antidos-status");
		valve.setStatusPassword("validKey");
		valve.start();

		String ip = "10.0.0.1";

		// 1. Via ?token=... (Accepted)
		TestRequest reqToken = new TestRequest("/antidos-status", ip);
		reqToken.setParameter("token", "validKey");
		TestResponse respToken = new TestResponse();
		valve.handleStatusRequest(reqToken, respToken, ip);
		assertEquals(-1, respToken.getErrorCode());

		// 2. Via Authorization: Bearer <token> (Accepted)
		TestRequest reqBearer = new TestRequest("/antidos-status", ip);
		reqBearer.setHeader("Authorization", "Bearer validKey");
		TestResponse respBearer = new TestResponse();
		valve.handleStatusRequest(reqBearer, respBearer, ip);
		assertEquals(-1, respBearer.getErrorCode());

		// 3. Alternative names like ?pwd= are NOT accepted (401)
		TestRequest reqPwd = new TestRequest("/antidos-status", ip);
		reqPwd.setParameter("pwd", "validKey");
		TestResponse respPwd = new TestResponse();
		valve.handleStatusRequest(reqPwd, respPwd, ip);
		assertEquals(401, respPwd.getErrorCode());

		// 4. Custom header X-AntiDoS-Token is NOT accepted (401)
		TestRequest reqHeader = new TestRequest("/antidos-status", ip);
		reqHeader.setHeader("X-AntiDoS-Token", "validKey");
		TestResponse respHeader = new TestResponse();
		valve.handleStatusRequest(reqHeader, respHeader, ip);
		assertEquals(401, respHeader.getErrorCode());

		// 5. Completely missing token (no parameter, no Authorization header) -> 401
		TestRequest reqNoToken = new TestRequest("/antidos-status", ip);
		TestResponse respNoToken = new TestResponse();
		valve.handleStatusRequest(reqNoToken, respNoToken, ip);
		assertEquals(401, respNoToken.getErrorCode());

		// 6. Invalid token via Authorization: Bearer <wrongToken> -> 401
		TestRequest reqWrongBearer = new TestRequest("/antidos-status", ip);
		reqWrongBearer.setHeader("Authorization", "Bearer wrongBearerToken");
		TestResponse respWrongBearer = new TestResponse();
		valve.handleStatusRequest(reqWrongBearer, respWrongBearer, ip);
		assertEquals(401, respWrongBearer.getErrorCode());

		// JSON format via ?format=json
		TestRequest reqJson = new TestRequest("/antidos-status", ip);
		reqJson.setParameter("token", "validKey");
		reqJson.setParameter("format", "json");
		TestResponse respJson = new TestResponse();
		valve.handleStatusRequest(reqJson, respJson, ip);
		assertEquals(-1, respJson.getErrorCode());
		assertTrue(respJson.getOutput().contains("\"totalActiveValves\":"));

		valve.stop();
	}

	@Test
	void testInvokeInterceptsStatusUri() throws Exception {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "INVOKE_INTERCEPT_TEST");
		valve.setStatusUri("/my-status");
		valve.setStatusPassword("testSecret");
		valve.start();

		TestRequest req = new TestRequest("/my-status", "127.0.0.1");
		req.setParameter("token", "testSecret");
		TestResponse resp = new TestResponse();

		valve.invoke(req, resp);
		assertEquals(-1, resp.getErrorCode());
		assertTrue(resp.getOutput().contains("Anti-DoS Valve Monitor"));

		valve.stop();
	}

	@Test
	void testBlockedIpCanStillAccessStatusWithValidToken() throws Exception {
		AntiDoSValve valve = new AntiDoSValve();
		setValidAntiDoSMonitorconfiguration(valve, "BLOCKED_IP_STATUS_TEST");
		valve.setStatusUri("/antidos-status");
		valve.setStatusPassword("secureAdminPass");
		valve.setRelevantPaths("/valvetest.*");
		valve.setAllowedRequestsPerSlot(2);
		valve.setSlotLength(60);
		valve.start();

		String clientIp = "192.168.1.55";

		// 1. Call /valvetest until IP is blocked
		assertTrue(valve.isRequestAllowed(clientIp, "/valvetest")); // 1
		assertTrue(valve.isRequestAllowed(clientIp, "/valvetest")); // 2
		assertFalse(valve.isRequestAllowed(clientIp, "/valvetest")); // 3 -> blocked!
		assertTrue(valve.isIPAddressCurrentlyBlocked(clientIp));

		// 2. Now call /antidos-status with VALID token: Must SUCCEED so admin can inspect the valve
		TestRequest statusReqValid = new TestRequest("/antidos-status", clientIp);
		statusReqValid.setParameter("token", "secureAdminPass");
		TestResponse statusRespValid = new TestResponse();
		valve.invoke(statusReqValid, statusRespValid);
		assertEquals(-1, statusRespValid.getErrorCode()); // 200 OK!
		assertTrue(statusRespValid.getOutput().contains("Anti-DoS Valve Monitor"));
		assertTrue(statusRespValid.getOutput().contains("BLOCKED_IP_STATUS_TEST"));
		assertEquals(1, valve.provideMonitor().getCurrentBlockedCounterCount());

		// 3. Call /antidos-status with WRONG token: Must be rejected with 429 because IP is blocked
		TestRequest statusReqWrong = new TestRequest("/antidos-status", clientIp);
		statusReqWrong.setParameter("token", "wrongToken");
		TestResponse statusRespWrong = new TestResponse();
		valve.invoke(statusReqWrong, statusRespWrong);
		assertEquals(429, statusRespWrong.getErrorCode());

		valve.stop();
	}

	private static class TestRequest extends Request {
		private final String testUri;
		private final String testRemoteAddr;
		private final Map<String, String> params = new HashMap<>();
		private final Map<String, String> headers = new HashMap<>();

		TestRequest(String uri, String remoteAddr) {
			super(new Connector());
			this.testUri = uri;
			this.testRemoteAddr = remoteAddr;
		}

		@Override
		public String getRequestURI() {
			return testUri;
		}

		@Override
		public String getRemoteAddr() {
			return testRemoteAddr;
		}

		@Override
		public String getParameter(String name) {
			return params.get(name);
		}

		void setParameter(String name, String value) {
			params.put(name, value);
		}

		@Override
		public String getHeader(String name) {
			return headers.get(name);
		}

		void setHeader(String name, String value) {
			headers.put(name, value);
		}
	}

	private static class TestResponse extends Response {
		private int errorCode = -1;
		private final StringWriter sw = new StringWriter();
		private final PrintWriter pw = new PrintWriter(sw);

		TestResponse() {
			super();
		}

		@Override
		public void sendError(int status) {
			this.errorCode = status;
		}

		@Override
		public void setContentType(String type) {
		}

		@Override
		public void setCharacterEncoding(String charset) {
		}

		@Override
		public void setHeader(String name, String value) {
		}

		@Override
		public PrintWriter getWriter() {
			return pw;
		}

		String getOutput() {
			pw.flush();
			return sw.toString();
		}

		int getErrorCode() {
			return errorCode;
		}
	}
}
