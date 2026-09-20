package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.catalina.LifecycleException;
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

	private static void setValidAntiDoSMonitorconfiguration(AntiDoSValve valve, String monitorName) {
		valve.setMonitorName(monitorName);
		valve.setNumberOfSlots(10);
		valve.setSlotLength(30);
		valve.setShareOfRetainedFormerRequests("1");
		valve.setAllowedRequestsPerSlot(50);
		valve.setMaxIPCacheSize(100);
	}
}
