package org.henbru.antidos;

import org.apache.catalina.LifecycleException;

import junit.framework.TestCase;

/**
 * Unit test for the valve implementation
 */
public class AntiDoSValveTest extends TestCase {

	public void testMonitorMode() {
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

	public void testAlwaysAllowedIPs() {
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

	public void testAlwaysForbiddenIPs() {
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

	public void testAlwaysAllowedIPsArePrefered() {
		AntiDoSValve valve = new AntiDoSValve();

		assertTrue(valve.isRequestAllowed("127.0.0.1", "/xyz"));

		valve.setAlwaysForbiddenIPs("127\\.\\d+\\.\\d+\\.\\d+");
		assertTrue(valve.isIPAddressInAlwaysForbidden("127.0.0.1"));

		assertFalse(valve.isRequestAllowed("127.0.0.1", "/xyz"));

		valve.setAlwaysAllowedIPs("127\\.\\d+\\.\\d+\\.\\d+");
		assertTrue(valve.isIPAddressInAlwaysAllowed("127.0.0.1"));

		assertFalse(valve.isRequestAllowed("127.0.0.1", "/xyz"));

	}

	public void testRelevantPaths() {
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

	public void testIPAddressStatus() throws LifecycleException {
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

	public void testBlocking() throws LifecycleException {
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

	public void testReloadAntiDoSMonitor() throws LifecycleException {
		AntiDoSValve valve = new AntiDoSValve();
		assertNotNull(valve.reloadMonitor());

		setValidAntiDoSMonitorconfiguration(valve, "RELOAD TEST");
		assertNull(valve.reloadMonitor());
	}

	public void testMultiAntiDoSMonitors() throws LifecycleException {
		AntiDoSValve valve1 = new AntiDoSValve();
		assertNotNull(valve1.reloadMonitor());

		AntiDoSValve valve2 = new AntiDoSValve();
		assertNotNull(valve2.reloadMonitor());

		setValidAntiDoSMonitorconfiguration(valve1, "MULTI TEST - Instanz1");
		assertNull(valve1.reloadMonitor());
		assertNotNull(valve2.reloadMonitor());
	}

	public void testBlockingMulti() throws LifecycleException {
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

	private static void setValidAntiDoSMonitorconfiguration(AntiDoSValve valve, String monitorName) {
		valve.setMonitorName(monitorName);
		valve.setNumberOfSlots(10);
		valve.setSlotLength(30);
		valve.setShareOfRetainedFormerRequests("1");
		valve.setAllowedRequestsPerSlot(50);
		valve.setMaxIPCacheSize(100);
	}
}
