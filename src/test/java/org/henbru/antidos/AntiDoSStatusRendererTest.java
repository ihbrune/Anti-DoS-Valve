package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AntiDoSStatusRenderer}.
 */
class AntiDoSStatusRendererTest {

	private AntiDoSValve valve;
	private AntiDoSStatusRenderer renderer;

	@BeforeEach
	public void setUp() throws Exception {
		AntiDoSValve.clearActiveValves();
		valve = new AntiDoSValve();
		valve.setContainer(new org.apache.catalina.core.StandardEngine());
		valve.setMonitorName("RENDERER_TEST");
		valve.setAllowedRequestsPerSlot(10);
		valve.setSlotLength(60);
		valve.setNumberOfSlots(3);
		valve.setShareOfRetainedFormerRequests("0.5");
		valve.setMaxIPCacheSize(100);
		valve.start();
		renderer = valve.getStatusRenderer();
	}

	@AfterEach
	public void tearDown() throws Exception {
		if (valve != null) {
			valve.stop();
		}
		AntiDoSValve.clearActiveValves();
	}

	@Test
	void testBuildDashboardUrl() {
		assertEquals("?", AntiDoSStatusRenderer.buildDashboardUrl(null, null, null, null));
		assertEquals("?token=tok123", AntiDoSStatusRenderer.buildDashboardUrl("tok123", null, null, null));
		assertEquals("?token=tok123&amp;valve=myValve", AntiDoSStatusRenderer.buildDashboardUrl("tok123", "myValve", null, null));
		assertEquals("?token=tok123&amp;valve=myValve&amp;view=details", AntiDoSStatusRenderer.buildDashboardUrl("tok123", "myValve", "details", null));
		assertEquals("?token=tok123&amp;valve=myValve&amp;view=details&amp;format=json", AntiDoSStatusRenderer.buildDashboardUrl("tok123", "myValve", "details", "json"));

		// Special character URL encoding
		assertEquals("?token=foo%26bar%3D123&amp;valve=V%2B1", AntiDoSStatusRenderer.buildDashboardUrl("foo&bar=123", "V+1", null, null));

		// Non-HTML separator
		assertEquals("?token=tok123&valve=myValve", AntiDoSStatusRenderer.buildDashboardUrl("tok123", "myValve", null, null, false));
	}

	@Test
	void testEscapeHtmlAndJson() {
		assertEquals("-", AntiDoSStatusRenderer.escapeHtml(null));
		assertEquals("&lt;b&gt;&amp;&#39;&quot;&lt;/b&gt;", AntiDoSStatusRenderer.escapeHtml("<b>&'\"</b>"));

		assertEquals("", AntiDoSStatusRenderer.escapeJson(null));
		assertEquals("hello\\n\\\"world\\\"", AntiDoSStatusRenderer.escapeJson("hello\n\"world\""));
	}

	@Test
	void testBuildStatusHtmlOverview() {
		String html = renderer.buildStatusHtml(null, "secretToken");
		assertNotNull(html);
		assertTrue(html.contains("Anti-DoS Valve Monitor"));
		assertTrue(html.contains("RENDERER_TEST"));
		assertTrue(html.contains("token=secretToken"));
		assertTrue(html.contains("Details &amp; Caches"));
		assertTrue(html.contains("none (no requests monitored)"));
	}

	@Test
	void testBuildStatusHtmlDetails() {
		// Populate some requests
		valve.isIPAddressBlocked("192.168.1.1");

		String htmlDetails = renderer.buildStatusHtmlDetails("RENDERER_TEST", "myToken");
		assertNotNull(htmlDetails);
		assertTrue(htmlDetails.contains("AntiDoSValve [RENDERER_TEST] Details"));
		assertTrue(htmlDetails.contains("Slot Ring Buffer Timeline"));
		assertTrue(htmlDetails.contains("<th>Requests</th>"));
		assertTrue(htmlDetails.contains("Top Active Clients (Current Slot)"));
		assertTrue(htmlDetails.contains("192.168.1.1"));
		assertTrue(htmlDetails.contains("token=myToken"));
		assertTrue(htmlDetails.contains("Back to Overview"));
		assertTrue(htmlDetails.contains("Refresh"));
		assertTrue(htmlDetails.contains("JSON Details"));
	}

	@Test
	void testBuildStatusJsonOverviewAndDetails() {
		String jsonOverview = renderer.buildStatusJson(null);
		assertNotNull(jsonOverview);
		assertTrue(jsonOverview.contains("\"totalActiveValves\": 1"));
		assertTrue(jsonOverview.contains("\"monitorName\": \"RENDERER_TEST\""));

		String jsonDetails = renderer.buildStatusJsonDetails("RENDERER_TEST");
		assertNotNull(jsonDetails);
		assertTrue(jsonDetails.contains("\"valve\": {"));
		assertTrue(jsonDetails.contains("\"slots\": ["));
		assertTrue(jsonDetails.contains("\"totalRequests\":"));
		assertTrue(jsonDetails.contains("\"blockedClients\": ["));
		assertTrue(jsonDetails.contains("\"topActiveClients\": ["));
	}

	@Test
	void testStatusDashboardHostAndIndicatorDisplay() throws Exception {
		valve.setStatusUri("/antidos-status");

		String htmlOverview = renderer.buildStatusHtml(null, "tok");
		assertTrue(htmlOverview.contains("STATUS DASHBOARD (CURRENT HOST): /antidos-status"));
		assertTrue(htmlOverview.contains("Dashboard Host: <strong>AntiDoSValve [RENDERER_TEST]</strong> (<code>/antidos-status</code>)"));
		assertTrue(htmlOverview.contains("<th>Status Dashboard</th><td><code>/antidos-status</code>"));
		assertTrue(htmlOverview.contains("<th>Status Allowed IPs</th><td><em>all (unrestricted)</em></td>"));
		assertTrue(htmlOverview.contains("Current Host"));
		assertTrue(htmlOverview.contains("dedicated to Status Dashboard at <code>/antidos-status</code>"));

		String htmlDetails = renderer.buildStatusHtmlDetails("RENDERER_TEST", "tok");
		assertTrue(htmlDetails.contains("STATUS DASHBOARD (CURRENT HOST): /antidos-status"));
		assertTrue(htmlDetails.contains("<th>Status Dashboard</th><td><code>/antidos-status</code>"));
		assertTrue(htmlDetails.contains("<th>Status Allowed IPs</th><td><em>all (unrestricted)</em></td>"));

		String jsonOverview = renderer.buildStatusJson(null);
		assertTrue(jsonOverview.contains("\"statusUri\": \"/antidos-status\""));
		assertTrue(jsonOverview.contains("\"statusAllowedIPs\": null"));
		assertTrue(jsonOverview.contains("\"isStatusHost\": true"));
		assertTrue(jsonOverview.contains("\"isCurrentHost\": true"));

		String jsonDetails = renderer.buildStatusJsonDetails("RENDERER_TEST");
		assertTrue(jsonDetails.contains("\"statusUri\": \"/antidos-status\""));
		assertTrue(jsonDetails.contains("\"statusAllowedIPs\": null"));
		assertTrue(jsonDetails.contains("\"isStatusHost\": true"));
		assertTrue(jsonDetails.contains("\"isCurrentHost\": true"));

		assertTrue(htmlOverview.contains("#1 IN PIPELINE"));
		assertTrue(htmlOverview.contains("<th>Pipeline Order</th><td><strong>#1</strong></td>"));
		assertTrue(htmlDetails.contains("#1 IN PIPELINE"));
		assertTrue(htmlDetails.contains("<th>Pipeline Order</th><td><strong>#1</strong></td>"));
		assertTrue(jsonOverview.contains("\"pipelineOrder\": 1"));
		assertTrue(jsonDetails.contains("\"pipelineOrder\": 1"));

		// With statusAllowedIPs configured
		valve.setStatusAllowedIPs("192\\.168\\..*");
		String htmlWithAllowed = renderer.buildStatusHtml(null, "tok");
		assertTrue(htmlWithAllowed.contains("<th>Status Allowed IPs</th><td><code>192\\.168\\..*</code></td>"));
		String htmlDetailsWithAllowed = renderer.buildStatusHtmlDetails("RENDERER_TEST", "tok");
		assertTrue(htmlDetailsWithAllowed.contains("<th>Status Allowed IPs</th><td><code>192\\.168\\..*</code></td>"));

		String jsonWithAllowed = renderer.buildStatusJson(null);
		assertTrue(jsonWithAllowed.contains("\"statusAllowedIPs\": \"192\\\\.168\\\\..*\""));
		String jsonDetailsWithAllowed = renderer.buildStatusJsonDetails("RENDERER_TEST");
		assertTrue(jsonDetailsWithAllowed.contains("\"statusAllowedIPs\": \"192\\\\.168\\\\..*\""));
	}

	@Test
	void testAlwaysForbiddenBlocksDisplay() {
		// When alwaysForbiddenIPs is NOT configured, the row should NOT appear
		String htmlNoConfig = renderer.buildStatusHtml(null, null);
		assertFalse(htmlNoConfig.contains("Always Forbidden Blocks"));

		// Configure alwaysForbiddenIPs
		valve.setAlwaysForbiddenIPs("10\\.0\\.0\\..*");
		valve.isRequestAllowed("10.0.0.1", "/api/test");
		valve.isRequestAllowed("10.0.0.2", "/api/test");
		valve.isRequestAllowed("10.0.0.3", "/api/test");
		valve.isRequestAllowed("192.168.1.1", "/api/test"); // Not forbidden

		assertEquals(3, valve.getAlwaysForbiddenBlockedRequests());

		String htmlOverview = renderer.buildStatusHtml(null, null);
		assertTrue(htmlOverview.contains("<th>Always Forbidden IPs</th>"));
		assertTrue(htmlOverview.contains("<th>Always Forbidden Blocks</th><td><strong>3</strong> requests rejected</td>"));

		String htmlDetails = renderer.buildStatusHtmlDetails("RENDERER_TEST", null);
		assertTrue(htmlDetails.contains("<th>Always Forbidden IPs</th>"));
		assertTrue(htmlDetails.contains("<th>Always Forbidden Blocks</th><td><strong>3</strong> requests rejected</td>"));

		String jsonOverview = renderer.buildStatusJson(null);
		assertTrue(jsonOverview.contains("\"alwaysForbiddenBlockedRequests\": 3"));
		assertTrue(jsonOverview.contains("\"alwaysForbiddenIPs\": \"10\\\\.0\\\\.0\\\\..*\""));

		String jsonDetails = renderer.buildStatusJsonDetails("RENDERER_TEST");
		assertTrue(jsonDetails.contains("\"alwaysForbiddenBlockedRequests\": 3"));
		assertTrue(jsonDetails.contains("\"alwaysForbiddenIPs\": \"10\\\\.0\\\\.0\\\\..*\""));

		valve.setAlwaysAllowedIPs("192\\.168\\..*");
		String jsonWithAllowed = renderer.buildStatusJson(null);
		assertTrue(jsonWithAllowed.contains("\"alwaysAllowedIPs\": \"192\\\\.168\\\\..*\""));
	}

	@Test
	void testPipelineOrderMultipleValves() throws Exception {
		AntiDoSValve.clearActiveValves();

		AntiDoSValve v1 = new AntiDoSValve();
		v1.setContainer(new org.apache.catalina.core.StandardEngine());
		v1.setMonitorName("VALVE_FIRST");
		v1.setAllowedRequestsPerSlot(10);
		v1.setNumberOfSlots(5);
		v1.setSlotLength(60);
		v1.setMaxIPCacheSize(100);
		v1.start();

		AntiDoSValve v2 = new AntiDoSValve();
		v2.setContainer(new org.apache.catalina.core.StandardEngine());
		v2.setMonitorName("VALVE_SECOND");
		v2.setAllowedRequestsPerSlot(10);
		v2.setNumberOfSlots(5);
		v2.setSlotLength(60);
		v2.setMaxIPCacheSize(100);
		v2.start();

		assertEquals(1, v1.getPipelineOrder());
		assertEquals(2, v2.getPipelineOrder());

		AntiDoSStatusRenderer r = new AntiDoSStatusRenderer(v1);
		String html = r.buildStatusHtml(null, null);

		// Assert order in rendered HTML: VALVE_FIRST appears before VALVE_SECOND
		int idxV1 = html.indexOf("VALVE_FIRST");
		int idxV2 = html.indexOf("VALVE_SECOND");
		assertTrue(idxV1 != -1 && idxV2 != -1);
		assertTrue(idxV1 < idxV2);

		// Assert pipeline badges
		assertTrue(html.contains("#1 IN PIPELINE"));
		assertTrue(html.contains("#2 IN PIPELINE"));

		// JSON verification
		String json = r.buildStatusJson(null);
		int jsonV1 = json.indexOf("\"monitorName\": \"VALVE_FIRST\"");
		int jsonV2 = json.indexOf("\"monitorName\": \"VALVE_SECOND\"");
		assertTrue(jsonV1 != -1 && jsonV2 != -1);
		assertTrue(jsonV1 < jsonV2);
		assertTrue(json.contains("\"pipelineOrder\": 1"));
		assertTrue(json.contains("\"pipelineOrder\": 2"));

		v1.stop();
		v2.stop();
		AntiDoSValve.clearActiveValves();
	}

	@Test
	void testParseLimit() {
		assertEquals(10, AntiDoSStatusRenderer.parseLimit("10", 50));
		assertEquals(Integer.MAX_VALUE, AntiDoSStatusRenderer.parseLimit("all", 50));
		assertEquals(Integer.MAX_VALUE, AntiDoSStatusRenderer.parseLimit("-1", 50));
		assertEquals(50, AntiDoSStatusRenderer.parseLimit("0", 50));
		assertEquals(50, AntiDoSStatusRenderer.parseLimit("-2", 50));
		assertEquals(50, AntiDoSStatusRenderer.parseLimit("invalid", 50));
		assertEquals(50, AntiDoSStatusRenderer.parseLimit(null, 50));
		assertEquals(50, AntiDoSStatusRenderer.parseLimit("", 50));
	}

	@Test
	void testSlotSelectionAndLimitInJsonAndHtml() {
		// Populate some requests and block an IP
		for (int i = 0; i < 15; i++) {
			valve.isIPAddressBlocked("192.168.1.100");
		}
		valve.isIPAddressBlocked("192.168.1.200");

		// Test default details JSON (current slot, limit default 50)
		String jsonCurrent = renderer.buildStatusJsonDetails("RENDERER_TEST", "current", null);
		assertNotNull(jsonCurrent);
		assertTrue(jsonCurrent.contains("\"selectedSlot\": {"));
		assertTrue(jsonCurrent.contains("\"type\": \"current\""));
		assertTrue(jsonCurrent.contains("\"endTime\":"));
		assertTrue(jsonCurrent.contains("\"currentSlotKey\":"));
		assertTrue(jsonCurrent.contains("\"lastCompletedSlotKey\":"));
		assertTrue(jsonCurrent.contains("\"blockedLimit\": 50"));
		assertTrue(jsonCurrent.contains("\"totalBlockedClients\": 1"));
		assertTrue(jsonCurrent.contains("\"192.168.1.100\""));

		// Test slot=previous
		String jsonPrevious = renderer.buildStatusJsonDetails("RENDERER_TEST", "previous", 10);
		assertNotNull(jsonPrevious);
		assertTrue(jsonPrevious.contains("\"blockedLimit\": 10"));
		assertTrue(jsonPrevious.contains("\"blockedClients\": ["));
		// When no previous slot exists yet, selectedSlot is null
		assertTrue(jsonPrevious.contains("\"selectedSlot\": null"));

		String jsonPreviousUnlimited = renderer.buildStatusJsonDetails("RENDERER_TEST", "previous", Integer.MAX_VALUE);
		assertNotNull(jsonPreviousUnlimited);
		assertTrue(jsonPreviousUnlimited.contains("\"blockedLimit\": null"));

		// Test Overview JSON slot metrics
		String jsonOverview = renderer.buildStatusJson(null);
		assertTrue(jsonOverview.contains("\"currentSlotKey\":"));
		assertTrue(jsonOverview.contains("\"lastCompletedSlotKey\":"));
		assertTrue(jsonOverview.contains("\"previousActiveCounters\":"));
		assertTrue(jsonOverview.contains("\"previousBlockedCounters\":"));
		assertTrue(jsonOverview.contains("\"previousTotalRequests\":"));

		// Test HTML Details with slot=previous
		String htmlPrev = renderer.buildStatusHtmlDetails("RENDERER_TEST", "tok", "previous", 25);
		assertNotNull(htmlPrev);
		assertTrue(htmlPrev.contains("Action"));
		assertTrue(htmlPrev.contains("Inspect"));
		assertTrue(htmlPrev.contains("Current Slot"));
		assertTrue(htmlPrev.contains("Previous Slot"));
		assertTrue(htmlPrev.contains("{ } JSON (This Slot)"));
	}

	@Test
	void testUnknownSlotReturnsNullSlot() {
		String jsonInvalid = renderer.buildStatusJsonDetails("RENDERER_TEST", "invalid_slot_key_999", null);
		assertNotNull(jsonInvalid);
		assertTrue(jsonInvalid.contains("\"selectedSlot\": null"));
		assertTrue(jsonInvalid.contains("\"totalBlockedClients\": 0"));

		String htmlInvalid = renderer.buildStatusHtmlDetails("RENDERER_TEST", "tok", "invalid_slot_key_999", 50);
		assertNotNull(htmlInvalid);
		assertTrue(htmlInvalid.contains("Slot Not Available"));
	}

	@Test
	void testHtmlLimitCappedToMax() {
		assertEquals(1000, AntiDoSStatusRenderer.MAX_HTML_LIMIT);
		String htmlCapped = renderer.buildStatusHtmlDetails("RENDERER_TEST", "tok", "current", 5000);
		assertNotNull(htmlCapped);
		// With 0 or few blocked clients, header shows (0 of 0 entries)
		assertTrue(htmlCapped.contains("entries)"));
	}
}

