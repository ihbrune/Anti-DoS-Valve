package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
		valve.reloadMonitor();
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

	@Test
	void testDescriptionRenderingInStatusHtmlAndJson() {
		// 1. Without description
		assertNull(valve.getDescription());
		String htmlNoDesc = renderer.buildStatusHtml(null, "tok");
		assertFalse(htmlNoDesc.contains("<div class=\"valve-desc\">"));
		assertFalse(htmlNoDesc.contains("<th>Description</th>"));

		String htmlDetailsNoDesc = renderer.buildStatusHtmlDetails("RENDERER_TEST", "tok");
		assertFalse(htmlDetailsNoDesc.contains("<div class=\"valve-desc\">"));
		assertFalse(htmlDetailsNoDesc.contains("<th>Description</th>"));

		String jsonOverviewNoDesc = renderer.buildStatusJson(null);
		assertTrue(jsonOverviewNoDesc.contains("\"description\": null"));

		String jsonDetailsNoDesc = renderer.buildStatusJsonDetails("RENDERER_TEST");
		assertTrue(jsonDetailsNoDesc.contains("\"description\": null"));

		// 2. With description
		valve.setDescription("Rate limiter for public API endpoints & <sensitive> routes");

		String htmlWithDesc = renderer.buildStatusHtml(null, "tok");
		assertTrue(htmlWithDesc.contains("<div class=\"valve-desc\">Rate limiter for public API endpoints &amp; &lt;sensitive&gt; routes</div>"));
		assertTrue(htmlWithDesc.contains("<tr><th>Description</th><td>Rate limiter for public API endpoints &amp; &lt;sensitive&gt; routes</td></tr>"));

		String htmlDetailsWithDesc = renderer.buildStatusHtmlDetails("RENDERER_TEST", "tok");
		assertTrue(htmlDetailsWithDesc.contains("<div class=\"valve-desc\">Rate limiter for public API endpoints &amp; &lt;sensitive&gt; routes</div>"));
		assertTrue(htmlDetailsWithDesc.contains("<tr><th>Description</th><td>Rate limiter for public API endpoints &amp; &lt;sensitive&gt; routes</td></tr>"));

		String jsonOverviewWithDesc = renderer.buildStatusJson(null);
		assertTrue(jsonOverviewWithDesc.contains("\"description\": \"Rate limiter for public API endpoints & <sensitive> routes\""));

		String jsonDetailsWithDesc = renderer.buildStatusJsonDetails("RENDERER_TEST");
		assertTrue(jsonDetailsWithDesc.contains("\"description\": \"Rate limiter for public API endpoints & <sensitive> routes\""));
	}

	@Test
	void testBlockedAndActiveLimits() {
		// Populate blocked IP and active IP
		for (int i = 0; i < 15; i++) {
			valve.isIPAddressBlocked("10.10.10.1");
		}
		valve.isIPAddressBlocked("10.10.10.2");

		// 1. parseLimit with allowZero
		assertEquals(0, AntiDoSStatusRenderer.parseLimit("0", 50, true));
		assertEquals(50, AntiDoSStatusRenderer.parseLimit("0", 50, false));
		assertEquals(50, AntiDoSStatusRenderer.parseLimit("0", 50));
		assertEquals(Integer.MAX_VALUE, AntiDoSStatusRenderer.parseLimit("all", 50, true));

		// 2. resolveEffectiveLimit
		assertEquals(0, AntiDoSStatusRenderer.resolveEffectiveLimit(0, 50, 50));
		assertEquals(25, AntiDoSStatusRenderer.resolveEffectiveLimit(null, 25, 50));
		assertEquals(50, AntiDoSStatusRenderer.resolveEffectiveLimit(null, null, 50));
		assertEquals(Integer.MAX_VALUE, AntiDoSStatusRenderer.resolveEffectiveLimit(-1, null, 50));

		// 3. Details JSON with blockedLimit=all and activeLimit=0
		String jsonBlockedOnly = renderer.buildStatusJsonDetails("RENDERER_TEST", "current", Integer.MAX_VALUE, 0);
		assertTrue(jsonBlockedOnly.contains("\"blockedLimit\": null"));
		assertTrue(jsonBlockedOnly.contains("\"activeLimit\": 0"));
		assertTrue(jsonBlockedOnly.contains("\"totalBlockedClients\": 1"));
		assertTrue(jsonBlockedOnly.contains("\"10.10.10.1\""));
		assertFalse(jsonBlockedOnly.contains("\"10.10.10.2\"")); // 10.10.10.2 is active, must be excluded when activeLimit=0
		assertTrue(jsonBlockedOnly.contains("\"totalActiveClients\": 1"));

		// 4. Details JSON with blockedLimit=0 and activeLimit=5
		String jsonActiveOnly = renderer.buildStatusJsonDetails("RENDERER_TEST", "current", 0, 5);
		assertTrue(jsonActiveOnly.contains("\"blockedLimit\": 0"));
		assertTrue(jsonActiveOnly.contains("\"activeLimit\": 5"));
		assertFalse(jsonActiveOnly.contains("\"10.10.10.1\"")); // 10.10.10.1 is blocked, must be excluded when blockedLimit=0
		assertTrue(jsonActiveOnly.contains("\"topActiveClients\": ["));
		assertTrue(jsonActiveOnly.contains("\"10.10.10.2\""));

		// 5. HTML Details with blockedLimit=all and activeLimit=0
		String htmlBlockedOnly = renderer.buildStatusHtmlDetails("RENDERER_TEST", "tok", "current", Integer.MAX_VALUE, 0);
		assertTrue(htmlBlockedOnly.contains("Blocked Clients"));
		assertTrue(htmlBlockedOnly.contains("Top Active Clients"));
		assertTrue(htmlBlockedOnly.contains("No active clients in current slot."));
	}

	@Test
	void testDeltaCursoringAndFiltering() {
		// Verify helper parsing methods
		assertNull(AntiDoSStatusRenderer.parseLongParam(null));
		assertNull(AntiDoSStatusRenderer.parseLongParam(""));
		assertNull(AntiDoSStatusRenderer.parseLongParam("abc"));
		assertEquals(123456789L, AntiDoSStatusRenderer.parseLongParam("123456789"));

		assertNull(AntiDoSStatusRenderer.parseIntParam(null));
		assertNull(AntiDoSStatusRenderer.parseIntParam(""));
		assertNull(AntiDoSStatusRenderer.parseIntParam("xyz"));
		assertEquals(5, AntiDoSStatusRenderer.parseIntParam("5"));

		// Populate slot with counters having controlled access orders
		AntiDoSMonitor mon = valve.provideMonitor();
		mon.registerAndCheckRequest("10.20.0.1");
		AntiDoSSlot slot = mon.getCurrentSlotIfExists();
		assertNotNull(slot);

		// Add an active IP with 1 hit and low order
		AntiDoSCounter c1 = slot.getActiveCounters().get("10.20.0.1");
		assertNotNull(c1);
		c1.touch(1000L);

		// Add another active IP with 3 hits and high order
		mon.registerAndCheckRequest("10.20.0.2");
		mon.registerAndCheckRequest("10.20.0.2");
		mon.registerAndCheckRequest("10.20.0.2");
		AntiDoSCounter c2 = slot.getActiveCounters().get("10.20.0.2");
		assertNotNull(c2);
		c2.touch(2000L);

		// 1. Initial poll without sinceOrder: should contain maxActiveOrder >= 2000 and both IPs
		String jsonInitial = renderer.buildStatusJsonDetails("RENDERER_TEST", "current", null, null);
		assertTrue(jsonInitial.contains("\"maxActiveOrder\":"));
		assertTrue(jsonInitial.contains("\"maxBlockedOrder\":"));
		assertTrue(jsonInitial.contains("\"10.20.0.1\""));
		assertTrue(jsonInitial.contains("\"10.20.0.2\""));

		// 2. Poll with sinceActiveOrder=1500: should only include 10.20.0.2
		String jsonSince1500 = renderer.buildStatusJsonDetails("RENDERER_TEST", "current", null, null, null, 1500L, null);
		assertTrue(jsonSince1500.contains("\"sinceActiveOrder\": 1500"));
		assertTrue(jsonSince1500.contains("\"10.20.0.2\""));
		assertFalse(jsonSince1500.contains("\"10.20.0.1\""));

		// 3. Poll with sinceActiveOrder=2500: should include neither IP
		String jsonSince2500 = renderer.buildStatusJsonDetails("RENDERER_TEST", "current", null, null, null, 2500L, null);
		assertFalse(jsonSince2500.contains("\"10.20.0.1\""));
		assertFalse(jsonSince2500.contains("\"10.20.0.2\""));

		// 4. Poll with activeMinCount=2: 10.20.0.1 has count=1 -> excluded; 10.20.0.2 has count=3 -> included
		String jsonMinCount2 = renderer.buildStatusJsonDetails("RENDERER_TEST", "current", null, null, null, 0L, 2);
		assertTrue(jsonMinCount2.contains("\"activeMinCount\": 2"));
		assertTrue(jsonMinCount2.contains("\"10.20.0.2\""));
		assertFalse(jsonMinCount2.contains("\"10.20.0.1\""));
	}
}

