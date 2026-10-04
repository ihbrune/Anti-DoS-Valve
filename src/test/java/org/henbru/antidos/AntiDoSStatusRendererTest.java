package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
		assertTrue(htmlOverview.contains("Current Host"));
		assertTrue(htmlOverview.contains("dedicated to Status Dashboard at <code>/antidos-status</code>"));

		String htmlDetails = renderer.buildStatusHtmlDetails("RENDERER_TEST", "tok");
		assertTrue(htmlDetails.contains("STATUS DASHBOARD (CURRENT HOST): /antidos-status"));
		assertTrue(htmlDetails.contains("<th>Status Dashboard</th><td><code>/antidos-status</code>"));

		String jsonOverview = renderer.buildStatusJson(null);
		assertTrue(jsonOverview.contains("\"statusUri\": \"/antidos-status\""));
		assertTrue(jsonOverview.contains("\"isStatusHost\": true"));
		assertTrue(jsonOverview.contains("\"isCurrentHost\": true"));

		String jsonDetails = renderer.buildStatusJsonDetails("RENDERER_TEST");
		assertTrue(jsonDetails.contains("\"statusUri\": \"/antidos-status\""));
		assertTrue(jsonDetails.contains("\"isStatusHost\": true"));
		assertTrue(jsonDetails.contains("\"isCurrentHost\": true"));
	}
}
