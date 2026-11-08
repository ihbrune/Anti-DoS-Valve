package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.CharArrayWriter;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import org.apache.catalina.connector.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AntiDoSOpenApiSpec} and OpenAPI rendering in
 * {@link AntiDoSStatusRenderer}.
 */
class AntiDoSOpenApiSpecTest {

	private AntiDoSValve valve;
	private AntiDoSStatusRenderer renderer;

	@BeforeEach
	void setUp() throws Exception {
		AntiDoSValve.clearActiveValves();
		valve = new AntiDoSValve();
		valve.setContainer(new org.apache.catalina.core.StandardEngine());
		valve.setMonitorName("OPENAPI_TEST_VALVE");
		valve.setAllowedRequestsPerSlot(10);
		valve.setSlotLength(60);
		valve.setNumberOfSlots(3);
		valve.setShareOfRetainedFormerRequests("0.5");
		valve.setMaxIPCacheSize(100);
		valve.setStatusUri("/custom-antidos-status");
		valve.start();
		valve.reloadMonitor();
		renderer = valve.getStatusRenderer();
	}

	@AfterEach
	void tearDown() throws Exception {
		if (valve != null) {
			valve.stop();
		}
		AntiDoSValve.clearActiveValves();
	}

	@Test
	void testBuildOpenApiJsonDefault() {
		String json = AntiDoSOpenApiSpec.buildOpenApiJson();
		assertNotNull(json);
		assertTrue(json.contains("\"openapi\": \"3.1.0\""));
		assertTrue(json.contains("\"title\": \"Anti-DoS Valve Monitor & Metrics API\""));
		assertTrue(json.contains("\"/antidos-status\":"));
		assertTrue(json.contains("\"ValveSummaryResponse\""));
		assertTrue(json.contains("\"ValveDetailsResponse\""));
		assertTrue(json.contains("\"CounterEntryDto\""));
		assertTrue(json.contains("\"ActiveCounterEntryDto\""));
		assertTrue(json.contains("\"sinceBlockedOrder\""));
		assertTrue(json.contains("\"sinceActiveOrder\""));
	}

	@Test
	void testBuildOpenApiJsonCustomUri() {
		String json = AntiDoSOpenApiSpec.buildOpenApiJson("/my-shield-status");
		assertNotNull(json);
		assertTrue(json.contains("\"/my-shield-status\":"));
		assertFalse(json.contains("\"/antidos-status\":"));
	}

	@Test
	void testRendererBuildOpenApiJsonMatchesConfiguredStatusUri() {
		String json = renderer.buildOpenApiJson();
		assertNotNull(json);
		assertTrue(json.contains("\"/custom-antidos-status\":"));
	}

	@Test
	void testBuildStatusDocsHtmlContent() {
		String html = renderer.buildStatusDocsHtml(null, "testTok123");
		assertNotNull(html);
		assertTrue(html.contains("Anti-DoS Valve API Documentation"));
		assertTrue(html.contains("OPENAPI 3.1"));
		assertTrue(html.contains("REST &bull; JSON"));
		assertTrue(html.contains("custom-antidos-status"));
		assertTrue(html.contains("token=testTok123"));
		assertTrue(html.contains("format=openapi"));
		assertTrue(html.contains("format=json"));
		assertTrue(html.contains("view=details"));
		assertTrue(html.contains("sinceBlockedOrder"));
		assertTrue(html.contains("sinceActiveOrder"));
		assertTrue(html.contains("Bearer Token"));
		assertTrue(html.contains("Asymmetric Auth Defense"));
		assertTrue(html.contains("copyCode(this"));
		assertTrue(html.contains("toggleTheme()"));
	}

	@Test
	void testRenderOpenApiJsonWritesHeadersAndBody() throws Exception {
		Map<String, String> headers = new HashMap<>();
		CharArrayWriter charWriter = new CharArrayWriter();
		PrintWriter printWriter = new PrintWriter(charWriter);

		Response mockResponse = new Response() {
			@Override
			public void setHeader(String name, String value) {
				headers.put(name, value);
			}

			@Override
			public void setContentType(String type) {
				headers.put("Content-Type", type);
			}

			@Override
			public void setCharacterEncoding(String charset) {
				headers.put("Character-Encoding", charset);
			}

			@Override
			public PrintWriter getWriter() {
				return printWriter;
			}
		};

		renderer.renderOpenApiJson(mockResponse);

		assertEqualsHeader("application/json;charset=UTF-8", headers.get("Content-Type"));
		assertEqualsHeader("default-src 'none'; frame-ancestors 'none'", headers.get("Content-Security-Policy"));
		assertEqualsHeader("nosniff", headers.get("X-Content-Type-Options"));

		String body = charWriter.toString();
		assertTrue(body.contains("\"openapi\": \"3.1.0\""));
		assertTrue(body.contains("\"/custom-antidos-status\":"));
	}

	private void assertEqualsHeader(String expected, String actual) {
		org.junit.jupiter.api.Assertions.assertEquals(expected, actual);
	}
}
