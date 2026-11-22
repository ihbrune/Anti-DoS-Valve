package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class AntiDoSSystemMetricsTest {

	@Test
	void testCollectAndJson() {
		AntiDoSSystemMetrics metrics = AntiDoSSystemMetrics.collect();
		assertNotNull(metrics);

		// Memory and GC should always be measurable on any standard JVM
		assertNotNull(metrics.heapUsedBytes());
		assertTrue(metrics.heapUsedBytes() > 0);

		StringBuilder sb = new StringBuilder();
		metrics.appendJson(sb);
		String json = sb.toString();

		assertTrue(json.contains("\"system\":"));
		assertTrue(json.contains("\"heapUsedBytes\":"));
		assertTrue(json.contains("\"heapUsedPercent\":"));
		assertTrue(json.contains("\"processCpuLoad\":"));
		assertTrue(json.contains("\"tomcatBusyThreads\":"));
	}

	@Test
	void testStatusRendererIncludesSystemMetrics() {
		AntiDoSValve valve = new AntiDoSValve();
		valve.setMonitorName("METRICS_TEST_VALVE");
		AntiDoSStatusRenderer renderer = new AntiDoSStatusRenderer(valve);

		String overviewJson = renderer.buildStatusJson(null);
		assertTrue(overviewJson.contains("\"system\":"));
		assertTrue(overviewJson.contains("\"heapUsedBytes\":"));

		String detailsJson = renderer.buildStatusJsonDetails("METRICS_TEST_VALVE");
		assertTrue(detailsJson.contains("\"system\":"));
		assertTrue(detailsJson.contains("\"heapUsedBytes\":"));

		String html = renderer.buildStatusHtml(null, "token");
		assertNotNull(html);
		assertTrue(html.contains("Host Telemetry"));
	}
}
