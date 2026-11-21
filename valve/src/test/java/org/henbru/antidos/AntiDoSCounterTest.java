package org.henbru.antidos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * Unit test for the counter implementation
 */
class AntiDoSCounterTest {

	@Test
	void testCount() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(0, rec.getCount());
		rec.incrementCount();
		assertEquals(1, rec.getCount());
		rec.addAndGetCount(1);
		assertEquals(2, rec.getCount());
		rec.setCount(1);
		assertEquals(1, rec.getCount());
		rec.setCount(100);
		assertEquals(100, rec.getCount());
	}

	@Test
	void testRetainedCounts() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(-1, rec.getRetainedCounts());
		rec.addAndGetRetainedCounts(1);
		assertEquals(0, rec.getRetainedCounts());
		rec.addAndGetRetainedCounts(1);
		assertEquals(1, rec.getRetainedCounts());
		rec.addAndGetRetainedCounts(1);
		assertEquals(2, rec.getRetainedCounts());
		rec.setRetainedCounts(1);
		assertEquals(1, rec.getRetainedCounts());
		assertTrue(rec.compareAndSetRetainedCounts(1, 5));
		assertEquals(5, rec.getRetainedCounts());
		assertFalse(rec.compareAndSetRetainedCounts(1, 10));
		assertEquals(5, rec.getRetainedCounts());
	}

	@Test
	void testCountCombined() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(0, rec.getCountCombined());

		rec.incrementCount();
		assertEquals(1, rec.getCountCombined());

		rec.addAndGetCount(1);
		assertEquals(2, rec.getCountCombined());

		rec.setRetainedCounts(123);
		assertEquals(125, rec.getCountCombined());
	}

	@Test
	void testTouch() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(0, rec.getAccessOrder());

		long t0 = System.nanoTime();
		rec.touch();
		long t1 = System.nanoTime();

		assertTrue(rec.getAccessOrder() >= t0);
		assertTrue(rec.getAccessOrder() <= t1);

		rec.touch(42L);
		assertEquals(42L, rec.getAccessOrder());
	}

	@Test
	void testReturningCount() {
		AntiDoSCounter rec = new AntiDoSCounter();
		assertEquals(0, rec.getReturningCount());
		rec.incrementReturningCount();
		assertEquals(1, rec.getReturningCount());
		rec.addAndGetReturningCount(4);
		assertEquals(5, rec.getReturningCount());
		rec.setReturningCount(10);
		assertEquals(10, rec.getReturningCount());
		assertTrue(rec.toString().contains("Returning:10"));
	}

	@Test
	void testRecordSampleIfAbsent() {
		AntiDoSCounter counter = new AntiDoSCounter();
		assertFalse(counter.isLocked());
		assertEquals(null, counter.getSample());

		boolean recorded = counter.recordSampleIfAbsent("POST", "/wp-login.php?user=admin&pwd=secret", "curl/7.88.1");
		assertTrue(recorded);

		AntiDoSCounter.SampleRequest sample = counter.getSample();
		assertEquals("POST", sample.method());
		assertEquals("/wp-login.php", sample.uri()); // query string stripped!
		assertEquals("curl/7.88.1", sample.userAgent());
		assertFalse(sample.authenticated());

		// Second call must NOT overwrite the first sample
		boolean second = counter.recordSampleIfAbsent("GET", "/other", "other-ua", true);
		assertFalse(second);
		assertEquals("POST", counter.getSample().method());
		assertEquals("/wp-login.php", counter.getSample().uri());
		assertFalse(counter.getSample().authenticated());
	}

	@Test
	void testRecordSampleAuthenticated() {
		AntiDoSCounter counter = new AntiDoSCounter();
		assertTrue(counter.recordSampleIfAbsent("GET", "/dashboard", "Mozilla/5.0", true));
		assertNotNull(counter.getSample());
		assertTrue(counter.getSample().authenticated());
	}

	@Test
	void testSampleSanitizationAndLimits() {
		AntiDoSCounter counter = new AntiDoSCounter();

		// Excessively long URI and UA, newlines/control chars
		String longUri = "/api/" + "a".repeat(500);
		String maliciousUa = "BadBot\r\nInjectedHeader: value\u0000" + "x".repeat(200);

		assertTrue(counter.recordSampleIfAbsent("post", longUri, maliciousUa));

		AntiDoSCounter.SampleRequest sample = counter.getSample();
		assertEquals("POST", sample.method());
		assertTrue(sample.uri().length() <= 256);
		assertTrue(sample.userAgent().length() <= 128);
		assertFalse(sample.userAgent().contains("\r"));
		assertFalse(sample.userAgent().contains("\n"));
		assertFalse(sample.userAgent().contains("\u0000"));
	}

	@Test
	void testCalculatePriority() {
		// Mutating methods -> Priority 3
		assertEquals(3, AntiDoSCounter.calculatePriority("POST", "/idp/login"));
		assertEquals(3, AntiDoSCounter.calculatePriority("PUT", "/api/item/1"));
		assertEquals(3, AntiDoSCounter.calculatePriority("DELETE", "/resource"));
		assertEquals(3, AntiDoSCounter.calculatePriority("PATCH", "/patch"));

		// Extensionless routes / content endpoints -> Priority 2
		assertEquals(2, AntiDoSCounter.calculatePriority("GET", "/portal/course/catalog"));
		assertEquals(2, AntiDoSCounter.calculatePriority("GET", "/app/public/overview"));
		assertEquals(2, AntiDoSCounter.calculatePriority("GET", "/idp/login"));
		assertEquals(2, AntiDoSCounter.calculatePriority("GET", "/intranet/"));
		assertEquals(2, AntiDoSCounter.calculatePriority("GET", "/api/qr"));

		// Dynamic pages, documents, data -> Priority 2
		assertEquals(2, AntiDoSCounter.calculatePriority("GET", "/portal/member/detail.jsp"));
		assertEquals(2, AntiDoSCounter.calculatePriority("GET", "/portal/member/detail.jsp;jsessionid=123"));
		assertEquals(2, AntiDoSCounter.calculatePriority("GET", "/document.pdf?dl=1"));
		assertEquals(2, AntiDoSCounter.calculatePriority("GET", "/data.json"));
		assertEquals(2, AntiDoSCounter.calculatePriority("GET", "/feed.xml"));

		// Images / Media -> Priority 1
		assertEquals(1, AntiDoSCounter.calculatePriority("GET", "/assets/images/banner.png"));
		assertEquals(1, AntiDoSCounter.calculatePriority("GET", "/photo.jpg"));
		assertEquals(1, AntiDoSCounter.calculatePriority("GET", "/icon.svg"));

		// Static frontend infrastructure -> Priority 0
		assertEquals(0, AntiDoSCounter.calculatePriority("GET", "/assets/css/layout.css"));
		assertEquals(0, AntiDoSCounter.calculatePriority("GET", "/assets/js/bundle.js"));
		assertEquals(0, AntiDoSCounter.calculatePriority("GET", "/assets/js/menus.js"));
		assertEquals(0, AntiDoSCounter.calculatePriority("GET", "/font.woff2"));
		assertEquals(0, AntiDoSCounter.calculatePriority("GET", "/favicon.ico"));
	}

	@Test
	void testSemanticPrioritySampleUpgrades() {
		AntiDoSCounter counter = new AntiDoSCounter();
		assertNull(counter.getSample());

		// 1. Initial static CSS asset (Priority 0)
		assertTrue(counter.recordSampleIfHigherPriority("GET", "/styles/layout.css", "Browser/1.0", false));
		assertEquals("/styles/layout.css", counter.getSample().uri());
		assertEquals(0, counter.getSample().priority());

		// 2. Subsequent static JS asset (Priority 0) -> equal priority, NOT overwritten
		assertFalse(counter.recordSampleIfHigherPriority("GET", "/scripts/app.js", "Browser/1.0", false));
		assertEquals("/styles/layout.css", counter.getSample().uri());

		// 3. Image (Priority 1) -> strictly higher than 0, UPGRADES sample!
		assertTrue(counter.recordSampleIfHigherPriority("GET", "/images/logo.png", "Browser/1.0", false));
		assertEquals("/images/logo.png", counter.getSample().uri());
		assertEquals(1, counter.getSample().priority());

		// 4. JS asset (Priority 0) -> lower than 1, NOT overwritten
		assertFalse(counter.recordSampleIfHigherPriority("GET", "/scripts/staticJavascript.js", "Browser/1.0", false));
		assertEquals("/images/logo.png", counter.getSample().uri());

		// 5. Semantic extensionless page (Priority 2) -> strictly higher than 1, UPGRADES sample!
		assertTrue(counter.recordSampleIfHigherPriority("GET", "/portal/course/catalog", "Browser/1.0", false));
		assertEquals("/portal/course/catalog", counter.getSample().uri());
		assertEquals(2, counter.getSample().priority());

		// 6. Another content page (Priority 2) -> equal priority, NOT overwritten (entry point preserved)
		assertFalse(counter.recordSampleIfHigherPriority("GET", "/portal/member/detail.jsp", "Browser/1.0", false));
		assertEquals("/portal/course/catalog", counter.getSample().uri());

		// 7. Login POST (Priority 3) -> strictly higher than 2, UPGRADES sample to mutating action!
		assertTrue(counter.recordSampleIfHigherPriority("POST", "/idp/login", "Browser/1.0", false));
		assertEquals("POST", counter.getSample().method());
		assertEquals("/idp/login", counter.getSample().uri());
		assertEquals(3, counter.getSample().priority());

		// 8. Subsequent GET page (Priority 2) -> lower than 3, NOT overwritten
		assertFalse(counter.recordSampleIfHigherPriority("GET", "/dashboard", "Browser/1.0", false));
		assertEquals("/idp/login", counter.getSample().uri());
	}

	@Test
	void testUserAgentCardinalityTracking() {
		AntiDoSCounter counter = new AntiDoSCounter();
		assertFalse(counter.hasUserAgentTracker());
		assertEquals(0, counter.getDistinctUserAgents());
		assertEquals(0L, counter.getUaCardinalityBits());

		// Register single User-Agent
		counter.registerUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
		assertTrue(counter.hasUserAgentTracker());
		assertEquals(1, counter.getDistinctUserAgents());
		long firstBits = counter.getUaCardinalityBits();
		assertTrue(firstBits != 0L);

		// Register same User-Agent again (idempotent, distinct count unchanged)
		counter.registerUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
		assertEquals(1, counter.getDistinctUserAgents());
		assertEquals(firstBits, counter.getUaCardinalityBits());

		// Register multiple distinct User-Agents
		counter.registerUserAgent("curl/7.88.1");
		counter.registerUserAgent("python-requests/2.31.0");
		counter.registerUserAgent("Googlebot/2.1");
		assertTrue(counter.getDistinctUserAgents() >= 2);
		assertTrue(counter.getDistinctUserAgents() <= 4);

		// Test merging bits
		AntiDoSCounter other = new AntiDoSCounter();
		other.registerUserAgent("Custom-Scanner/1.0");
		counter.mergeUaCardinalityBits(other.getUaCardinalityBits());
		assertTrue(counter.getDistinctUserAgents() >= other.getDistinctUserAgents());
	}
}
