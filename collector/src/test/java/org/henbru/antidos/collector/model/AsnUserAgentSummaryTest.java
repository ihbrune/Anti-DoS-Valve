package org.henbru.antidos.collector.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AsnUserAgentSummaryTest {

	@Test
	void testFamilyDetectionAndSuspiciousCheck() {
		// Chrome 149 (unreleased/spoofed future version)
		String spoofedChrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";
		AsnUserAgentSummary sum1 = AsnUserAgentSummary.of(spoofedChrome, 12000, 24000, 500, 20);
		assertEquals("Chrome 149", sum1.browserFamily());
		assertTrue(sum1.suspicious());
		assertEquals(50.0, sum1.requestPct(), 0.1);
		assertTrue(sum1.isCaptured());

		// Edge 148 (unreleased/spoofed)
		String spoofedEdge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0";
		AsnUserAgentSummary sum2 = AsnUserAgentSummary.of(spoofedEdge, 3000, 24000, 100, 5);
		assertEquals("Edge 148", sum2.browserFamily());
		assertEquals(12.5, sum2.requestPct(), 0.1);

		// Firefox 128 (regular/current release)
		String legitFirefox = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
		AsnUserAgentSummary sum3 = AsnUserAgentSummary.of(legitFirefox, 5000, 24000, 200, 3);
		assertEquals("Firefox 128", sum3.browserFamily());
		assertFalse(sum3.suspicious());

		// Python / Scrapy scraper
		String pythonScript = "Scrapy/2.11.0 (+https://scrapy.org)";
		AsnUserAgentSummary sum4 = AsnUserAgentSummary.of(pythonScript, 1000, 24000, 50, 1);
		assertEquals("Bot / Script", sum4.browserFamily());
		assertTrue(sum4.suspicious());

		// Empty / Not captured
		AsnUserAgentSummary sum5 = AsnUserAgentSummary.of("(No User-Agent captured)", 3000, 24000, 150, 8);
		assertEquals("None", sum5.browserFamily());
		assertFalse(sum5.suspicious());
		assertFalse(sum5.isCaptured());
	}
}

