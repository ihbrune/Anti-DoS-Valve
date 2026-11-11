package org.henbru.antidos.collector.aggregation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.henbru.antidos.collector.model.UserAgentFamily;
import org.junit.jupiter.api.Test;

class UserAgentClassifierTest {

	@Test
	void testClassifyStandardBrowsers() {
		// Chrome Desktop
		assertEquals(UserAgentFamily.CHROME_DESKTOP, UserAgentClassifier.classify(
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"));

		// Chrome Mobile
		assertEquals(UserAgentFamily.CHROME_MOBILE, UserAgentClassifier.classify(
				"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.39 Mobile Safari/537.36"));

		// Safari Desktop
		assertEquals(UserAgentFamily.SAFARI_DESKTOP, UserAgentClassifier.classify(
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"));

		// Mobile Safari
		assertEquals(UserAgentFamily.SAFARI_MOBILE, UserAgentClassifier.classify(
				"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"));

		// Firefox Desktop
		assertEquals(UserAgentFamily.FIREFOX_DESKTOP, UserAgentClassifier.classify(
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"));

		// Firefox Mobile
		assertEquals(UserAgentFamily.FIREFOX_MOBILE, UserAgentClassifier.classify(
				"Mozilla/5.0 (Android 14; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0"));

		// Edge Desktop
		assertEquals(UserAgentFamily.EDGE_DESKTOP, UserAgentClassifier.classify(
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"));

		// Opera
		assertEquals(UserAgentFamily.OPERA, UserAgentClassifier.classify(
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/114.0.0.0"));
	}

	@Test
	void testClassifyAutomatedTools() {
		assertEquals(UserAgentFamily.AUTOMATED_TOOL, UserAgentClassifier.classify("python-requests/2.31.0"));
		assertEquals(UserAgentFamily.AUTOMATED_TOOL, UserAgentClassifier.classify("curl/8.4.0"));
		assertEquals(UserAgentFamily.AUTOMATED_TOOL, UserAgentClassifier.classify("Wget/1.21.4"));
		assertEquals(UserAgentFamily.AUTOMATED_TOOL, UserAgentClassifier.classify("Scrapy/2.11.0 (+https://scrapy.org)"));
		assertEquals(UserAgentFamily.AUTOMATED_TOOL, UserAgentClassifier.classify("Go-http-client/1.1"));
		assertEquals(UserAgentFamily.AUTOMATED_TOOL, UserAgentClassifier.classify("okhttp/4.12.0"));
		assertEquals(UserAgentFamily.AUTOMATED_TOOL, UserAgentClassifier.classify("Apache-HttpClient/4.5.14 (Java/17.0.9)"));
		assertEquals(UserAgentFamily.AUTOMATED_TOOL, UserAgentClassifier.classify("PostmanRuntime/7.36.0"));
		assertEquals(UserAgentFamily.AUTOMATED_TOOL, UserAgentClassifier.classify("HeadlessChrome/120.0.0.0"));

		assertTrue(UserAgentFamily.AUTOMATED_TOOL.isAutomated());
	}

	@Test
	void testClassifyCrawlers() {
		assertEquals(UserAgentFamily.BOT_CRAWLER, UserAgentClassifier.classify(
				"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"));
		assertEquals(UserAgentFamily.BOT_CRAWLER, UserAgentClassifier.classify(
				"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"));
		assertEquals(UserAgentFamily.BOT_CRAWLER, UserAgentClassifier.classify(
				"ClaudeBot/1.0; (+https://www.anthropic.com/claudebot)"));
		assertEquals(UserAgentFamily.BOT_CRAWLER, UserAgentClassifier.classify(
				"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)"));

		assertTrue(UserAgentFamily.BOT_CRAWLER.isAutomated());
	}

	@Test
	void testClassifyEmptyAndUnknown() {
		assertEquals(UserAgentFamily.EMPTY, UserAgentClassifier.classify(null));
		assertEquals(UserAgentFamily.EMPTY, UserAgentClassifier.classify("   "));
		assertEquals(UserAgentFamily.UNKNOWN, UserAgentClassifier.classify("CustomEmbeddedDevice/1.0"));

		assertFalse(UserAgentFamily.CHROME_DESKTOP.isAutomated());
		assertFalse(UserAgentFamily.UNKNOWN.isAutomated());
	}
}

