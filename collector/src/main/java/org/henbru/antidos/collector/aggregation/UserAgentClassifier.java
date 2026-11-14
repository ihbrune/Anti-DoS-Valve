package org.henbru.antidos.collector.aggregation;

import java.util.Locale;
import org.henbru.antidos.collector.model.UserAgentFamily;

/**
 * Lightweight, zero-dependency classifier mapping raw User-Agent headers
 * to semantic families (Desktop/Mobile browsers, HTTP libraries, crawlers).
 */
public final class UserAgentClassifier {

	private UserAgentClassifier() {
	}

	public static UserAgentFamily classify(String ua) {
		if (ua == null || ua.isBlank()) {
			return UserAgentFamily.EMPTY;
		}
		String lower = ua.toLowerCase(Locale.ROOT);

		// 1. Automated Tools, HTTP client libraries, and script engines
		if (lower.contains("python") || lower.contains("requests") || lower.contains("aiohttp")
				|| lower.contains("curl/") || lower.contains("wget/") || lower.contains("scrapy")
				|| lower.contains("go-http-client") || lower.contains("okhttp")
				|| lower.contains("java/") || lower.contains("apache-httpclient")
				|| lower.contains("postman") || lower.contains("libwww-perl")
				|| lower.contains("urllib") || lower.contains("axios")
				|| lower.contains("node-fetch") || lower.contains("got/")
				|| lower.contains("headless") || lower.contains("puppeteer")
				|| lower.contains("selenium") || lower.contains("playwright")
				|| lower.contains("httpclient") || lower.contains("colly")) {
			return UserAgentFamily.AUTOMATED_TOOL;
		}

		// 2. Search Engine & AI Web Crawlers
		if (lower.contains("googlebot") || lower.contains("bingbot") || lower.contains("yandex")
				|| lower.contains("bytespider") || lower.contains("claudebot") || lower.contains("gptbot")
				|| lower.contains("chatgpt") || lower.contains("applebot") || lower.contains("baiduspider")
				|| lower.contains("duckduckbot") || lower.contains("facebookexternalhit")
				|| lower.contains("semrush") || lower.contains("ahrefs") || lower.contains("mj12bot")
				|| lower.contains("dotbot") || lower.contains("seznambot") || lower.contains("linkupbot")
				|| lower.contains("crawler")) {
			return UserAgentFamily.BOT_CRAWLER;
		}

		// 3. Microsoft Edge
		if (lower.contains("edg/") || lower.contains("edge/")) {
			return (lower.contains("mobile") || lower.contains("android") || lower.contains("iphone"))
					? UserAgentFamily.EDGE_MOBILE : UserAgentFamily.EDGE_DESKTOP;
		}

		// 4. Opera
		if (lower.contains("opr/") || lower.contains("opera")) {
			return UserAgentFamily.OPERA;
		}

		// 5. Mozilla Firefox
		if (lower.contains("firefox") || lower.contains("fxios")) {
			return (lower.contains("mobile") || lower.contains("android") || lower.contains("iphone"))
					? UserAgentFamily.FIREFOX_MOBILE : UserAgentFamily.FIREFOX_DESKTOP;
		}

		// 6. Google Chrome / Chromium (must precede Safari check)
		if (lower.contains("chrome") || lower.contains("chromium") || lower.contains("crios")) {
			return (lower.contains("mobile") || lower.contains("android") || lower.contains("iphone"))
					? UserAgentFamily.CHROME_MOBILE : UserAgentFamily.CHROME_DESKTOP;
		}

		// 7. Apple Safari (only if not Chrome/Chromium)
		if (lower.contains("safari") || lower.contains("applewebkit")) {
			return (lower.contains("mobile") || lower.contains("iphone") || lower.contains("ipad"))
					? UserAgentFamily.SAFARI_MOBILE : UserAgentFamily.SAFARI_DESKTOP;
		}

		// 8. Other mobile browsers
		if (lower.contains("samsungbrowser") || lower.contains("ucbrowser")) {
			return UserAgentFamily.OTHER_BROWSER;
		}

		return UserAgentFamily.UNKNOWN;
	}
}

