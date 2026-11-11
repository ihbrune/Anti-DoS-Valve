package org.henbru.antidos.collector.model;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Summary of a User-Agent signature observed within an ASN's traffic.
 */
public record AsnUserAgentSummary(
		String userAgent,
		long totalRequests,
		double requestPct,
		int eventCount,
		int distinctSubnets,
		String browserFamily,
		boolean suspicious
) {
	private static final Pattern CHROME_VER = Pattern.compile("(?:Chrome|CriOS)/(\\d+)");
	private static final Pattern FIREFOX_VER = Pattern.compile("(?:Firefox|FxiOS)/(\\d+)");
	private static final Pattern EDGE_VER = Pattern.compile("Edg(?:e|A|iOS)?/(\\d+)");

	public static AsnUserAgentSummary of(
			String userAgent,
			long totalRequests,
			long grandTotalRequests,
			int eventCount,
			int distinctSubnets
	) {
		double pct = grandTotalRequests > 0 ? (totalRequests * 100.0 / grandTotalRequests) : 0.0;
		double roundedPct = Math.round(pct * 10.0) / 10.0;
		String family = detectFamily(userAgent);
		boolean susp = checkSuspicious(userAgent, family);
		return new AsnUserAgentSummary(userAgent, totalRequests, roundedPct, eventCount, distinctSubnets, family, susp);
	}

	public boolean isCaptured() {
		return userAgent != null && !userAgent.isBlank() && !userAgent.startsWith("(");
	}

	public static String detectFamily(String ua) {
		if (ua == null || ua.isBlank() || ua.startsWith("(")) {
			return "None";
		}
		String lower = ua.toLowerCase();
		if (lower.contains("python") || lower.contains("curl") || lower.contains("scrapy")
				|| lower.contains("aiohttp") || lower.contains("bot") || lower.contains("crawler")
				|| lower.contains("spider") || lower.contains("httpclient") || lower.contains("go-http")
				|| lower.contains("postman") || lower.contains("wget")) {
			return "Bot / Script";
		}
		Matcher edgeMatcher = EDGE_VER.matcher(ua);
		if (edgeMatcher.find()) {
			return "Edge " + edgeMatcher.group(1);
		}
		Matcher chromeMatcher = CHROME_VER.matcher(ua);
		if (chromeMatcher.find()) {
			return "Chrome " + chromeMatcher.group(1);
		}
		Matcher ffMatcher = FIREFOX_VER.matcher(ua);
		if (ffMatcher.find()) {
			return "Firefox " + ffMatcher.group(1);
		}
		if (ua.contains("Safari/") && !ua.contains("Chrome/")) {
			return "Safari";
		}
		if (ua.contains("Mozilla/")) {
			return "Browser";
		}
		return "Custom / Tool";
	}

	public static boolean checkSuspicious(String ua, String family) {
		if (ua == null || ua.isBlank()) {
			return false;
		}
		String lower = ua.toLowerCase();
		if (lower.contains("python") || lower.contains("curl") || lower.contains("scrapy") || lower.contains("aiohttp")) {
			return true;
		}
		// Versions beyond realistic current releases (e.g. Chrome 140+, Firefox 140+)
		// indicating synthetic/spoofed UA generator used by scrapers
		Matcher chromeMatcher = CHROME_VER.matcher(ua);
		if (chromeMatcher.find()) {
			try {
				int ver = Integer.parseInt(chromeMatcher.group(1));
				if (ver >= 140) {
					return true;
				}
			} catch (NumberFormatException ignored) {
			}
		}
		Matcher ffMatcher = FIREFOX_VER.matcher(ua);
		if (ffMatcher.find()) {
			try {
				int ver = Integer.parseInt(ffMatcher.group(1));
				if (ver >= 140) {
					return true;
				}
			} catch (NumberFormatException ignored) {
			}
		}
		return false;
	}
}

