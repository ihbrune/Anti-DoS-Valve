package org.henbru.antidos.collector.enrichment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.BrowserFamilyReference;
import org.henbru.antidos.collector.model.BrowserReferenceOverviewDto;
import org.henbru.antidos.collector.model.BrowserVersionEntry;
import org.henbru.antidos.collector.model.BrowserVersionLagAssessment;
import org.henbru.antidos.collector.model.UserAgentFamily;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Service providing authoritative release version intelligence for major web browsers
 * (Chrome, Edge, Firefox, Safari) from official live sources and configurable release matrices.
 */
@Service
public class BrowserVersionSyncService {

	private static final Logger log = LoggerFactory.getLogger(BrowserVersionSyncService.class);

	private static final Pattern CHROME_VERSION_PATTERN = Pattern.compile("(?:Chrome|Chromium|CriOS)/(\\d+)");
	private static final Pattern EDGE_VERSION_PATTERN = Pattern.compile("(?:Edg|Edge|EdgA|EdgiOS)/(\\d+)");
	private static final Pattern FIREFOX_VERSION_PATTERN = Pattern.compile("(?:Firefox|FxiOS)/(\\d+)");
	private static final Pattern SAFARI_VERSION_PATTERN = Pattern.compile("Version/(\\d+)");

	private final CollectorProperties properties;
	private final ObjectMapper objectMapper;
	private final HttpClient httpClient;

	private final Map<String, BrowserFamilyReference> familyReferences = new ConcurrentHashMap<>();
	private Instant lastSynced = null;
	private boolean lastSyncSuccessful = false;
	private String lastSyncMessage = "Initialized from bundled baseline";

	@Autowired
	public BrowserVersionSyncService(CollectorProperties properties, ObjectMapper objectMapper) {
		this.properties = properties;
		this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
		this.httpClient = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(8))
				.followRedirects(HttpClient.Redirect.NORMAL)
				.build();
	}

	@PostConstruct
	public void init() {
		loadBundledBaseline();
		applyConfiguredSafariMatrix();
		log.info("BrowserVersionSyncService initialized with {} browser families", familyReferences.size());
	}

	/**
	 * Daily scheduled background sync of browser release intelligence feeds.
	 */
	@Scheduled(fixedDelay = 86400000L, initialDelay = 60000L)
	public void scheduledSync() {
		if (properties != null && properties.getBrowserReference().isEnabled()) {
			syncAll();
		}
	}

	/**
	 * Synchronizes live release versions from official Google and Mozilla APIs,
	 * aligning with the configurable Safari OS matrix.
	 */
	public synchronized void syncAll() {
		boolean anySuccess = false;
		List<String> messages = new ArrayList<>();

		// 1. Google Chrome & Chromium
		try {
			boolean chromeOk = syncChrome();
			if (chromeOk) {
				anySuccess = true;
				messages.add("Chrome & Edge synchronized via Google Version History API");
			}
		} catch (Exception e) {
			log.warn("Failed to sync Chrome version history: {}", e.getMessage());
			messages.add("Chrome sync failed: " + e.getMessage());
		}

		// 2. Mozilla Firefox
		try {
			boolean firefoxOk = syncFirefox();
			if (firefoxOk) {
				anySuccess = true;
				messages.add("Firefox synchronized via Mozilla Product Details API");
			}
		} catch (Exception e) {
			log.warn("Failed to sync Firefox version history: {}", e.getMessage());
			messages.add("Firefox sync failed: " + e.getMessage());
		}

		// 3. Apple Safari (Apply configured matrix)
		applyConfiguredSafariMatrix();

		this.lastSynced = Instant.now();
		this.lastSyncSuccessful = anySuccess;
		this.lastSyncMessage = String.join(" | ", messages);
	}

	private boolean syncChrome() {
		String url = properties.getBrowserReference().getChromeApiUrl();
		if (url == null || url.isBlank()) {
			return false;
		}

		try {
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(url))
					.header("User-Agent", "AntiDoS-Collector-BrowserSync/1.0")
					.timeout(Duration.ofSeconds(10))
					.GET()
					.build();

			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() >= 200 && response.statusCode() < 300) {
				JsonNode root = objectMapper.readTree(response.body());
				JsonNode versionsNode = root.get("versions");
				if (versionsNode != null && versionsNode.isArray()) {
					parseGoogleChromeVersions(versionsNode);
					return true;
				}
			}
		} catch (Exception e) {
			log.debug("Chrome sync error: {}", e.getMessage());
		}
		return false;
	}

	private void parseGoogleChromeVersions(JsonNode versionsNode) {
		int highestStable = 0;
		int highestBeta = 0;
		int highestCanary = 0;
		int highestExtended = 0;

		String stableFull = null;
		String betaFull = null;
		String canaryFull = null;
		String extendedFull = null;

		for (JsonNode item : versionsNode) {
			String name = item.has("name") ? item.get("name").asText("") : "";
			String version = item.has("version") ? item.get("version").asText("") : "";
			if (version.isBlank()) continue;

			int major = parseMajorFromVersionString(version);
			if (major <= 0) continue;

			if (name.contains("/channels/stable/")) {
				if (major > highestStable) {
					highestStable = major;
					stableFull = version;
				}
			} else if (name.contains("/channels/beta/")) {
				if (major > highestBeta) {
					highestBeta = major;
					betaFull = version;
				}
			} else if (name.contains("/channels/canary/") || name.contains("/channels/dev/")) {
				if (major > highestCanary) {
					highestCanary = major;
					canaryFull = version;
				}
			} else if (name.contains("/channels/extended/")) {
				if (major > highestExtended) {
					highestExtended = major;
					extendedFull = version;
				}
			}
		}

		if (highestStable > 0) {
			if (highestCanary <= highestStable) highestCanary = highestStable + 2;
			if (highestBeta <= highestStable) highestBeta = highestStable + 1;
			if (highestExtended <= 0) highestExtended = highestStable - 1;

			List<BrowserVersionEntry> chromeVersions = new ArrayList<>();
			chromeVersions.add(new BrowserVersionEntry("Chrome", highestCanary, canaryFull != null ? canaryFull : (highestCanary + ".0.0.0"), "CANARY", null, "GOOGLE_API", true, false));
			chromeVersions.add(new BrowserVersionEntry("Chrome", highestBeta, betaFull != null ? betaFull : (highestBeta + ".0.0.0"), "BETA", null, "GOOGLE_API", true, false));
			chromeVersions.add(new BrowserVersionEntry("Chrome", highestStable, stableFull != null ? stableFull : (highestStable + ".0.0.0"), "STABLE", null, "GOOGLE_API", false, false));
			chromeVersions.add(new BrowserVersionEntry("Chrome", highestExtended, extendedFull != null ? extendedFull : (highestExtended + ".0.0.0"), "EXTENDED", null, "GOOGLE_API", false, true));
			chromeVersions.add(new BrowserVersionEntry("Chrome", highestStable - 2, (highestStable - 2) + ".0.0.0", "PREVIOUS", null, "GOOGLE_API", false, true));

			BrowserFamilyReference chromeRef = new BrowserFamilyReference(
					"Chrome", "&#x1F310;", highestStable, highestCanary, highestExtended,
					"Google Version History API", true, "Live automated feed via Google Version History API",
					Instant.now(), chromeVersions
			);
			familyReferences.put("Chrome", chromeRef);

			// Edge follows Chromium Core
			List<BrowserVersionEntry> edgeVersions = new ArrayList<>();
			edgeVersions.add(new BrowserVersionEntry("Edge", highestCanary, highestCanary + ".0.0.0", "CANARY", null, "GOOGLE_API", true, false));
			edgeVersions.add(new BrowserVersionEntry("Edge", highestBeta, highestBeta + ".0.0.0", "BETA", null, "GOOGLE_API", true, false));
			edgeVersions.add(new BrowserVersionEntry("Edge", highestStable, highestStable + ".0.0.0", "STABLE", null, "GOOGLE_API", false, false));
			edgeVersions.add(new BrowserVersionEntry("Edge", highestExtended, highestExtended + ".0.0.0", "EXTENDED", null, "GOOGLE_API", false, true));
			edgeVersions.add(new BrowserVersionEntry("Edge", highestStable - 2, (highestStable - 2) + ".0.0.0", "PREVIOUS", null, "GOOGLE_API", false, true));

			BrowserFamilyReference edgeRef = new BrowserFamilyReference(
					"Edge", "&#x1F310;", highestStable, highestCanary, highestExtended,
					"Chromium Core Alignment", true, "Synchronized with Chromium release schedule",
					Instant.now(), edgeVersions
			);
			familyReferences.put("Edge", edgeRef);
		}
	}

	private boolean syncFirefox() {
		String url = properties.getBrowserReference().getFirefoxApiUrl();
		if (url == null || url.isBlank()) {
			return false;
		}

		try {
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(url))
					.header("User-Agent", "AntiDoS-Collector-BrowserSync/1.0")
					.timeout(Duration.ofSeconds(10))
					.GET()
					.build();

			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() >= 200 && response.statusCode() < 300) {
				JsonNode root = objectMapper.readTree(response.body());
				String stableStr = root.has("LATEST_FIREFOX_VERSION") ? root.get("LATEST_FIREFOX_VERSION").asText("") : "";
				String betaStr = root.has("LATEST_FIREFOX_DEVEL_VERSION") ? root.get("LATEST_FIREFOX_DEVEL_VERSION").asText("") : "";
				String nightlyStr = root.has("LATEST_FIREFOX_NIGHTLY_VERSION") ? root.get("LATEST_FIREFOX_NIGHTLY_VERSION").asText("") : "";
				String esrStr = root.has("FIREFOX_ESR") ? root.get("FIREFOX_ESR").asText("") : "";

				int stableMajor = parseMajorFromVersionString(stableStr);
				if (stableMajor > 0) {
					int betaMajor = parseMajorFromVersionString(betaStr);
					int nightlyMajor = parseMajorFromVersionString(nightlyStr);
					int esrMajor = parseMajorFromVersionString(esrStr);

					if (nightlyMajor <= stableMajor) nightlyMajor = stableMajor + 2;
					if (betaMajor <= stableMajor) betaMajor = stableMajor + 1;
					if (esrMajor <= 0) esrMajor = stableMajor - 13;

					List<BrowserVersionEntry> ffVersions = new ArrayList<>();
					ffVersions.add(new BrowserVersionEntry("Firefox", nightlyMajor, !nightlyStr.isBlank() ? nightlyStr : (nightlyMajor + ".0a1"), "NIGHTLY", null, "MOZILLA_API", true, false));
					ffVersions.add(new BrowserVersionEntry("Firefox", betaMajor, !betaStr.isBlank() ? betaStr : (betaMajor + ".0b9"), "BETA", null, "MOZILLA_API", true, false));
					ffVersions.add(new BrowserVersionEntry("Firefox", stableMajor, stableStr, "STABLE", null, "MOZILLA_API", false, false));
					ffVersions.add(new BrowserVersionEntry("Firefox", stableMajor - 1, (stableMajor - 1) + ".0", "PREVIOUS", null, "MOZILLA_API", false, true));
					ffVersions.add(new BrowserVersionEntry("Firefox", esrMajor, !esrStr.isBlank() ? esrStr : (esrMajor + ".0esr"), "ESR", null, "MOZILLA_API", false, true));

					BrowserFamilyReference ffRef = new BrowserFamilyReference(
							"Firefox", "&#x1F98A;", stableMajor, nightlyMajor, esrMajor,
							"Mozilla Product Details API", true, "Live automated feed via Mozilla Product Details API",
							Instant.now(), ffVersions
					);
					familyReferences.put("Firefox", ffRef);
					return true;
				}
			}
		} catch (Exception e) {
			log.debug("Firefox sync error: {}", e.getMessage());
		}
		return false;
	}

	private void applyConfiguredSafariMatrix() {
		List<String> configured = properties != null ? properties.getBrowserReference().getSafariVersions() : null;
		if (configured == null || configured.isEmpty()) {
			configured = List.of("26.2 STP", "26.1", "26.0", "18.2", "17.6");
		}

		List<BrowserVersionEntry> versions = new ArrayList<>();
		int latestStable = 26;
		int maxPreview = 26;
		int minSupported = 17;

		boolean foundStable = false;
		for (int i = 0; i < configured.size() && i < 5; i++) {
			String verStr = configured.get(i).trim();
			int major = parseMajorFromVersionString(verStr);
			if (major <= 0) continue;

			String channel;
			boolean isPreview = false;
			boolean isLegacy = false;

			String lower = verStr.toLowerCase(Locale.ROOT);
			if (lower.contains("stp") || lower.contains("preview") || lower.contains("beta")) {
				channel = "PREVIEW";
				isPreview = true;
				if (major > maxPreview) {
					maxPreview = major;
				}
			} else if (!foundStable) {
				channel = "STABLE";
				foundStable = true;
				latestStable = major;
				if (latestStable > maxPreview) {
					maxPreview = latestStable;
				}
			} else if (major == latestStable) {
				channel = "PREVIOUS";
				isLegacy = true;
			} else {
				channel = "SUPPORTED_LEGACY";
				isLegacy = true;
			}

			if (major < minSupported) {
				minSupported = major;
			}

			versions.add(new BrowserVersionEntry(
					"Safari", major, verStr, channel, null, "CONFIGURED_MATRIX", isPreview, isLegacy
			));
		}

		if (versions.isEmpty()) {
			versions.add(new BrowserVersionEntry("Safari", 26, "26.1", "STABLE", null, "CONFIGURED_MATRIX", false, false));
		}

		BrowserFamilyReference safariRef = new BrowserFamilyReference(
				"Safari", "&#x1F9ED;", latestStable, maxPreview, minSupported,
				"Configurable OS Matrix", false,
				"Static OS-bound matrix. Configurable via collector.browser-reference.safari-versions without code changes.",
				Instant.now(), versions
		);
		familyReferences.put("Safari", safariRef);
	}

	private void loadBundledBaseline() {
		try (InputStream is = getClass().getResourceAsStream("/browser-versions-baseline.json")) {
			if (is != null) {
				JsonNode root = objectMapper.readTree(is);
				JsonNode familiesNode = root.get("families");
				if (familiesNode != null && familiesNode.isArray()) {
					for (JsonNode famNode : familiesNode) {
						String familyName = famNode.path("familyName").asText("");
						String icon = famNode.path("icon").asText("&#x1F310;");
						int latestStable = famNode.path("latestStableMajor").asInt(100);
						int maxPreview = famNode.path("maxPreviewMajor").asInt(latestStable + 2);
						int minSupported = famNode.path("minSupportedMajor").asInt(latestStable - 15);
						String sourceName = famNode.path("sourceName").asText("Bundled Baseline");
						boolean autoSync = famNode.path("automatedSync").asBoolean(true);
						String sourceNotice = famNode.path("sourceNotice").asText("");

						List<BrowserVersionEntry> versions = new ArrayList<>();
						JsonNode versionsArr = famNode.get("topVersions");
						if (versionsArr != null && versionsArr.isArray()) {
							for (JsonNode vNode : versionsArr) {
								versions.add(new BrowserVersionEntry(
										vNode.path("family").asText(familyName),
										vNode.path("majorVersion").asInt(),
										vNode.path("fullVersion").asText(""),
										vNode.path("channel").asText("STABLE"),
										vNode.path("releaseDate").asText(null),
										vNode.path("source").asText("BASELINE"),
										vNode.path("isPreview").asBoolean(false),
										vNode.path("isSupportedLegacy").asBoolean(false)
								));
							}
						}
						familyReferences.put(familyName, new BrowserFamilyReference(
								familyName, icon, latestStable, maxPreview, minSupported,
								sourceName, autoSync, sourceNotice, Instant.now(), versions
						));
					}
				}
			}
		} catch (Exception e) {
			log.warn("Failed to load bundled browser versions baseline: {}", e.getMessage());
		}
	}

	public BrowserReferenceOverviewDto getOverview() {
		List<BrowserFamilyReference> list = new ArrayList<>();
		addIfPresent(list, "Chrome");
		addIfPresent(list, "Edge");
		addIfPresent(list, "Firefox");
		addIfPresent(list, "Safari");

		return new BrowserReferenceOverviewDto(
				list,
				lastSynced != null ? lastSynced : Instant.now(),
				lastSyncSuccessful,
				lastSyncMessage
		);
	}

	private void addIfPresent(List<BrowserFamilyReference> target, String key) {
		BrowserFamilyReference ref = familyReferences.get(key);
		if (ref != null) target.add(ref);
	}

	public BrowserFamilyReference getFamilyReference(String family) {
		return familyReferences.get(family);
	}

	/**
	 * Assesses an observed User-Agent version against authoritative release references.
	 */
	public UserAgentVersionAssessmentResult assessUserAgent(UserAgentFamily family, String userAgent) {
		if (userAgent == null || userAgent.isBlank() || family == null) {
			return new UserAgentVersionAssessmentResult(BrowserVersionLagAssessment.UNTRACKED, null, null, "Unknown");
		}

		String targetFamily;
		int majorVersion = -1;

		if (family == UserAgentFamily.CHROME_DESKTOP || family == UserAgentFamily.CHROME_MOBILE) {
			targetFamily = "Chrome";
			majorVersion = extractVersionWithRegex(userAgent, CHROME_VERSION_PATTERN);
		} else if (family == UserAgentFamily.EDGE_DESKTOP || family == UserAgentFamily.EDGE_MOBILE) {
			targetFamily = "Edge";
			majorVersion = extractVersionWithRegex(userAgent, EDGE_VERSION_PATTERN);
			if (majorVersion <= 0) {
				majorVersion = extractVersionWithRegex(userAgent, CHROME_VERSION_PATTERN);
			}
		} else if (family == UserAgentFamily.FIREFOX_DESKTOP || family == UserAgentFamily.FIREFOX_MOBILE) {
			targetFamily = "Firefox";
			majorVersion = extractVersionWithRegex(userAgent, FIREFOX_VERSION_PATTERN);
		} else if (family == UserAgentFamily.SAFARI_DESKTOP || family == UserAgentFamily.SAFARI_MOBILE) {
			targetFamily = "Safari";
			majorVersion = extractVersionWithRegex(userAgent, SAFARI_VERSION_PATTERN);
		} else {
			return new UserAgentVersionAssessmentResult(BrowserVersionLagAssessment.UNTRACKED, null, null, family.displayName());
		}

		if (majorVersion <= 0) {
			return new UserAgentVersionAssessmentResult(BrowserVersionLagAssessment.UNTRACKED, null, null, targetFamily);
		}

		BrowserFamilyReference ref = familyReferences.get(targetFamily);
		if (ref == null) {
			return new UserAgentVersionAssessmentResult(BrowserVersionLagAssessment.UNTRACKED, majorVersion, null, targetFamily);
		}

		int lag = ref.latestStableMajor() - majorVersion;

		// 1. Plausible Preview (Beta, Dev, Canary, STP)
		if (majorVersion > ref.latestStableMajor() && majorVersion <= (ref.maxPreviewMajor() + 1)) {
			return new UserAgentVersionAssessmentResult(BrowserVersionLagAssessment.PRE_RELEASE_PLAUSIBLE, majorVersion, lag, targetFamily);
		}

		// 2. Implausible Future Version (synthetic forgery)
		if (majorVersion > (ref.maxPreviewMajor() + 2)) {
			return new UserAgentVersionAssessmentResult(BrowserVersionLagAssessment.IMPLAUSIBLE_FUTURE, majorVersion, lag, targetFamily);
		}

		// 3. Current Stable
		if (majorVersion >= (ref.latestStableMajor() - 1)) {
			return new UserAgentVersionAssessmentResult(BrowserVersionLagAssessment.CURRENT_STABLE, majorVersion, lag, targetFamily);
		}

		// 4. Supported Legacy (ESR or preceding OS generation)
		if (majorVersion >= ref.minSupportedMajor()) {
			return new UserAgentVersionAssessmentResult(BrowserVersionLagAssessment.SUPPORTED_LEGACY, majorVersion, lag, targetFamily);
		}

		// 5. Obsolete Anomaly (> 30 versions / > 3 years behind)
		if (lag >= 30) {
			return new UserAgentVersionAssessmentResult(BrowserVersionLagAssessment.OBSOLETE_ANOMALY, majorVersion, lag, targetFamily);
		}

		// 6. Outdated Lag
		return new UserAgentVersionAssessmentResult(BrowserVersionLagAssessment.OUTDATED_LAG, majorVersion, lag, targetFamily);
	}

	private int extractVersionWithRegex(String ua, Pattern pattern) {
		Matcher m = pattern.matcher(ua);
		if (m.find()) {
			try {
				return Integer.parseInt(m.group(1));
			} catch (NumberFormatException ignored) {}
		}
		return -1;
	}

	private int parseMajorFromVersionString(String verStr) {
		if (verStr == null) return -1;
		int dotIdx = verStr.indexOf('.');
		String numPart = dotIdx >= 0 ? verStr.substring(0, dotIdx) : verStr;
		numPart = numPart.replaceAll("[^0-9]", "");
		if (!numPart.isEmpty()) {
			try {
				return Integer.parseInt(numPart);
			} catch (NumberFormatException ignored) {}
		}
		return -1;
	}

	public record UserAgentVersionAssessmentResult(
			BrowserVersionLagAssessment assessment,
			Integer parsedMajorVersion,
			Integer versionLagMajors,
			String browserFamily
	) {}
}
