package org.henbru.antidos.collector.enrichment;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.BrowserFamilyReference;
import org.henbru.antidos.collector.model.BrowserReferenceOverviewDto;
import org.henbru.antidos.collector.model.BrowserVersionLagAssessment;
import org.henbru.antidos.collector.model.UserAgentFamily;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BrowserVersionSyncServiceTest {

	private CollectorProperties properties;
	private BrowserVersionSyncService service;

	@BeforeEach
	void setUp() {
		properties = new CollectorProperties();
		service = new BrowserVersionSyncService(properties, new ObjectMapper());
		service.init();
	}

	@Test
	void testBundledBaselineLoadsAllFourFamiliesWithTopFiveVersions() {
		BrowserReferenceOverviewDto overview = service.getOverview();
		assertNotNull(overview);
		assertEquals(4, overview.families().size(), "Must contain Chrome, Edge, Firefox, and Safari");

		for (BrowserFamilyReference fam : overview.families()) {
			assertEquals(5, fam.topVersions().size(), fam.familyName() + " must have exactly 5 top versions");
			assertTrue(fam.latestStableMajor() > 0, fam.familyName() + " latest stable major must be positive");
			assertNotNull(fam.sourceName());
			assertNotNull(fam.sourceNotice());
		}

		BrowserFamilyReference safari = service.getFamilyReference("Safari");
		assertNotNull(safari);
		assertFalse(safari.automatedSync(), "Safari must use configurable matrix, not automated sync");
		assertTrue(safari.sourceNotice().contains("collector.browser-reference.safari-versions"));
	}

	@Test
	void testSafariConfigurableMatrixOverrides() {
		properties.getBrowserReference().setSafariVersions(List.of("27.0 STP", "26.1", "26.0", "18.2", "17.6"));
		BrowserVersionSyncService customService = new BrowserVersionSyncService(properties, new ObjectMapper());
		customService.init();

		BrowserFamilyReference safari = customService.getFamilyReference("Safari");
		assertNotNull(safari);
		assertEquals(5, safari.topVersions().size());
		assertEquals(26, safari.latestStableMajor());
		assertEquals(27, safari.maxPreviewMajor());
		assertEquals("27.0 STP", safari.topVersions().get(0).fullVersion());
		assertEquals("27.0 STP", safari.topVersions().get(0).displayVersion());
		assertTrue(safari.topVersions().get(0).isPreview());
		assertEquals("PREVIEW", safari.topVersions().get(0).channel());

		assertEquals("26.1", safari.topVersions().get(1).displayVersion());
		assertEquals("STABLE", safari.topVersions().get(1).channel());

		assertEquals("26.0", safari.topVersions().get(2).displayVersion());
		assertEquals("PREVIOUS", safari.topVersions().get(2).channel());

		assertEquals("18.2", safari.topVersions().get(3).displayVersion());
		assertEquals("SUPPORTED_LEGACY", safari.topVersions().get(3).channel());
	}

	@Test
	void testAssessChromeVersions() {
		// Current Stable (e.g. 157)
		var rStable = service.assessUserAgent(UserAgentFamily.CHROME_DESKTOP,
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36");
		assertEquals(BrowserVersionLagAssessment.CURRENT_STABLE, rStable.assessment());
		assertEquals(157, rStable.parsedMajorVersion());
		assertFalse(rStable.assessment().isSuspicious());

		// Plausible Preview: Beta / Canary (158 or 159)
		var rBeta = service.assessUserAgent(UserAgentFamily.CHROME_DESKTOP,
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.7200.5 Safari/537.36");
		assertEquals(BrowserVersionLagAssessment.PRE_RELEASE_PLAUSIBLE, rBeta.assessment());
		assertEquals(158, rBeta.parsedMajorVersion());
		assertFalse(rBeta.assessment().isSuspicious(), "Beta/Canary builds must not be flagged as suspicious");

		// Implausible Future Version (e.g. Chrome 185)
		var rFuture = service.assessUserAgent(UserAgentFamily.CHROME_DESKTOP,
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/185.0.0.0 Safari/537.36");
		assertEquals(BrowserVersionLagAssessment.IMPLAUSIBLE_FUTURE, rFuture.assessment());
		assertEquals(185, rFuture.parsedMajorVersion());
		assertTrue(rFuture.assessment().isSuspicious(), "Implausible future versions must be flagged as suspicious");

		// Obsolete Anomaly: Chrome 74 (>3 years / >30 versions lag)
		var rObsolete = service.assessUserAgent(UserAgentFamily.CHROME_DESKTOP,
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/537.36 Chrome/74.0.3729.157");
		assertEquals(BrowserVersionLagAssessment.OBSOLETE_ANOMALY, rObsolete.assessment());
		assertEquals(74, rObsolete.parsedMajorVersion());
		assertTrue(rObsolete.assessment().isSuspicious(), "Ancient browser versions must be flagged as anomalous");

		// Outdated Release: Chrome 146 (-11 versions lag)
		var rLag = service.assessUserAgent(UserAgentFamily.CHROME_DESKTOP,
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36");
		assertEquals(BrowserVersionLagAssessment.OUTDATED_LAG, rLag.assessment());
		assertEquals(146, rLag.parsedMajorVersion());
		assertEquals(11, rLag.versionLagMajors());
	}

	@Test
	void testAssessFirefoxVersions() {
		// Stable (153)
		var rStable = service.assessUserAgent(UserAgentFamily.FIREFOX_DESKTOP,
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0");
		assertEquals(BrowserVersionLagAssessment.CURRENT_STABLE, rStable.assessment());
		assertEquals(153, rStable.parsedMajorVersion());

		// Beta (154)
		var rBeta = service.assessUserAgent(UserAgentFamily.FIREFOX_DESKTOP,
				"Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0");
		assertEquals(BrowserVersionLagAssessment.PRE_RELEASE_PLAUSIBLE, rBeta.assessment());

		// ESR (140)
		var rEsr = service.assessUserAgent(UserAgentFamily.FIREFOX_DESKTOP,
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0");
		assertEquals(BrowserVersionLagAssessment.SUPPORTED_LEGACY, rEsr.assessment());
		assertFalse(rEsr.assessment().isSuspicious(), "Enterprise ESR versions must not be flagged as suspicious");
	}

	@Test
	void testAssessSafariVersions() {
		// Current Safari 26 (Tahoe)
		var rSafari26 = service.assessUserAgent(UserAgentFamily.SAFARI_DESKTOP,
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15");
		assertEquals(BrowserVersionLagAssessment.CURRENT_STABLE, rSafari26.assessment());
		assertEquals(26, rSafari26.parsedMajorVersion());

		// Legacy Safari 18 (Sequoia) - supported legacy OS generation
		var rSafari18 = service.assessUserAgent(UserAgentFamily.SAFARI_DESKTOP,
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15");
		assertEquals(BrowserVersionLagAssessment.SUPPORTED_LEGACY, rSafari18.assessment());
		assertEquals(18, rSafari18.parsedMajorVersion());

		// Plausible Preview Safari 27
		var rSafari27 = service.assessUserAgent(UserAgentFamily.SAFARI_DESKTOP,
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15");
		assertEquals(BrowserVersionLagAssessment.PRE_RELEASE_PLAUSIBLE, rSafari27.assessment());
		assertEquals(27, rSafari27.parsedMajorVersion());
	}

	@Test
	void testForgedReducedBrowserBuildDetection() {
		// Synthetic Chromium build randomizer violating .0.0.0 User-Agent Reduction
		var forgedChrome = service.assessUserAgent(UserAgentFamily.CHROME_DESKTOP,
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.6590.913 Safari/537.36");
		assertEquals(BrowserVersionLagAssessment.FORGED_BUILD_ANOMALY, forgedChrome.assessment());
		assertTrue(forgedChrome.assessment().isSuspicious());

		var forgedEdge = service.assessUserAgent(UserAgentFamily.EDGE_DESKTOP,
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.1234.5");
		assertEquals(BrowserVersionLagAssessment.FORGED_BUILD_ANOMALY, forgedEdge.assessment());

		// Legitimate Android WebView (; wv), iOS Chrome (CriOS), and Cronet apps remain exempt
		var webView = service.assessUserAgent(UserAgentFamily.CHROME_MOBILE,
				"Mozilla/5.0 (Linux; Android 16; SM-A536B Build/BP2A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/150.0.7123.88 Mobile Safari/537.36");
		assertNotEquals(BrowserVersionLagAssessment.FORGED_BUILD_ANOMALY, webView.assessment());

		var iosChrome = service.assessUserAgent(UserAgentFamily.CHROME_MOBILE,
				"Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/140.0.7339.101 Mobile/15E148 Safari/604.1");
		assertNotEquals(BrowserVersionLagAssessment.FORGED_BUILD_ANOMALY, iosChrome.assessment());

		assertFalse(BrowserVersionSyncService.hasForgedReducedBrowserBuild(
				UserAgentFamily.CHROME_MOBILE,
				"ExampleApp/165 (Linux; U; Android 16; Cronet/157.0.8103.30)",
				157));
	}
}
