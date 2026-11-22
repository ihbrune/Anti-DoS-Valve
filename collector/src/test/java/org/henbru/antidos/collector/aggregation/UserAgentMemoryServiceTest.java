package org.henbru.antidos.collector.aggregation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import org.henbru.antidos.collector.aggregation.UserAgentMemoryService.EvaluationInput;
import org.henbru.antidos.collector.aggregation.UserAgentMemoryService.EvaluationOutcome;
import org.henbru.antidos.collector.config.CollectorMode;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.CollectorTokenRole;
import org.henbru.antidos.collector.model.ClientEvent;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.EffectiveUaHeuristicSettings;
import org.henbru.antidos.collector.model.EnrichmentStatus;
import org.henbru.antidos.collector.model.UserAgentAutoVerdict;
import org.henbru.antidos.collector.model.UserAgentDrilldownDto;
import org.henbru.antidos.collector.model.UserAgentFamily;
import org.henbru.antidos.collector.model.UserAgentManualOverride;
import org.henbru.antidos.collector.model.UserAgentProfile;
import org.henbru.antidos.collector.security.CollectorAuthContext;
import org.henbru.antidos.collector.storage.ClientEventRepository;
import org.henbru.antidos.collector.storage.UserAgentMemoryRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@SuppressWarnings("null")
class UserAgentMemoryServiceTest {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private CollectorProperties properties;

	@Autowired
	private ClientEventRepository clientEventRepository;

	@Autowired
	private UserAgentMemoryRepository memoryRepository;

	@Autowired
	private UserAgentMemoryService memoryService;

	@BeforeEach
	void setUp() {
		CollectorAuthContext.clear();
		properties.setMode(CollectorMode.FULL);
		jdbcTemplate.update("DELETE FROM user_agent_hourly_rollups");
		jdbcTemplate.update("DELETE FROM dim_user_agent");
		jdbcTemplate.update("DELETE FROM client_events");
		jdbcTemplate.update("DELETE FROM system_settings WHERE setting_key LIKE 'ua.heuristic.%'");
	}

	@AfterEach
	void tearDown() {
		CollectorAuthContext.clear();
		properties.setMode(CollectorMode.FULL);
		jdbcTemplate.update("DELETE FROM system_settings WHERE setting_key LIKE 'ua.heuristic.%'");
	}

	@Test
	void testStage0ImmunityBarriersProtectInternalSearchEngineAndAuthTraffic() {
		EffectiveUaHeuristicSettings cfg = EffectiveUaHeuristicSettings.defaults();

		// 1. Internal/Campus network legacy device (e.g., ancient signage display with 0 auth) -> IMMUNE_INTERNAL
		EvaluationOutcome internalOutcome = memoryService.evaluateVerdict(new EvaluationInput(
				"Mozilla/5.0 (iPad; CPU OS 12_5_7 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
				UserAgentFamily.SAFARI_MOBILE,
				1500L, 40, 0, 0, 1, 1,
				0, 0L, 1500L, 0L, 0L, 0L, 0L, 0L, false, null
		), cfg);
		assertEquals(UserAgentAutoVerdict.IMMUNE_INTERNAL, internalOutcome.verdict());
		assertTrue(internalOutcome.verdict().isImmune());
		assertFalse(internalOutcome.verdict().isSuspicious());

		// 2. Verified Search Engine crawler -> IMMUNE_SEARCH_ENGINE (even though family is BOT_CRAWLER)
		EvaluationOutcome searchEngineOutcome = memoryService.evaluateVerdict(new EvaluationInput(
				"Mozilla/5.0 (compatible; ExampleSearchBot/1.0)",
				UserAgentFamily.BOT_CRAWLER,
				4000L, 120, 0, 0, 10, 1,
				0, 0L, 0L, 3800L, 0L, 0L, 0L, 0L, false, null
		), cfg);
		assertEquals(UserAgentAutoVerdict.IMMUNE_SEARCH_ENGINE, searchEngineOutcome.verdict());
		assertTrue(searchEngineOutcome.verdict().isImmune());

		// 3. Mobile App (`Dart/3.12`) with automated family signature BUT authenticated sessions -> IMMUNE_AUTHENTICATED
		EvaluationOutcome authAppOutcome = memoryService.evaluateVerdict(new EvaluationInput(
				"Dart/3.12 (dart:io)",
				UserAgentFamily.AUTOMATED_TOOL,
				8000L, 250, 0, 0, 80, 15,
				12, 240L, 0L, 0L, 0L, 7500L, 0L, 0L, false, null
		), cfg);
		assertEquals(UserAgentAutoVerdict.IMMUNE_AUTHENTICATED, authAppOutcome.verdict());
		assertTrue(authAppOutcome.verdict().isImmune());
		assertFalse(authAppOutcome.verdict().isSuspicious());
	}

	@Test
	void testThreePillarHeuristicDetectsUltraSpreadCorrelatedAndDatacenterScrapers() {
		EffectiveUaHeuristicSettings cfg = EffectiveUaHeuristicSettings.defaults();

		// Pillar 1: Ultra-spread residential proxy botnet (zero auth, high subnet/ASN spread, thin requests per slot)
		EvaluationOutcome pillar1 = memoryService.evaluateVerdict(new EvaluationInput(
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/142.0.0.0 Safari/537.36",
				UserAgentFamily.CHROME_DESKTOP,
				15000L, 2200, 10, 5, 420, 65,
				0, 0L, 0L, 0L, 800L, 14200L, 0L, 0L, false, null
		), cfg);
		assertEquals(UserAgentAutoVerdict.SUSPICIOUS_ULTRA_SPREAD, pillar1.verdict());
		assertTrue(pillar1.verdict().isSuspicious());

		// Pillar 2: Guilt by Association (high mitigated ASN overlap and incident ratio, zero auth)
		EvaluationOutcome pillar2 = memoryService.evaluateVerdict(new EvaluationInput(
				"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/141.0.0.0 Safari/537.36",
				UserAgentFamily.CHROME_DESKTOP,
				3200L, 80, 35, 5, 18, 4,
				0, 0L, 0L, 0L, 200L, 2800L, 1800L, 0L, true, "AS64512"
		), cfg);
		assertEquals(UserAgentAutoVerdict.SUSPICIOUS_CORRELATED, pillar2.verdict());
		assertTrue(pillar2.verdict().isSuspicious());

		// Pillar 3: Datacenter Zero-Auth Scraper
		EvaluationOutcome pillar3 = memoryService.evaluateVerdict(new EvaluationInput(
				"Mozilla/5.0 (compatible; CloudScraper/2.0)",
				UserAgentFamily.OTHER_BROWSER,
				7500L, 150, 0, 0, 22, 6,
				0, 0L, 0L, 0L, 6900L, 600L, 0L, 0L, false, null
		), cfg);
		assertEquals(UserAgentAutoVerdict.SUSPICIOUS_DATACENTER, pillar3.verdict());
		assertTrue(pillar3.verdict().isSuspicious());
	}

	@Test
	void testHourlyRollupsAndNonOverwritableManualOverridesWithDualStatus() {
		Instant now = Instant.now().truncatedTo(ChronoUnit.HOURS);
		Instant bucket1Start = now.minus(2, ChronoUnit.HOURS);
		Instant bucket1End = now.minus(1, ChronoUnit.HOURS);
		Instant t1 = bucket1Start.plus(15, ChronoUnit.MINUTES);

		String scraperUa = "CustomScraperBot/1.0 (+https://example.com/bot)";
		String internalDisplayUa = "Mozilla/5.0 (iPad; CPU OS 12_5_7 like Mac OS X) Safari/604.1";
		String mobileAppUa = "Dart/3.12 (dart:io)";

		ClientEvent eScraper = new ClientEvent(
				null, "Node-A", "Limiter", 101L, t1, "198.51.100.10",
				4, 24, null, null, null, null, "198.51.100.0/24",
				6200, 0, false, ClientEvent.STATUS_ACTIVE, true, t1,
				64520L, "Cloud Host Alpha", "DE", ClientType.DATACENTER, EnrichmentStatus.ENRICHED,
				null, 1, 1, 0, 0, 0, "GET", "/portal/course/catalog", scraperUa, false
		);
		ClientEvent eInternal = new ClientEvent(
				null, "Node-A", "Limiter", 102L, t1, "10.20.30.40",
				4, 24, null, null, null, null, "10.20.30.0/24",
				350, 0, false, ClientEvent.STATUS_ACTIVE, true, t1,
				64512L, "Campus Internal Network", "DE", ClientType.INTERNAL_NETWORK, EnrichmentStatus.ENRICHED,
				null, 1, 1, 0, 0, 0, "GET", "/catalog/details", internalDisplayUa, false
		);
		ClientEvent eMobileAuth = new ClientEvent(
				null, "Node-A", "Limiter", 103L, t1, "203.0.113.55",
				4, 24, null, null, null, null, "203.0.113.0/24",
				900, 0, false, ClientEvent.STATUS_ACTIVE, true, t1,
				64521L, "Residential Net Beta", "DE", ClientType.RESIDENTIAL, EnrichmentStatus.ENRICHED,
				null, 1, 1, 900, 450, 0, "GET", "/api/v1/search", mobileAppUa, true
		);
		ClientEvent eMobileAuth2 = new ClientEvent(
				null, "Node-A", "Limiter", 104L, t1, "203.0.113.56",
				4, 24, null, null, null, null, "203.0.113.0/24",
				400, 0, false, ClientEvent.STATUS_ACTIVE, true, t1,
				64521L, "Residential Net Beta", "DE", ClientType.RESIDENTIAL, EnrichmentStatus.ENRICHED,
				null, 1, 1, 400, 200, 0, "GET", "/api/v1/search", mobileAppUa, true
		);

		clientEventRepository.batchUpsert(List.of(eScraper, eInternal, eMobileAuth, eMobileAuth2));

		int aggregated = memoryService.aggregateHourlyWindow(bucket1Start, bucket1End);
		assertEquals(3, aggregated);

		int refreshed = memoryService.refreshProfiles24h();
		assertEquals(3, refreshed);

		Optional<UserAgentProfile> internalProfile = memoryRepository.findByRawUserAgent(internalDisplayUa);
		assertTrue(internalProfile.isPresent());
		assertEquals(UserAgentAutoVerdict.IMMUNE_INTERNAL, internalProfile.get().effectiveAutoVerdict());

		Optional<UserAgentProfile> mobileProfile = memoryRepository.findByRawUserAgent(mobileAppUa);
		assertTrue(mobileProfile.isPresent());
		assertEquals(UserAgentAutoVerdict.IMMUNE_AUTHENTICATED, mobileProfile.get().effectiveAutoVerdict());

		// Set non-overwritable manual override & note on scraperUa
		memoryService.updateManualOverride(
				scraperUa,
				UserAgentManualOverride.ALWAYS_ALLOW,
				"Approved research partner monitor on test endpoint",
				"ADMIN:alice"
		);

		// Simulate second hour of heavy datacenter scraping for scraperUa & re-aggregate
		Instant bucket2Start = bucket1End;
		Instant bucket2End = now;
		Instant t2 = bucket2Start.plus(20, ChronoUnit.MINUTES);
		ClientEvent eScraperHour2 = new ClientEvent(
				null, "Node-A", "Limiter", 201L, t2, "198.51.100.11",
				4, 24, null, null, null, null, "198.51.100.0/24",
				7000, 0, false, ClientEvent.STATUS_ACTIVE, true, t2,
				64520L, "Cloud Host Alpha", "DE", ClientType.DATACENTER, EnrichmentStatus.ENRICHED,
				null, 1, 1, 0, 0, 0, "GET", "/portal/course/catalog", scraperUa, false
		);
		clientEventRepository.batchUpsert(List.of(eScraperHour2));

		assertEquals(1, memoryService.aggregateHourlyWindow(bucket2Start, bucket2End));
		memoryService.refreshProfiles24h();

		// Verify manual override and operator note were NOT overwritten, yet autoVerdict updated
		UserAgentProfile reloadedScraper = memoryRepository.findByRawUserAgent(scraperUa).orElseThrow();
		assertEquals(UserAgentManualOverride.ALWAYS_ALLOW, reloadedScraper.effectiveOverride());
		assertEquals("Approved research partner monitor on test endpoint", reloadedScraper.operatorNote());
		assertEquals("ADMIN:alice", reloadedScraper.updatedBy());
		assertEquals(UserAgentAutoVerdict.SUSPICIOUS_DATACENTER, reloadedScraper.effectiveAutoVerdict());
		assertFalse(reloadedScraper.isEffectiveSuspicious(), "ALWAYS_ALLOW override must suppress effective suspicion");
		assertTrue(reloadedScraper.isEffectiveProtected());

		// Verify chronological drilldown reads from persistent user_agent_hourly_rollups & preserves dual status
		UserAgentDrilldownDto drilldown = memoryService.getUserAgentDrilldown(scraperUa, 168);
		assertNotNull(drilldown);
		assertEquals(UserAgentManualOverride.ALWAYS_ALLOW, drilldown.manualOverride());
		assertEquals(UserAgentAutoVerdict.SUSPICIOUS_DATACENTER, drilldown.liveAutoVerdict());
		assertFalse(drilldown.historyFromLiveEvents(), "Should read from persistent hourly rollups");
		assertEquals(2, drilldown.hourlyHistory().size());
		assertEquals(UserAgentMemoryRepository.computeSha256Hex(scraperUa), drilldown.userAgentHash());
		assertEquals(UserAgentMemoryRepository.computeUaHash32(scraperUa), drilldown.uaHash32());
	}

	@Test
	void testOperationalModeAndAiAgentPermissionGuards() {
		String targetUa = "ManualTestAgent/2.0";

		try {
			// 1. FULL mode allows settings updates and manual overrides
			properties.setMode(CollectorMode.FULL);
			EffectiveUaHeuristicSettings custom = new EffectiveUaHeuristicSettings(
					10.0, 50L, 60.0, 2.0, 3.0,
					12000L, 250, 40, 8.0, 3,
					3000L, 35.0, 45.0, 25.0,
					4000L, 85.0, false
			);
			EffectiveUaHeuristicSettings saved = memoryService.updateSettings(custom, "ADMIN:bob");
			assertTrue(saved.hasDatabaseOverrides());
			assertEquals(12000L, saved.spreadMinRequests());
			assertEquals(4000L, saved.datacenterMinRequests());

			memoryService.updateManualOverride(targetUa, UserAgentManualOverride.MANUAL_BLOCK, "Manual test", "ADMIN:bob");
			assertEquals(UserAgentManualOverride.MANUAL_BLOCK,
					memoryRepository.findByRawUserAgent(targetUa).orElseThrow().effectiveOverride());

			// 2. OPERATOR mode allows manual overrides, but blocks changing global heuristic thresholds
			properties.setMode(CollectorMode.OPERATOR);
			assertThrows(IllegalStateException.class, () -> memoryService.updateSettings(custom, "OPERATOR:eve"));
			assertThrows(IllegalStateException.class, () -> memoryService.resetToDefaults("OPERATOR:eve"));
			memoryService.updateManualOverride(targetUa, UserAgentManualOverride.OBSERVE_ONLY, "Watching", "OPERATOR:eve");
			assertEquals(UserAgentManualOverride.OBSERVE_ONLY,
					memoryRepository.findByRawUserAgent(targetUa).orElseThrow().effectiveOverride());

			// 3. VIEWER mode blocks both threshold edits and manual overrides
			properties.setMode(CollectorMode.VIEWER);
			assertThrows(IllegalStateException.class, () -> memoryService.updateSettings(custom, "VIEWER:v1"));
			assertThrows(IllegalStateException.class, () ->
					memoryService.updateManualOverride(targetUa, UserAgentManualOverride.MANUAL_BLOCK, "No", "VIEWER:v1"));

			// 4. AI_AGENT principal is blocked even when CollectorMode is FULL
			properties.setMode(CollectorMode.FULL);
			CollectorAuthContext.set(new CollectorAuthContext.AuthPrincipal("ai-bot", CollectorTokenRole.AI_AGENT, true, false));
			assertThrows(IllegalStateException.class, () -> memoryService.updateSettings(custom, "AI_AGENT:ai-bot"));
			assertThrows(IllegalStateException.class, () -> memoryService.resetToDefaults("AI_AGENT:ai-bot"));
			assertThrows(IllegalStateException.class, () ->
					memoryService.updateManualOverride(targetUa, UserAgentManualOverride.MANUAL_BLOCK, "Blocked AI", "AI_AGENT:ai-bot"));

			// 5. Clear AI context and verify admin reset works
			CollectorAuthContext.clear();
			EffectiveUaHeuristicSettings reset = memoryService.resetToDefaults("ADMIN:bob");
			assertFalse(reset.hasDatabaseOverrides());
		} finally {
			CollectorAuthContext.clear();
			properties.setMode(CollectorMode.FULL);
		}
	}

	@Test
	void testForgedBuildAnomalyAndRefinedVersionLadderThresholds() {
		EffectiveUaHeuristicSettings cfg = EffectiveUaHeuristicSettings.defaults();

		// 1. Single-slot low-volume randomized UA build (Chrome/150.0.6590.913) -> immediate SUSPICIOUS_SIGNATURE
		EvaluationOutcome forgedOutcome = memoryService.evaluateVerdict(new EvaluationInput(
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.6590.913 Safari/537.36",
				UserAgentFamily.CHROME_DESKTOP,
				10L, 1, 0, 0, 1, 1,
				0, 0L, 0L, 0L, 10L, 0L, 0L, 0L, false, null
		), cfg);
		assertEquals(UserAgentAutoVerdict.SUSPICIOUS_SIGNATURE, forgedOutcome.verdict());
		assertEquals(org.henbru.antidos.collector.model.BrowserVersionLagAssessment.FORGED_BUILD_ANOMALY, forgedOutcome.versionAssessment());
		assertTrue(forgedOutcome.reason().contains("Forged browser build number"));

		// 2. Sliced version-ladder traffic (3,000 reqs across 120 subnets and 25 ASNs) -> caught by refined Pillar 1 defaults
		EvaluationOutcome slicedLadder = memoryService.evaluateVerdict(new EvaluationInput(
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
				UserAgentFamily.CHROME_DESKTOP,
				3000L, 450, 0, 0, 120, 25,
				0, 0L, 0L, 0L, 150L, 2850L, 0L, 0L, false, null
		), cfg);
		assertEquals(UserAgentAutoVerdict.SUSPICIOUS_ULTRA_SPREAD, slicedLadder.verdict());
		assertTrue(slicedLadder.verdict().isSuspicious());
	}

	@Test
	void testMarkedEventsAndSyntheticUaSubnetSpreadInRefreshProfiles24h() {
		Instant now = Instant.now();
		Instant bucketStart = now.minus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.HOURS);
		Instant bucketEnd = bucketStart.plus(2, ChronoUnit.HOURS);
		Instant t1 = bucketStart.plus(10, ChronoUnit.MINUTES);
		Instant t2 = bucketStart.plus(20, ChronoUnit.MINUTES);

		String markedUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/145.0.0.0 Safari/537.36";
		ClientEvent markedEv1 = new ClientEvent(
				null, "Node-A", "Limiter", 401L, t1, "198.51.100.20",
				4, 24, null, null, null, null, "198.51.100.0/24",
				2000, 0, false, ClientEvent.STATUS_MARKED, true, t1,
				64521L, "Residential Net Beta", "DE", ClientType.RESIDENTIAL, EnrichmentStatus.ENRICHED,
				null, 1, 1, 0, 0, 0, "GET", "/portal/course/catalog", markedUa, false
		);
		ClientEvent markedEv2 = new ClientEvent(
				null, "Node-A", "Limiter", 402L, t2, "198.51.100.21",
				4, 24, null, null, null, null, "198.51.100.0/24",
				1500, 0, false, ClientEvent.STATUS_MARKED, true, t2,
				64521L, "Residential Net Beta", "DE", ClientType.RESIDENTIAL, EnrichmentStatus.ENRICHED,
				null, 1, 1, 0, 0, 0, "GET", "/catalog/details", markedUa, false
		);

		String syntheticSpreadUa = "Mozilla/5.0 Chrome/154.0.0.0 SyntheticSpreadBot";
		String syntheticKey = "UA:" + UserAgentMemoryRepository.computeUaHash32(syntheticSpreadUa);
		ClientEvent syntheticEvent = new ClientEvent(
				null, "Node-A", "Limiter", 403L, t1, syntheticKey,
				15, 0, false, ClientEvent.STATUS_BLOCKED, true, t1,
				320, 1, 0, 0, 0, "GET", "/portal/course/catalog", syntheticSpreadUa, false, false
		);

		clientEventRepository.batchUpsert(List.of(markedEv1, markedEv2, syntheticEvent));

		assertEquals(2, memoryService.aggregateHourlyWindow(bucketStart, bucketEnd));
		assertEquals(2, memoryService.refreshProfiles24h());

		UserAgentProfile markedProfile = memoryRepository.findByRawUserAgent(markedUa).orElseThrow();
		assertEquals(0L, markedProfile.last24hBlockedRequests());
		assertEquals(3500L, markedProfile.last24hMarkedRequests());
		assertEquals(UserAgentAutoVerdict.SUSPICIOUS_CORRELATED, markedProfile.effectiveAutoVerdict());

		UserAgentProfile syntheticProfile = memoryRepository.findByRawUserAgent(syntheticSpreadUa).orElseThrow();
		assertEquals(320, syntheticProfile.last24hDistinctSubnets());
	}
}
