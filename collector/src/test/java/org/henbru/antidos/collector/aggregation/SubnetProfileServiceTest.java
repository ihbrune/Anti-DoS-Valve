package org.henbru.antidos.collector.aggregation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.henbru.antidos.collector.model.ClientSubnetRollup;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.SubnetProfile;
import org.henbru.antidos.collector.storage.SubnetProfileRepository;
import org.henbru.antidos.collector.storage.SubnetRollupRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SubnetProfileServiceTest {

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private SubnetProfileRepository profileRepository;

	@Autowired
	private SubnetRollupRepository rollupRepository;

	@Autowired
	private SubnetProfileService profileService;

	@BeforeEach
	public void setUp() {
		jdbcTemplate.update("DELETE FROM subnet_profiles");
		jdbcTemplate.update("DELETE FROM client_subnet_rollups");
	}

	@Test
	void testBatchUpsertAndFilterPatterns() {
		Instant now = Instant.now();

		// 1. New Subnet (first seen 2 hours ago)
		SubnetProfile newProfile = new SubnetProfile(
				"198.51.100.0/24",
				now.minus(2, ChronoUnit.HOURS),
				now,
				0,
				100,
				100,
				0,
				0.0,
				5,
				100,
				100,
				5,
				0,
				100.0,
				13335L,
				"Cloudflare",
				"US",
				ClientType.RESIDENTIAL
		);

		// 2. Dormancy Breakout (inactive for 25 days before last activity)
		SubnetProfile dormantProfile = new SubnetProfile(
				"203.0.113.0/24",
				now.minus(40, ChronoUnit.DAYS),
				now,
				25,
				500,
				450,
				50,
				1.0,
				10,
				200,
				200,
				10,
				50,
				200.0,
				3320L,
				"Deutsche Telekom AG",
				"DE",
				ClientType.RESIDENTIAL
		);

		// 3. High Surge (baseline: 10/day, last 24h: 120 -> 12x surge)
		SubnetProfile surgeProfile = new SubnetProfile(
				"192.0.2.0/24",
				now.minus(60, ChronoUnit.DAYS),
				now,
				0,
				2500,
				2000,
				500,
				10.0,
				2,
				120,
				120,
				2,
				20,
				12.0,
				24940L,
				"Hetzner Online GmbH",
				"DE",
				ClientType.DATACENTER
		);

		// 4. Rotating Residential Proxy Pool (15 distinct clients, avg 2.0 reqs/client)
		SubnetProfile proxyPool = new SubnetProfile(
				"185.246.221.0/24",
				now.minus(10, ChronoUnit.DAYS),
				now,
				0,
				300,
				250,
				50,
				5.0,
				15,
				30,
				30,
				15,
				10,
				6.0,
				3209L,
				"Vodafone",
				"DE",
				ClientType.RESIDENTIAL
		);

		profileRepository.batchUpsert(List.of(newProfile, dormantProfile, surgeProfile, proxyPool));

		// Check single lookup
		Optional<SubnetProfile> fetched = profileRepository.findBySubnetGroup("198.51.100.0/24");
		assertTrue(fetched.isPresent());
		assertEquals("Cloudflare", fetched.get().asOrg());
		assertTrue(fetched.get().isNewSubnet(7));

		// Check map lookup
		Map<String, SubnetProfile> map = profileRepository.findSubnetProfilesMap(List.of("198.51.100.0/24", "192.0.2.0/24"));
		assertEquals(2, map.size());
		assertTrue(map.containsKey("198.51.100.0/24"));
		assertTrue(map.containsKey("192.0.2.0/24"));

		// Filter ALL
		List<SubnetProfile> all = profileRepository.findProfilesFiltered("ALL", null, null, null, null, null, "SURGE", 10, 0);
		assertEquals(4, all.size());
		assertEquals(4, profileRepository.countProfilesFiltered("ALL", null, null, null, null, null));

		// Filter SURGE with default de minimis threshold (1000 req/24h) -> 0 (all test profiles have < 1000 reqs)
		List<SubnetProfile> surgeDefault = profileRepository.findProfilesFiltered("SURGE", null, null, null, null, null, "SURGE", 10, 0);
		assertEquals(0, surgeDefault.size(), "De minimis threshold (1000) should filter low-volume spikes");

		// Filter SURGE with explicit volume override (>= 25 req/24h) -> dormantProfile (200x), surgeProfile (12x), proxyPool (6x)
		List<SubnetProfile> surgeWithOverride = profileRepository.findProfilesFiltered("SURGE", 25L, null, null, null, null, "SURGE", 10, 0);
		assertEquals(3, surgeWithOverride.size());

		// Filter DORMANT (>= 14d) -> dormantProfile (25d)
		List<SubnetProfile> dormantOnly = profileRepository.findProfilesFiltered("DORMANT", null, null, null, null, null, "DORMANT", 10, 0);
		assertEquals(1, dormantOnly.size());
		assertEquals("203.0.113.0/24", dormantOnly.getFirst().subnetGroup());

		// Filter NEW (< 7d first seen or dormant >= 900)
		List<SubnetProfile> newOnly = profileRepository.findProfilesFiltered("NEW", null, null, null, null, null, "FIRST_SEEN", 10, 0);
		assertTrue(newOnly.stream().anyMatch(p -> p.subnetGroup().equals("198.51.100.0/24")));

		// Filter PROXY_POOL (distinct >= 5 && avg <= 5.0)
		List<SubnetProfile> proxyPools = profileRepository.findProfilesFiltered("PROXY_POOL", null, null, null, null, null, "DISTINCT_IPS", 10, 0);
		assertTrue(proxyPools.stream().anyMatch(p -> p.subnetGroup().equals("185.246.221.0/24")));

		// Sort by REQUESTS
		List<SubnetProfile> sortedByReqs = profileRepository.findProfilesFiltered("ALL", null, null, null, null, null, "REQUESTS", 10, 0);
		assertEquals("203.0.113.0/24", sortedByReqs.getFirst().subnetGroup()); // 200 reqs in 24h
	}

	@Test
	void testComputeProfilesFromRollups() {
		Instant now = Instant.now().truncatedTo(ChronoUnit.HOURS);
		Instant cutoff24h = now.minus(24, ChronoUnit.HOURS);
		Instant cutoff30d = now.minus(30, ChronoUnit.DAYS);

		// Subnet A: Historical traffic 28 days ago (270 requests across 27 available prior days -> 10 req/day baseline)
		Instant past28d = now.minus(28, ChronoUnit.DAYS);
		ClientSubnetRollup pastRollup = new ClientSubnetRollup(
				null, past28d, past28d.plus(1, ChronoUnit.HOURS), 60, "Node-1", "Limiter", "198.51.100.0/24",
				270L, 270L, 0L, 1, 270, 270, 1, 13335L, "Cloudflare", "US", ClientType.RESIDENTIAL
		);

		// Subnet A: Massive burst in the last 24 hours (100 requests -> surge factor = 100 / 10 = 10.0x)
		Instant current3h = now.minus(3, ChronoUnit.HOURS);
		ClientSubnetRollup recentRollup = new ClientSubnetRollup(
				null, current3h, current3h.plus(1, ChronoUnit.HOURS), 60, "Node-1", "Limiter", "198.51.100.0/24",
				100L, 80L, 20L, 8, 5, 20, 1, 13335L, "Cloudflare", "US", ClientType.RESIDENTIAL
		);

		// Subnet B: Brand new subnet active only in last 24 hours (50 requests, 0 prior)
		ClientSubnetRollup brandNewRollup = new ClientSubnetRollup(
				null, current3h, current3h.plus(1, ChronoUnit.HOURS), 60, "Node-1", "Limiter", "203.0.113.0/24",
				50L, 50L, 0L, 5, 10, 10, 1, 3320L, "DTAG", "DE", ClientType.RESIDENTIAL
		);

		rollupRepository.batchUpsert(List.of(pastRollup, recentRollup, brandNewRollup));

		// Run compute
		List<SubnetProfile> computed = profileRepository.computeProfilesFromRollups(cutoff24h, cutoff30d);
		assertEquals(2, computed.size());

		SubnetProfile profA = computed.stream().filter(p -> p.subnetGroup().equals("198.51.100.0/24")).findFirst().orElseThrow();
		assertEquals(370L, profA.totalLifetimeRequests());
		assertEquals(100L, profA.last24hRequests());
		assertEquals(20L, profA.last24hBlockedRequests());
		assertEquals(10.0, profA.baselineDailyAvg(), 0.5);
		assertEquals(10.0, profA.last24hSurgeFactor(), 0.5);
		assertTrue(profA.isHighSurge(5.0));
		assertFalse(profA.isHighSurge(5.0, 1000L), "100 reqs should not qualify as high surge with 1000 req threshold");
		assertTrue(profA.isSubThresholdSurge(5.0, 1000L), "100 reqs with 10x surge should qualify as sub-threshold low volume");
		assertFalse(profA.isInitializing());
		assertTrue(profA.daysDormantBeforeLastSeen() >= 14, "Should detect 14+ days dormancy before recent burst");

		SubnetProfile profB = computed.stream().filter(p -> p.subnetGroup().equals("203.0.113.0/24")).findFirst().orElseThrow();
		assertEquals(50L, profB.totalLifetimeRequests());
		assertEquals(50L, profB.last24hRequests());
		assertEquals(0.0, profB.baselineDailyAvg());
		assertEquals(999, profB.daysDormantBeforeLastSeen(), "Brand new subnet should have dormancy code 999");
		assertEquals(0.0, profB.last24hSurgeFactor(), "Brand new subnet active only in last 24h should have 0.0 surge factor (initializing)");
		assertTrue(profB.isInitializing());
		assertFalse(profB.isHighSurge(5.0));
		assertTrue(profB.isNewSubnet(7));

		// Test end-to-end service refresh
		int refreshed = profileService.refreshProfiles();
		assertEquals(2, refreshed);

		Optional<SubnetProfile> persistedA = profileService.findBySubnetGroup("198.51.100.0/24");
		assertTrue(persistedA.isPresent());
		assertEquals(10.0, persistedA.get().last24hSurgeFactor(), 0.5);
	}

	@Test
	void testDynamicCalibrationOnFreshInstallation() {
		Instant now = Instant.now().truncatedTo(ChronoUnit.HOURS);
		Instant cutoff24h = now.minus(24, ChronoUnit.HOURS);
		Instant cutoff30d = now.minus(30, ChronoUnit.DAYS);

		// System running for only 3 days total (2 days prior to cutoff24h)
		Instant twoDaysPrior = now.minus(72, ChronoUnit.HOURS);
		ClientSubnetRollup pastRollup = new ClientSubnetRollup(
				null, twoDaysPrior, twoDaysPrior.plus(1, ChronoUnit.HOURS), 60, "Node-1", "Limiter", "192.0.2.0/24",
				100L, 100L, 0L, 1, 100, 100, 1, 24940L, "Hetzner", "DE", ClientType.DATACENTER
		);

		// Current 24h window has 50 requests
		Instant currentRollup = now.minus(2, ChronoUnit.HOURS);
		ClientSubnetRollup current = new ClientSubnetRollup(
				null, currentRollup, currentRollup.plus(1, ChronoUnit.HOURS), 60, "Node-1", "Limiter", "192.0.2.0/24",
				50L, 50L, 0L, 1, 50, 50, 1, 24940L, "Hetzner", "DE", ClientType.DATACENTER
		);

		rollupRepository.batchUpsert(List.of(pastRollup, current));

		List<SubnetProfile> computed = profileRepository.computeProfilesFromRollups(cutoff24h, cutoff30d);
		SubnetProfile prof = computed.stream().filter(p -> p.subnetGroup().equals("192.0.2.0/24")).findFirst().orElseThrow();

		// Baseline divisor is ~2.0 days (not 29!), so baseline = 100 / 2 = 50 req/day
		assertEquals(50.0, prof.baselineDailyAvg(), 5.0);
		// Surge = 50 / 50 = ~1.0x (Normal), NOT 29x surge!
		assertEquals(1.0, prof.last24hSurgeFactor(), 0.3);
		assertFalse(prof.isHighSurge(5.0));
	}

	@Test
	void testBrandNewSubnetDoesNotMatchDormant() {
		Instant now = Instant.now();
		SubnetProfile brandNew = new SubnetProfile(
				"198.51.200.0/24",
				now.minus(1, ChronoUnit.HOURS),
				now,
				999, // Brand new sentinel
				50,
				50,
				0,
				0.0,
				2,
				50,
				50,
				2,
				0,
				50.0,
				null,
				null,
				null,
				ClientType.UNKNOWN
		);
		profileRepository.batchUpsert(List.of(brandNew));

		List<SubnetProfile> dormant = profileRepository.findProfilesFiltered("DORMANT", null, null, null, null, null, "DORMANT", 10, 0);
		assertTrue(dormant.isEmpty(), "Brand-new subnet with sentinel 999 must NOT match DORMANT filter");

		List<SubnetProfile> newSubnets = profileRepository.findProfilesFiltered("NEW", null, null, null, null, null, "FIRST_SEEN", 10, 0);
		assertEquals(1, newSubnets.size());
		assertEquals("198.51.200.0/24", newSubnets.getFirst().subnetGroup());
	}

	@Test
	void testProfileFreshnessComputation() {
		org.henbru.antidos.collector.model.SubnetProfileFreshness freshness = profileService.getProfileFreshness();
		assertNotNull(freshness);
		assertEquals(60, freshness.rollupWindowMinutes());

		// Insert a rollup ending 30 minutes ago
		Instant now = Instant.now();
		Instant rollupEnd = now.minus(30, ChronoUnit.MINUTES);
		Instant rollupStart = rollupEnd.minus(60, ChronoUnit.MINUTES);

		ClientSubnetRollup rollup = new ClientSubnetRollup(
				null, rollupStart, rollupEnd, 60, "srv-1", "valve-1", "198.51.100.0/24",
				100, 100, 0, 5, 20, 20, 1, 3320L, "Telekom", "DE", ClientType.RESIDENTIAL,
				now, 0, 0, 0, 0
		);
		rollupRepository.batchUpsert(List.of(rollup));

		// Re-evaluate freshness
		freshness = profileService.getProfileFreshness();
		assertNotNull(freshness);
		assertNotNull(freshness.latestRollupEnd());
		assertTrue(freshness.hasData());
	}
}
