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

		// Filter SURGE (>= 5.0x) -> newProfile (100x), dormantProfile (200x), surgeProfile (12x), proxyPool (6x)
		List<SubnetProfile> surgeOnly = profileRepository.findProfilesFiltered("SURGE", null, null, null, null, null, "SURGE", 10, 0);
		assertEquals(4, surgeOnly.size());

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

		// Subnet A: Historical traffic 15 days ago (290 requests across 29 days -> ~10 req/day baseline)
		Instant past15d = now.minus(15, ChronoUnit.DAYS);
		ClientSubnetRollup pastRollup = new ClientSubnetRollup(
				null, past15d, past15d.plus(1, ChronoUnit.HOURS), 60, "Node-1", "Limiter", "198.51.100.0/24",
				290L, 290L, 0L, 1, 290, 290, 1, 13335L, "Cloudflare", "US", ClientType.RESIDENTIAL
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
		assertEquals(390L, profA.totalLifetimeRequests());
		assertEquals(100L, profA.last24hRequests());
		assertEquals(20L, profA.last24hBlockedRequests());
		assertEquals(10.0, profA.baselineDailyAvg(), 0.5);
		assertEquals(10.0, profA.last24hSurgeFactor(), 0.5);
		assertTrue(profA.daysDormantBeforeLastSeen() >= 14, "Should detect 14+ days dormancy before recent burst");

		SubnetProfile profB = computed.stream().filter(p -> p.subnetGroup().equals("203.0.113.0/24")).findFirst().orElseThrow();
		assertEquals(50L, profB.totalLifetimeRequests());
		assertEquals(50L, profB.last24hRequests());
		assertEquals(0.0, profB.baselineDailyAvg());
		assertEquals(999, profB.daysDormantBeforeLastSeen(), "Brand new subnet should have dormancy code 999");
		assertEquals(50.0, profB.last24hSurgeFactor());

		// Test end-to-end service refresh
		int refreshed = profileService.refreshProfiles();
		assertEquals(2, refreshed);

		Optional<SubnetProfile> persistedA = profileService.findBySubnetGroup("198.51.100.0/24");
		assertTrue(persistedA.isPresent());
		assertEquals(10.0, persistedA.get().last24hSurgeFactor(), 0.5);
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
