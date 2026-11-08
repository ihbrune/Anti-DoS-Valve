package org.henbru.antidos.collector.advisor;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.henbru.antidos.collector.model.ClientSubnetRollup;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.MonitoredValve;
import org.henbru.antidos.collector.storage.MonitoredValveRepository;
import org.henbru.antidos.collector.storage.SubnetRollupRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class AdvisorServiceTest {

	@Autowired
	private AdvisorService advisorService;

	@Autowired
	private SubnetRollupRepository subnetRollupRepository;

	@Autowired
	private MonitoredValveRepository monitoredValveRepository;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@BeforeEach
	void setUp() {
		jdbcTemplate.update("DELETE FROM client_subnet_rollups");
		jdbcTemplate.update("DELETE FROM monitored_valves");
	}

	@Test
	void testCidrToRegexConversion() {
		assertEquals("10\\.77\\.25\\..*", AdvisorService.cidrToRegex("10.77.25.0/24"));
		assertEquals("40\\.77\\.167\\..*", AdvisorService.cidrToRegex("40.77.167.0/24"));
		assertEquals("10\\..*", AdvisorService.cidrToRegex("10.0.0.0/8"));
		assertEquals("192\\.168\\..*", AdvisorService.cidrToRegex("192.168.0.0/16"));
		assertEquals("10\\.77\\.25\\.133", AdvisorService.cidrToRegex("10.77.25.133/32"));
		assertEquals("127\\.0\\.0\\.1", AdvisorService.cidrToRegex("127.0.0.1"));
	}

	@Test
	void testRegexMerging() {
		assertEquals("10\\.77\\.25\\..*", AdvisorService.mergeWithExistingRegex(null, "10\\.77\\.25\\..*"));
		assertEquals("10\\.77\\.25\\..*", AdvisorService.mergeWithExistingRegex("", "10\\.77\\.25\\..*"));
		assertEquals("129\\.70\\..*|10\\.77\\.25\\..*", AdvisorService.mergeWithExistingRegex("129\\.70\\..*", "10\\.77\\.25\\..*"));
		assertEquals("129\\.70\\..*|10\\.77\\.25\\..*", AdvisorService.mergeWithExistingRegex("129\\.70\\..*|10\\.77\\.25\\..*", "10\\.77\\.25\\..*"));
	}

	@Test
	void testAdvisorRuleEvaluation() {
		Instant now = Instant.now();
		Instant hourAgo = now.minus(1, ChronoUnit.HOURS);
		Instant twoHoursAgo = now.minus(2, ChronoUnit.HOURS);

		// Configure a valve with limit 50 and existing whitelist
		MonitoredValve valve = new MonitoredValve(
				"test-server-01", "FUER-EXTERNE", "External Limiter", 1, "BLOCKING", false, false,
				429, 50, 15, 20, 0f, 32, 128, 500, 500,
				null, null, "129\\.70\\..*", null, null, null, "auto",
				false, null, false, null, null, null, 900, 50000,
				now, 1, true
		);
		monitoredValveRepository.upsert(valve);

		// 1. Search Engine Crawler blocked (Bingbot)
		ClientSubnetRollup seRollup = new ClientSubnetRollup(
				null, twoHoursAgo, hourAgo, 60, "test-server-01", "FUER-EXTERNE", "40.77.167.0/24",
				5000, 0, 5000, 0, 10, 1, 1, 45, 1, 8075L, "Bingbot", "US", ClientType.SEARCH_ENGINE,
				0, 0, 0, 0
		);

		// 2. Private Network blocked (10.77.25.0/24)
		ClientSubnetRollup privRollup = new ClientSubnetRollup(
				null, twoHoursAgo, hourAgo, 60, "test-server-01", "FUER-EXTERNE", "10.77.25.0/24",
				2000, 0, 2000, 0, 5, 1, 1, 120, 1, null, "Private Network (RFC 1918)", null, ClientType.PRIVATE_NETWORK,
				1800, 2000, 0, 0
		);

		// 3. Residential cluster with high returning ratio
		ClientSubnetRollup resRollup = new ClientSubnetRollup(
				null, twoHoursAgo, hourAgo, 60, "test-server-01", "FUER-EXTERNE", "92.208.14.0/24",
				800, 700, 100, 0, 4, 1, 1, 35, 1, 3209L, "Vodafone GmbH", "DE", ClientType.RESIDENTIAL,
				750, 800, 0, 0
		);

		// 4. Massive Datacenter Scraping
		ClientSubnetRollup dcRollup = new ClientSubnetRollup(
				null, twoHoursAgo, hourAgo, 60, "test-server-01", "FUER-EXTERNE", "20.237.225.0/24",
				15000, 5000, 10000, 0, 1, 1, 1, 500, 1, 8075L, "Microsoft Corporation", "US", ClientType.DATACENTER,
				0, 0, 0, 0
		);

		// 5. Authenticated Users Blocked
		ClientSubnetRollup authRollup = new ClientSubnetRollup(
				null, twoHoursAgo, hourAgo, 60, "test-server-01", "FUER-EXTERNE", "195.201.55.0/24",
				3000, 2500, 500, 0, 2, 1, 1, 80, 1, 24940L, "Hetzner Online GmbH", "DE", ClientType.DATACENTER,
				0, 0, 1200, 3000
		);

		subnetRollupRepository.batchUpsert(List.of(seRollup, privRollup, resRollup, dcRollup, authRollup));

		AdvisorReport report = advisorService.generateReport(24, List.of("test-server-01"), List.of("FUER-EXTERNE"));
		assertNotNull(report);
		assertTrue(report.criticalCount() >= 3, "Should detect at least 3 critical findings (Search Engine + RFC1918 + Authenticated)");
		assertTrue(report.warningCount() >= 1, "Should detect at least 1 warning finding (Residential NAT)");
		assertTrue(report.infoCount() >= 1, "Should detect at least 1 info finding (Datacenter Offload)");

		assertTrue(report.recommendedAlwaysAllowedSubnets().contains("40.77.167.0/24"));
		assertTrue(report.recommendedAlwaysAllowedSubnets().contains("10.77.25.0/24"));

		assertTrue(report.consolidatedAlwaysAllowedRegex().contains("10\\.77\\.25\\..*"));
		assertTrue(report.consolidatedAlwaysAllowedRegex().contains("40\\.77\\.167\\..*"));
		assertTrue(report.consolidatedServerXmlSnippet().contains("<Valve className=\"org.henbru.antidos.AntiDoSValve\""));

		// Verify findings structure
		AdvisorFinding authFinding = report.findings().stream()
				.filter(f -> f.category() == AdvisorCategory.AUTHENTICATED_COLLATERAL)
				.findFirst()
				.orElseThrow();
		assertEquals(AdvisorSeverity.CRITICAL, authFinding.severity());
		assertEquals("195.201.55.0/24", authFinding.targetSubnet());
		assertEquals(500L, authFinding.blockedRequests());
		assertTrue(authFinding.explanation().contains("carrying valid authentication credentials"));

		// Verify findings structure
		AdvisorFinding seFinding = report.findings().stream()
				.filter(f -> f.category() == AdvisorCategory.SEARCH_ENGINE_COLLATERAL)
				.findFirst()
				.orElseThrow();
		assertEquals(AdvisorSeverity.CRITICAL, seFinding.severity());
		assertEquals("FUER-EXTERNE", seFinding.valveName());
		assertEquals("40.77.167.0/24", seFinding.targetSubnet());
		assertEquals(50, seFinding.currentLimit());
		assertTrue(seFinding.suggestedConfigXml().contains("alwaysAllowedIPs=\"129\\.70\\..*|40\\.77\\.167\\..*\""));

		AdvisorFinding privFinding = report.findings().stream()
				.filter(f -> f.category() == AdvisorCategory.INTERNAL_INFRASTRUCTURE)
				.findFirst()
				.orElseThrow();
		assertEquals(AdvisorSeverity.CRITICAL, privFinding.severity());
		assertEquals("10.77.25.0/24", privFinding.targetSubnet());
		assertTrue(privFinding.suggestedConfigXml().contains("10\\.77\\.25\\..*"));
	}

	@Test
	void testStealthCarpetAttackDetection() {
		Instant now = Instant.now();
		Instant hourAgo = now.minus(1, ChronoUnit.HOURS);
		Instant twoHoursAgo = now.minus(2, ChronoUnit.HOURS);

		MonitoredValve valve = new MonitoredValve(
				"test-server-01", "GLOBAL-LIMITER", "Global Subnet Limiter", 1, "BLOCKING", false, false,
				429, 200, 15, 20, 0f, 24, 64, 500, 500,
				null, null, null, null, null, null, "auto",
				false, null, false, null, null, null, 900, 50000, "ALL", 50,
				now, 1, true
		);
		monitoredValveRepository.upsert(valve);

		// 3 subnets in ASN 64496 sending a total of 18,000 requests with 0 blocks and 0 auth
		ClientSubnetRollup r1 = new ClientSubnetRollup(
				null, twoHoursAgo, hourAgo, 60, "test-server-01", "GLOBAL-LIMITER", "198.51.100.0/24",
				6000, 6000, 0, 0, 8, 1, 1, 80, 1, 64496L, "Example Hosting Corp.", "US", ClientType.DATACENTER,
				0, 0, 0, 0
		);
		ClientSubnetRollup r2 = new ClientSubnetRollup(
				null, twoHoursAgo, hourAgo, 60, "test-server-01", "GLOBAL-LIMITER", "203.0.113.0/24",
				6000, 6000, 0, 0, 8, 1, 1, 80, 1, 64496L, "Example Hosting Corp.", "US", ClientType.DATACENTER,
				0, 0, 0, 0
		);
		ClientSubnetRollup r3 = new ClientSubnetRollup(
				null, twoHoursAgo, hourAgo, 60, "test-server-01", "GLOBAL-LIMITER", "192.0.2.0/24",
				6000, 6000, 0, 0, 8, 1, 1, 80, 1, 64496L, "Example Hosting Corp.", "US", ClientType.DATACENTER,
				0, 0, 0, 0
		);
		subnetRollupRepository.batchUpsert(List.of(r1, r2, r3));

		AdvisorReport report = advisorService.generateReport(24, List.of("test-server-01"), List.of("GLOBAL-LIMITER"));
		assertNotNull(report);

		AdvisorFinding carpetFinding = report.findings().stream()
				.filter(f -> f.category() == AdvisorCategory.STEALTH_CARPET_ATTACK)
				.findFirst()
				.orElseThrow();

		assertEquals(AdvisorSeverity.WARNING, carpetFinding.severity());
		assertEquals("GLOBAL-LIMITER", carpetFinding.valveName());
		assertTrue(carpetFinding.title().contains("ASN 64496"));
		assertEquals(18000L, carpetFinding.totalRequests());
		assertEquals(0L, carpetFinding.blockedRequests());
		assertTrue(carpetFinding.explanation().contains("distributing traffic across multiple IP blocks"));
		assertTrue(carpetFinding.suggestedRegex().contains("iptables -I INPUT -m set --match-set asn_64496 src -j DROP"));
	}

	@Test
	void testChameleonScraperDetection() {
		Instant now = Instant.now();
		Instant hourAgo = now.minus(1, ChronoUnit.HOURS);
		Instant twoHoursAgo = now.minus(2, ChronoUnit.HOURS);

		MonitoredValve valve = new MonitoredValve(
				"test-server-01", "EDGE-VALVE", "Edge Limiter", 1, "BLOCKING", false, false,
				429, 100, 15, 20, 0f, 32, 64, 500, 500,
				null, null, null, null, null, null, "auto",
				false, null, false, null, null, null, 900, 50000, "ALL", 50,
				now, 1, true
		);
		monitoredValveRepository.upsert(valve);

		// Subnet with 14 distinct user agents across 2 client IPs, 0 auth, 0 returning
		ClientSubnetRollup chameleon = new ClientSubnetRollup(
				null, twoHoursAgo, hourAgo, 60, "test-server-01", "EDGE-VALVE", "185.220.101.0/24",
				1500, 1500, 0, 0, 2, 14, 1, 75, 1, 60729L, "Tor Exit Node", "NL", ClientType.DATACENTER,
				now, 0, 0, 0, 0
		);
		subnetRollupRepository.batchUpsert(List.of(chameleon));

		AdvisorReport report = advisorService.generateReport(24, List.of("test-server-01"), List.of("EDGE-VALVE"));
		assertNotNull(report);

		AdvisorFinding chamFinding = report.findings().stream()
				.filter(f -> f.category() == AdvisorCategory.CHAMELEON_BOT)
				.findFirst()
				.orElseThrow();

		assertEquals(AdvisorSeverity.WARNING, chamFinding.severity());
		assertEquals("185.220.101.0/24", chamFinding.targetSubnet());
		assertTrue(chamFinding.title().contains("Chameleon"));
		assertTrue(chamFinding.explanation().contains("rotating User-Agent strings"));
		assertTrue(chamFinding.recommendation().contains("Do NOT whitelist this subnet"));
	}

	@Test
	void testMissingActiveSamplingDetection() {
		Instant now = Instant.now();

		// Configure a valve with subnet mask /24 and activeSampleThreshold = 0
		MonitoredValve valve = new MonitoredValve(
				"test-server-01", "SUBNET-VALVE", "Subnet Aggregator", 1, "BLOCKING", false, false,
				429, 200, 15, 20, 0f, 24, 64, 500, 500,
				null, null, null, null, null, null, "auto",
				false, null, false, null, null, null, 900, 50000, "ALL", 0,
				now, 1, true
		);
		monitoredValveRepository.upsert(valve);

		AdvisorReport report = advisorService.generateReport(24, List.of("test-server-01"), List.of("SUBNET-VALVE"));
		assertNotNull(report);

		AdvisorFinding sampFinding = report.findings().stream()
				.filter(f -> f.category() == AdvisorCategory.SAMPLING_TUNING)
				.findFirst()
				.orElseThrow();

		assertEquals(AdvisorSeverity.INFO, sampFinding.severity());
		assertEquals("SUBNET-VALVE", sampFinding.valveName());
		assertTrue(sampFinding.title().contains("Active Sampling Inactive"));
		assertTrue(sampFinding.explanation().contains("activeSampleThreshold' is set to 0"));
		assertTrue(sampFinding.suggestedConfigXml().contains("activeSampleThreshold=\"50\""));
	}
}
