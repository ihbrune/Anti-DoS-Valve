package org.henbru.antidos.collector.aggregation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.henbru.antidos.collector.model.AnalyticsDashboardDto;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.SubnetScatterPoint;
import org.henbru.antidos.collector.model.TimelinePoint;
import org.henbru.antidos.collector.storage.SubnetRollupRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

class AnalyticsServiceTest {

	private SubnetRollupRepository rollupRepository;
	private RollupAggregationService rollupAggregationService;
	private AnalyticsService analyticsService;

	@BeforeEach
	void setUp() {
		rollupRepository = Mockito.mock(SubnetRollupRepository.class);
		rollupAggregationService = Mockito.mock(RollupAggregationService.class);
		analyticsService = new AnalyticsService(rollupRepository, rollupAggregationService);
	}

	@Test
	void testGetDashboardAnalyticsCalculations() {
		Instant now = Instant.now();
		List<TimelinePoint> mockTimeline = List.of(
				new TimelinePoint(now.minus(2, ChronoUnit.HOURS), 1000, 900, 100),
				new TimelinePoint(now.minus(1, ChronoUnit.HOURS), 2000, 1600, 400)
		);

		List<SubnetRollupRepository.RawCompositionRow> mockComp = List.of(
				new SubnetRollupRepository.RawCompositionRow(ClientType.UNKNOWN, 2500, 100, 15),
				new SubnetRollupRepository.RawCompositionRow(ClientType.RESIDENTIAL, 500, 400, 8)
		);

		List<SubnetRollupRepository.RawScatterCluster> mockScatter = List.of(
				new SubnetRollupRepository.RawScatterCluster("185.246.221.0/24", 500, 100, 400, 50, 3320L, "Deutsche Telekom AG", "DE", ClientType.RESIDENTIAL),
				new SubnetRollupRepository.RawScatterCluster("45.154.255.0/24", 2000, 1500, 500, 2, 45102L, "Alibaba Cloud", "SG", ClientType.DATACENTER)
		);

		when(rollupRepository.findTimeline(any(), any(), any(), any())).thenReturn(mockTimeline);
		when(rollupRepository.findTrafficComposition(any(), any(), any(), any())).thenReturn(mockComp);
		when(rollupRepository.findScatterClusters(any(), any(), any(), any(), anyInt())).thenReturn(mockScatter);

		AnalyticsDashboardDto dto = analyticsService.getDashboardAnalytics(24, null, null);

		assertNotNull(dto);
		assertEquals(3000, dto.totalRequests());
		assertEquals(2500, dto.totalActive());
		assertEquals(500, dto.totalBlocked());
		assertEquals(16.7, dto.blockedRatioPercent()); // 500 / 3000 * 100 = 16.666... -> 16.7

		// Test Traffic Composition
		assertEquals(2, dto.composition().size());
		assertEquals("👤", dto.composition().get(0).icon());
		assertEquals(83.3, dto.composition().get(0).percentage());
		assertEquals(16.7, dto.composition().get(1).percentage());

		// Test Scatter Points
		assertEquals(2, dto.scatterPoints().size());
		SubnetScatterPoint residentialCluster = dto.scatterPoints().get(0);
		assertEquals("185.246.221.0/24", residentialCluster.subnetGroup());
		assertEquals(50, residentialCluster.distinctClients());
		assertEquals(10.0, residentialCluster.averageRequestsPerClient()); // 500 / 50 = 10.0
		assertTrue(residentialCluster.isPotentialResidentialProxy());
		assertEquals("HIGH_RISK_RESIDENTIAL", residentialCluster.classification());

		SubnetScatterPoint datacenterCluster = dto.scatterPoints().get(1);
		assertEquals("45.154.255.0/24", datacenterCluster.subnetGroup());
		assertEquals(2, datacenterCluster.distinctClients());
		assertEquals(1000.0, datacenterCluster.averageRequestsPerClient()); // 2000 / 2 = 1000.0
		assertFalse(datacenterCluster.isPotentialResidentialProxy());
		assertEquals("DATACENTER_CLUSTER", datacenterCluster.classification());
		assertFalse(datacenterCluster.hasNote());
		assertNull(datacenterCluster.noteVerdict());
	}

	@Test
	void testGetDashboardAnalyticsWithAnnotations() {
		org.henbru.antidos.collector.annotation.NetworkAnnotationService annotationService =
				Mockito.mock(org.henbru.antidos.collector.annotation.NetworkAnnotationService.class);
		AnalyticsService service = new AnalyticsService(rollupRepository, rollupAggregationService, annotationService);

		Instant now = Instant.now();
		when(rollupRepository.findTimeline(any(), any(), any(), any())).thenReturn(List.of());
		when(rollupRepository.findTrafficComposition(any(), any(), any(), any())).thenReturn(List.of());

		List<SubnetRollupRepository.RawScatterCluster> mockScatter = List.of(
				new SubnetRollupRepository.RawScatterCluster("185.246.221.0/24", 500, 100, 400, 50, 3320L, "Deutsche Telekom AG", "DE", ClientType.RESIDENTIAL),
				new SubnetRollupRepository.RawScatterCluster("45.154.255.0/24", 2000, 1500, 500, 2, 45102L, "Alibaba Cloud", "SG", ClientType.DATACENTER)
		);
		when(rollupRepository.findScatterClusters(any(), any(), any(), any(), anyInt())).thenReturn(mockScatter);

		org.henbru.antidos.collector.model.NetworkAnnotation subnetAnnotation = new org.henbru.antidos.collector.model.NetworkAnnotation(
				1L, org.henbru.antidos.collector.model.AnnotationTargetType.SUBNET, "185.246.221.0/24", null, "185.246.221.0/24",
				4, 24, null, null, null, null, org.henbru.antidos.collector.model.AnnotationVerdict.SUSPICIOUS,
				"### Residential VPN Proxy\nRotating scrapers", now, now
		);

		org.henbru.antidos.collector.model.NetworkAnnotation asnAnnotation = new org.henbru.antidos.collector.model.NetworkAnnotation(
				2L, org.henbru.antidos.collector.model.AnnotationTargetType.ASN, "AS45102", 45102L, null,
				4, 32, null, null, null, null, org.henbru.antidos.collector.model.AnnotationVerdict.MALICIOUS,
				"Bulletproof scanner hoster", now, now
		);

		when(annotationService.getSubnetAnnotationMap()).thenReturn(java.util.Map.of("185.246.221.0/24", subnetAnnotation));
		when(annotationService.getAsnAnnotationMap()).thenReturn(java.util.Map.of(45102L, asnAnnotation));

		AnalyticsDashboardDto dto = service.getDashboardAnalytics(24, null, null);

		assertNotNull(dto);
		assertEquals(2, dto.scatterPoints().size());

		SubnetScatterPoint pt1 = dto.scatterPoints().get(0);
		assertTrue(pt1.hasNote());
		assertEquals("SUSPICIOUS", pt1.noteVerdict());
		assertEquals("🟡", pt1.noteVerdictIcon());
		assertEquals("Suspicious", pt1.noteVerdictDisplayName());
		assertEquals("#f59e0b", pt1.noteVerdictColor());
		assertEquals("Suspicious", pt1.subnetNoteVerdict());
		assertEquals("Residential VPN Proxy", pt1.subnetNoteSnippet());

		SubnetScatterPoint pt2 = dto.scatterPoints().get(1);
		assertTrue(pt2.hasNote());
		assertEquals("MALICIOUS", pt2.noteVerdict());
		assertEquals("🔴", pt2.noteVerdictIcon());
		assertEquals("Malicious", pt2.noteVerdictDisplayName());
		assertEquals("#f43f5e", pt2.noteVerdictColor());
		assertEquals("Malicious", pt2.asnNoteVerdict());
		assertEquals("Bulletproof scanner hoster", pt2.asnNoteSnippet());
	}

	@Test
	void testGetDashboardAnalyticsAsnRollup() {
		List<SubnetRollupRepository.RawScatterCluster> mockAsnClusters = List.of(
				new SubnetRollupRepository.RawScatterCluster("AS3320", 50000, 48000, 2000, 0L,
						450, 8, 3320L, "Deutsche Telekom AG", "DE", ClientType.RESIDENTIAL, 500L, 2000L, 120L, 800L),
				new SubnetRollupRepository.RawScatterCluster("AS9009", 15000, 5000, 10000, 0L,
						120, 1, 9009L, "M247 Europe", "RO", ClientType.DATACENTER, 0L, 0L, 0L, 5000L)
		);
		when(rollupRepository.findTimeline(any(), any(), any(), any())).thenReturn(List.of());
		when(rollupRepository.findTrafficComposition(any(), any(), any(), any())).thenReturn(List.of());
		when(rollupRepository.findScatterClusters(any(), any(), any(), any(), eq("ASN"), eq("ALL"), eq("ALL"), anyInt()))
				.thenReturn(mockAsnClusters);

		AnalyticsDashboardDto dto = analyticsService.getDashboardAnalytics(24, null, null, "ASN", "ALL", "ALL");

		assertNotNull(dto);
		assertEquals("ASN", dto.scatterGroupBy());
		assertEquals(2, dto.scatterPoints().size());

		SubnetScatterPoint pt1 = dto.scatterPoints().get(0);
		assertEquals("AS3320", pt1.subnetGroup());
		assertEquals(3320L, pt1.asn());
		assertEquals("ASN", pt1.groupBy());
		assertEquals(450, pt1.distinctClients());
		assertEquals(120L, pt1.authenticatedRequests());
		assertTrue(pt1.hasLogins());
		assertEquals(15.0, pt1.authenticatedRatioPercent()); // 120 / 800 * 100 = 15.0

		SubnetScatterPoint pt2 = dto.scatterPoints().get(1);
		assertEquals("AS9009", pt2.subnetGroup());
		assertEquals(9009L, pt2.asn());
		assertEquals(0L, pt2.authenticatedRequests());
		assertFalse(pt2.hasLogins());
		assertEquals(0.0, pt2.authenticatedRatioPercent());
	}

	@Test
	void testGetDashboardAnalyticsWithTrafficAndAuthFilters() {
		List<SubnetRollupRepository.RawScatterCluster> filteredClusters = List.of(
				new SubnetRollupRepository.RawScatterCluster("185.246.221.0/24", 800, 200, 600, 0L,
						35, 1, 3320L, "Deutsche Telekom AG", "DE", ClientType.RESIDENTIAL, 0L, 0L, 0L, 800L)
		);
		when(rollupRepository.findTimeline(any(), any(), any(), any())).thenReturn(List.of());
		when(rollupRepository.findTrafficComposition(any(), any(), any(), any())).thenReturn(List.of());
		when(rollupRepository.findScatterClusters(any(), any(), any(), any(), eq("SUBNET"), eq("EXCLUDE_BOTS"), eq("NO_LOGINS"), anyInt()))
				.thenReturn(filteredClusters);

		AnalyticsDashboardDto dto = analyticsService.getDashboardAnalytics(6, null, null, "SUBNET", "EXCLUDE_BOTS", "NO_LOGINS");

		assertNotNull(dto);
		assertEquals("SUBNET", dto.scatterGroupBy());
		assertEquals("EXCLUDE_BOTS", dto.scatterTrafficFilter());
		assertEquals("NO_LOGINS", dto.scatterAuthFilter());
		assertEquals(1, dto.scatterPoints().size());
		SubnetScatterPoint pt = dto.scatterPoints().get(0);
		assertEquals("185.246.221.0/24", pt.subnetGroup());
		assertEquals(0L, pt.authenticatedRequests());
		assertFalse(pt.hasLogins());
	}

	@Test
	void testGetAsnDrilldownCalculation() {
		Instant now = Instant.now();
		List<org.henbru.antidos.collector.model.AsnHourlyPoint> mockPoints = List.of(
				new org.henbru.antidos.collector.model.AsnHourlyPoint(
						now.minus(1, ChronoUnit.HOURS), "11:00", 50000, 150, 12000, 24.0, 0, 500, 1.0, 0, 1200, List.of("Pub01")
				),
				new org.henbru.antidos.collector.model.AsnHourlyPoint(
						now, "12:00", 30000, 100, 6000, 20.0, 0, 0, 0.0, 0, 800, List.of("Pub01", "Pub02")
				)
		);

		List<org.henbru.antidos.collector.model.AsnSubnetSummary> mockSubnets = List.of(
				new org.henbru.antidos.collector.model.AsnSubnetSummary(
						"198.51.100.0/24", 25000, 200, 0, 6000, 24.0, 0, 500, "US", ClientType.DATACENTER
				)
		);

		SubnetRollupRepository.AsnMeta mockMeta = new SubnetRollupRepository.AsnMeta(
				"GTT Communications", "US", ClientType.DATACENTER
		);

		when(rollupRepository.findAsnHourlyPoints(eq(3257L), any(), any())).thenReturn(mockPoints);
		when(rollupRepository.findAsnTopSubnets(eq(3257L), any(), any(), anyInt())).thenReturn(mockSubnets);
		when(rollupRepository.findAsnMeta(3257L)).thenReturn(mockMeta);

		org.henbru.antidos.collector.model.AsnDrilldownDto drilldown = analyticsService.getAsnDrilldown(3257L, 24);

		assertNotNull(drilldown);
		assertEquals(3257L, drilldown.asn());
		assertEquals("GTT Communications", drilldown.asOrg());
		assertEquals("US", drilldown.countryCode());
		assertEquals(80000L, drilldown.totalRequests());
		assertEquals(500L, drilldown.totalBlocked());
		assertEquals(18000L, drilldown.totalReturning());
		assertEquals(22.5, drilldown.overallReturningPct(), 0.1);
		assertEquals(50000L, drilldown.peakHourRequests());
		assertEquals(1, drilldown.topSubnets().size());
		assertEquals(2, drilldown.hourlyPoints().size());
		assertEquals(0, drilldown.distinctUserAgents());
		assertTrue(drilldown.topUserAgents().isEmpty());
	}

	@Test
	void testGetAsnDrilldownWithUserAgents() {
		Instant now = Instant.now();
		org.henbru.antidos.collector.storage.ClientEventRepository clientRepo = Mockito.mock(org.henbru.antidos.collector.storage.ClientEventRepository.class);
		AnalyticsService service = new AnalyticsService(rollupRepository, rollupAggregationService, null, null, clientRepo);

		List<org.henbru.antidos.collector.model.AsnHourlyPoint> mockPoints = List.of(
				new org.henbru.antidos.collector.model.AsnHourlyPoint(
						now, "12:00", 100000, 50, 0, 0.0, 0, 0, 0.0, 0, 1000, List.of("Pub01")
				)
		);
		List<org.henbru.antidos.collector.model.AsnSubnetSummary> mockSubnets = List.of(
				new org.henbru.antidos.collector.model.AsnSubnetSummary(
						"198.51.100.0/24", 50000, 0, 0, 0, 0.0, 0, 500, "US", ClientType.DATACENTER
				)
		);
		SubnetRollupRepository.AsnMeta mockMeta = new SubnetRollupRepository.AsnMeta(
				"Attacking Hosting ASN", "US", ClientType.DATACENTER
		);

		List<org.henbru.antidos.collector.model.AsnUserAgentSummary> mockUas = List.of(
				org.henbru.antidos.collector.model.AsnUserAgentSummary.of(
						"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
						60000, 100000, 1500, 45
				),
				org.henbru.antidos.collector.model.AsnUserAgentSummary.of(
						"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
						40000, 100000, 1000, 30
				)
		);

		when(rollupRepository.findAsnHourlyPoints(eq(64496L), any(), any())).thenReturn(mockPoints);
		when(rollupRepository.findAsnTopSubnets(eq(64496L), any(), any(), anyInt())).thenReturn(mockSubnets);
		when(rollupRepository.findAsnMeta(64496L)).thenReturn(mockMeta);
		when(clientRepo.countAsnDistinctUserAgents(eq(64496L), any(), any())).thenReturn(2);
		when(clientRepo.findAsnTopUserAgents(eq(64496L), any(), any(), anyInt(), eq(100000L))).thenReturn(mockUas);

		org.henbru.antidos.collector.model.AsnDrilldownDto drilldown = service.getAsnDrilldown(64496L, 24);

		assertNotNull(drilldown);
		assertEquals(2, drilldown.distinctUserAgents());
		assertEquals(2, drilldown.topUserAgents().size());

		org.henbru.antidos.collector.model.AsnUserAgentSummary topUa = drilldown.topUserAgents().get(0);
		assertEquals(60000, topUa.totalRequests());
		assertEquals(60.0, topUa.requestPct(), 0.1);
		assertEquals("Chrome 149", topUa.browserFamily());
		assertTrue(topUa.suspicious()); // Chrome >= 140 is suspicious/spoofed
		assertEquals(45, topUa.distinctSubnets());
	}
}
