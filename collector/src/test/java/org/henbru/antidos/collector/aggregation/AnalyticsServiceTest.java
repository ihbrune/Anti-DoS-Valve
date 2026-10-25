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
}
