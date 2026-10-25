package org.henbru.antidos.collector.annotation;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.henbru.antidos.collector.model.AnnotationTargetType;
import org.henbru.antidos.collector.model.AnnotationVerdict;
import org.henbru.antidos.collector.model.NetworkAnnotation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class NetworkAnnotationServiceTest {

	@Autowired
	private NetworkAnnotationService annotationService;

	@Autowired
	private org.henbru.antidos.collector.storage.NetworkAnnotationRepository repository;

	@BeforeEach
	void setUp() {
		for (NetworkAnnotation a : repository.findAll("updated_desc")) {
			repository.deleteById(a.id());
		}
		annotationService.refreshCache();
	}

	@Test
	void testSaveAsnNormalizesPrefixAndPopulatesCache() {
		NetworkAnnotation saved = annotationService.saveAnnotation(
				null,
				AnnotationTargetType.ASN,
				"24940",
				AnnotationVerdict.SUSPICIOUS,
				"### Hetzner Online\n- Many aggressive scrapers"
		);

		assertNotNull(saved.id());
		assertEquals("AS24940", saved.targetKey());
		assertEquals(24940L, saved.asn());
		assertEquals(AnnotationVerdict.SUSPICIOUS, saved.verdict());

		// Test cache lookup by numeric ASN
		Optional<NetworkAnnotation> cached = annotationService.findForAsn(24940L);
		assertTrue(cached.isPresent());
		assertEquals("AS24940", cached.get().targetKey());

		Map<Long, NetworkAnnotation> asns = annotationService.getAsnAnnotationMap();
		assertTrue(asns.containsKey(24940L));
	}

	@Test
	void testSaveSubnetCalculatesCidrAndRange() {
		NetworkAnnotation saved = annotationService.saveAnnotation(
				null,
				AnnotationTargetType.SUBNET,
				"198.51.100.42",
				AnnotationVerdict.LEGITIMATE,
				"- Partner API gateway"
		);

		assertNotNull(saved.id());
		assertEquals("198.51.100.0/24", saved.subnetGroup());
		assertEquals("198.51.100.0/24", saved.targetKey());
		assertEquals(24, saved.cidrPrefix());
		assertEquals(4, saved.ipVersion());

		// Test cache lookup
		Optional<NetworkAnnotation> cached = annotationService.findForSubnet("198.51.100.0/24");
		assertTrue(cached.isPresent());
		assertEquals(AnnotationVerdict.LEGITIMATE, cached.get().verdict());
	}

	@Test
	void testMarkdownRendering() {
		String md = """
				# Headline
				- Item 1
				- Item 2
				[Link](https://example.com)
				""";
		String html = annotationService.renderMarkdown(md);
		assertTrue(html.contains("<h1>Headline</h1>"));
		assertTrue(html.contains("<li>Item 1</li>"));
		assertTrue(html.contains("target=\"_blank\""));
		assertTrue(html.contains("rel=\"noopener noreferrer\""));
	}

	@Test
	void testFilterAndVerdictCounts() {
		annotationService.saveAnnotation(null, AnnotationTargetType.ASN, "AS15169", AnnotationVerdict.LEGITIMATE, "Googlebot");
		annotationService.saveAnnotation(null, AnnotationTargetType.ASN, "AS14061", AnnotationVerdict.MALICIOUS, "Scanners");
		annotationService.saveAnnotation(null, AnnotationTargetType.SUBNET, "192.168.1.0/24", AnnotationVerdict.INTERNAL, "LAN");

		Map<AnnotationVerdict, Long> counts = annotationService.getVerdictCounts();
		assertEquals(1L, counts.get(AnnotationVerdict.LEGITIMATE));
		assertEquals(1L, counts.get(AnnotationVerdict.MALICIOUS));
		assertEquals(1L, counts.get(AnnotationVerdict.INTERNAL));
		assertEquals(3L, annotationService.getTotalCount());

		// Filter by target type
		List<NetworkAnnotation> asnsOnly = annotationService.getAnnotationsFiltered(AnnotationTargetType.ASN, null, null, "updated_desc");
		assertEquals(2, asnsOnly.size());

		// Filter by query
		List<NetworkAnnotation> queryResult = annotationService.getAnnotationsFiltered(null, null, "scanners", "updated_desc");
		assertEquals(1, queryResult.size());
		assertEquals("AS14061", queryResult.get(0).targetKey());
	}
}
