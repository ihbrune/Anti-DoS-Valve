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

	@Test
	void testExportAndImportNotesAppendWithTextComparison() {
		// 1. Initial annotation
		annotationService.saveAnnotation(null, AnnotationTargetType.ASN, "AS24940", AnnotationVerdict.SUSPICIOUS, "Existing note for Hetzner");

		// 2. Export
		NoteExportDocument exported = annotationService.exportAnnotations();
		assertNotNull(exported);
		assertEquals(1, exported.count());
		assertEquals("AS24940", exported.notes().get(0).targetKey());

		// 3. Import identical content -> should skip because text is identical
		String jsonIdentical = """
				{
				  "version": 1,
				  "notes": [
				    {
				      "targetType": "ASN",
				      "targetKey": "AS24940",
				      "verdict": "SUSPICIOUS",
				      "noteMarkdown": "Existing note for Hetzner"
				    }
				  ]
				}
				""";
		NoteImportResult resultIdentical = annotationService.importAnnotations(
				new java.io.ByteArrayInputStream(jsonIdentical.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
				NoteImportConflictStrategy.APPEND
		);
		assertEquals(1, resultIdentical.totalProcessed());
		assertEquals(0, resultIdentical.createdCount());
		assertEquals(0, resultIdentical.updatedCount());
		assertEquals(1, resultIdentical.skippedCount());

		// 4. Import distinct content with APPEND -> should append with separator
		String jsonDifferent = """
				{
				  "version": 1,
				  "notes": [
				    {
				      "targetType": "ASN",
				      "targetKey": "AS24940",
				      "verdict": "MALICIOUS",
				      "noteMarkdown": "Second finding: brute-force campaign"
				    },
				    {
				      "targetType": "SUBNET",
				      "targetKey": "198.51.100.0/24",
				      "verdict": "LEGITIMATE",
				      "noteMarkdown": "New subnet note"
				    }
				  ]
				}
				""";
		NoteImportResult resultAppend = annotationService.importAnnotations(
				new java.io.ByteArrayInputStream(jsonDifferent.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
				NoteImportConflictStrategy.APPEND
		);
		assertEquals(2, resultAppend.totalProcessed());
		assertEquals(1, resultAppend.createdCount());
		assertEquals(1, resultAppend.updatedCount());
		assertEquals(0, resultAppend.skippedCount());

		Optional<NetworkAnnotation> updatedAsn = annotationService.findForAsn(24940L);
		assertTrue(updatedAsn.isPresent());
		assertTrue(updatedAsn.get().noteMarkdown().contains("Existing note for Hetzner"));
		assertTrue(updatedAsn.get().noteMarkdown().contains("Second finding: brute-force campaign"));
		assertTrue(updatedAsn.get().noteMarkdown().contains("---"));

		// 5. Test OVERWRITE strategy
		String jsonOverwrite = """
				{
				  "version": 1,
				  "notes": [
				    {
				      "targetType": "ASN",
				      "targetKey": "AS24940",
				      "verdict": "LEGITIMATE",
				      "noteMarkdown": "Completely replaced note"
				    }
				  ]
				}
				""";
		NoteImportResult resultOverwrite = annotationService.importAnnotations(
				new java.io.ByteArrayInputStream(jsonOverwrite.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
				NoteImportConflictStrategy.OVERWRITE
		);
		assertEquals(1, resultOverwrite.updatedCount());
		Optional<NetworkAnnotation> overwritten = annotationService.findForAsn(24940L);
		assertTrue(overwritten.isPresent());
		assertEquals("Completely replaced note", overwritten.get().noteMarkdown());
		assertEquals(AnnotationVerdict.LEGITIMATE, overwritten.get().verdict());

		// 6. Test SKIP strategy
		String jsonSkip = """
				{
				  "version": 1,
				  "notes": [
				    {
				      "targetType": "ASN",
				      "targetKey": "AS24940",
				      "verdict": "MALICIOUS",
				      "noteMarkdown": "Ignored note"
				    }
				  ]
				}
				""";
		NoteImportResult resultSkip = annotationService.importAnnotations(
				new java.io.ByteArrayInputStream(jsonSkip.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
				NoteImportConflictStrategy.SKIP
		);
		assertEquals(1, resultSkip.skippedCount());
		Optional<NetworkAnnotation> unchanged = annotationService.findForAsn(24940L);
		assertTrue(unchanged.isPresent());
		assertEquals("Completely replaced note", unchanged.get().noteMarkdown());
	}
}
