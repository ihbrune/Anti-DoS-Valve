package org.henbru.antidos.collector.docs;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DocumentationServiceTest {

	@Test
	void testGetDocumentationLoadsAndRendersHtmlAndToc() {
		DocumentationService service = new DocumentationService();
		DocumentationService.DocumentationPayload payload = service.getDocumentation();

		assertNotNull(payload);
		assertNotNull(payload.html());
		assertFalse(payload.html().isBlank());

		// Verify key markdown elements were rendered to HTML
		assertTrue(payload.html().contains("<h1") || payload.html().contains("<h2"), "HTML should contain heading tags");
		assertTrue(payload.html().contains("Anti-DoS"), "HTML should contain main title");

		// Check TOC
		assertNotNull(payload.tableOfContents());
		assertFalse(payload.tableOfContents().isEmpty(), "TOC should contain extracted headings");

		// Check that TOC items have valid titles and anchor IDs
		boolean foundDemoMode = false;
		for (DocumentationService.DocumentationTocItem item : payload.tableOfContents()) {
			assertNotNull(item.title());
			assertNotNull(item.anchorId());
			assertFalse(item.anchorId().isBlank());
			if (item.title().contains("Demo Mode")) {
				foundDemoMode = true;
				// Anchors should match heading id attributes in HTML
				assertTrue(payload.html().contains("id=\"" + item.anchorId() + "\""),
						"HTML heading should have anchor id: " + item.anchorId());
			}
		}
		assertTrue(foundDemoMode, "TOC should contain Demo Mode heading");

		// Test caching returns the exact same payload instance
		assertSame(payload, service.getDocumentation());
	}
}
