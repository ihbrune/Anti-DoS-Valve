package org.henbru.antidos.collector.docs;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DocumentationServiceTest {

	@Test
	void testGetDocumentationLoadsUiGuideByDefault() {
		DocumentationService service = new DocumentationService();
		DocumentationService.DocumentationPayload payload = service.getDocumentation();

		assertNotNull(payload);
		assertNotNull(payload.html());
		assertFalse(payload.html().isBlank());
		assertTrue(payload.title().contains("Dashboard & Forensics"));

		// Verify key UI sections are present
		assertTrue(payload.html().contains("Fleet Overview Dashboard"));
		assertTrue(payload.html().contains("Top Offender Analytics"));
		assertTrue(payload.html().contains("Incident Explorer"));
		assertTrue(payload.html().contains("System Status &amp; Configuration") || payload.html().contains("System Status & Configuration"));

		// Check TOC
		assertNotNull(payload.tableOfContents());
		assertFalse(payload.tableOfContents().isEmpty());

		boolean foundSystemConfig = false;
		for (DocumentationService.DocumentationTocItem item : payload.tableOfContents()) {
			assertNotNull(item.title());
			assertNotNull(item.anchorId());
			if (item.title().contains("System Status")) {
				foundSystemConfig = true;
				assertTrue(payload.html().contains("id=\"" + item.anchorId() + "\""));
			}
		}
		assertTrue(foundSystemConfig, "TOC should contain System Status & Configuration");

		// Test caching returns the exact same payload instance
		assertSame(payload, service.getDocumentation());
	}

	@Test
	void testGetDocumentationLoadsSetupGuide() {
		DocumentationService service = new DocumentationService();
		DocumentationService.DocumentationPayload payload = service.getDocumentation(DocumentationService.DOC_SETUP);

		assertNotNull(payload);
		assertNotNull(payload.html());
		assertFalse(payload.html().isBlank());
		assertTrue(payload.title().contains("Setup"));

		// Verify key DevOps / Setup sections are present
		assertTrue(payload.html().contains("Production Setup"));
		assertTrue(payload.html().contains("Database Configuration"));
		assertTrue(payload.html().contains("Relational Database Schema"));
		assertTrue(payload.html().contains("systemd"));
	}

	@Test
	void testGetSectionHtmlExtractsTargetSectionOnly() {
		DocumentationService service = new DocumentationService();

		// Extract section for Incident Explorer
		String sectionHtml = service.getSectionHtml(DocumentationService.DOC_UI, "incident-explorer");
		assertNotNull(sectionHtml);
		assertFalse(sectionHtml.isBlank());
		assertTrue(sectionHtml.contains("Incident Explorer &amp; Forensic Log Search") || sectionHtml.contains("Incident Explorer & Forensic Log Search"));
		assertTrue(sectionHtml.contains("Multi-Dimensional Filter Controls"));

		// Should NOT contain unrelated sections like Setup or Systemd
		assertFalse(sectionHtml.contains("Production Setup &amp; Zero-Friction"));

		// Extract section for System Status & Configuration
		String systemSectionHtml = service.getSectionHtml(DocumentationService.DOC_UI, "system-status-configuration");
		assertNotNull(systemSectionHtml);
		assertTrue(systemSectionHtml.contains("System Status &amp; Configuration") || systemSectionHtml.contains("System Status & Configuration"));
		assertTrue(systemSectionHtml.contains("Runtime &amp; Database Telemetry") || systemSectionHtml.contains("Runtime & Database Telemetry"));
		assertTrue(systemSectionHtml.contains("Operational Maintenance Triggers"));
	}

	@Test
	void testReadmeLinksAreRewrittenToInAppRoutes() {
		DocumentationService service = new DocumentationService();
		DocumentationService.DocumentationPayload readmePayload = service.getDocumentation(DocumentationService.DOC_README);

		assertNotNull(readmePayload);
		String html = readmePayload.html();

		// Verify links to DASHBOARD_GUIDE.md were rewritten to in-app /help?doc=ui
		assertTrue(html.contains("href=\"/help?doc=ui\""), "DASHBOARD_GUIDE.md link should be rewritten to /help?doc=ui");
		assertFalse(html.contains("href=\"DASHBOARD_GUIDE.md\""), "Raw markdown link DASHBOARD_GUIDE.md should not remain");

		// Verify links to SETUP_GUIDE.md were rewritten to in-app /help?doc=setup
		assertTrue(html.contains("href=\"/help?doc=setup\""), "SETUP_GUIDE.md link should be rewritten to /help?doc=setup");
		assertFalse(html.contains("href=\"SETUP_GUIDE.md\""), "Raw markdown link SETUP_GUIDE.md should not remain");
	}

	@Test
	void testExternalLinksOpenInNewTabWithSecurityAttributes() {
		DocumentationService service = new DocumentationService();
		DocumentationService.DocumentationPayload setupPayload = service.getDocumentation(DocumentationService.DOC_SETUP);

		assertNotNull(setupPayload);
		String html = setupPayload.html();

		// SETUP_GUIDE.md contains https://db-ip.com links
		assertTrue(html.contains("target=\"_blank\""), "External links should open in new tab");
		assertTrue(html.contains("rel=\"noopener noreferrer\""), "External links should contain noopener noreferrer");
	}
}
