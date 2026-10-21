package org.henbru.antidos.collector.enrichment;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

class AsnClassifierServiceTest {

	@Test
	void testDefaultHostingAsnsLoaded() {
		CollectorProperties properties = new CollectorProperties();
		AsnClassifierService service = new AsnClassifierService(properties);
		service.loadAsnDefinitions();

		// Check known default hosters
		assertTrue(service.getHostingAsns().contains(24940L)); // Hetzner
		assertTrue(service.getHostingAsns().contains(16509L)); // AWS
		assertTrue(service.getHostingAsns().contains(16276L)); // OVH
		assertTrue(service.getHostingAsns().contains(14061L)); // DigitalOcean
		assertTrue(service.getHostingAsns().contains(32934L)); // Meta Platforms (Facebook)

		assertEquals(ClientType.DATACENTER, service.classify(24940L, "Hetzner Online GmbH"));
		assertEquals(ClientType.DATACENTER, service.classify(16509L, "AMAZON-02"));
		assertEquals(ClientType.DATACENTER, service.classify(32934L, "FACEBOOK"));
		assertEquals(ClientType.DATACENTER, service.classify(32934L, "Meta Platforms, Inc."));
	}

	@Test
	void testCustomFileOverlayAddAndExclude(@TempDir File tempDir) throws Exception {
		File customFile = new File(tempDir, "custom-datacenter-asns.txt");
		Files.writeString(customFile.toPath(), """
				# Custom additions
				+99999 # My local data center
				88888  # Another test datacenter
				
				# Exclude a default hoster from datacenter classification
				-24940 # Treat Hetzner as residential for this test
				""");

		CollectorProperties properties = new CollectorProperties();
		properties.getEnrichment().setCustomDatacenterAsnsFile(customFile.getAbsolutePath());
		properties.getEnrichment().setCustomDatacenterAsns(List.of(77777L));

		AsnClassifierService service = new AsnClassifierService(properties);
		service.loadAsnDefinitions();

		assertTrue(service.getHostingAsns().contains(99999L));
		assertTrue(service.getHostingAsns().contains(88888L));
		assertTrue(service.getHostingAsns().contains(77777L)); // from yaml
		assertFalse(service.getHostingAsns().contains(24940L)); // excluded via '-'

		assertEquals(ClientType.DATACENTER, service.classify(99999L, "Local Colocation"));
		// Hetzner is excluded from hosting ASNs set, but would still match if keyword is present
		assertEquals(ClientType.RESIDENTIAL, service.classify(24940L, "Hetzner Consumer DSL"));
	}

	@Test
	void testKeywordHeuristics() {
		CollectorProperties properties = new CollectorProperties();
		AsnClassifierService service = new AsnClassifierService(properties);
		service.loadAsnDefinitions();

		// Unknown ASN, but hosting keyword in asOrg
		assertEquals(ClientType.DATACENTER, service.classify(12345L, "Super Server Cloud VPS Ltd"));
		assertEquals(ClientType.DATACENTER, service.classify(12345L, "Berlin Colocation & Hosting Services"));

		// Mobile keyword
		assertEquals(ClientType.MOBILE, service.classify(3320L, "Deutsche Telekom Mobile 5G CGNAT"));

		// Regular consumer ISP matching residential keywords
		assertEquals(ClientType.RESIDENTIAL, service.classify(3209L, "Vodafone Deutschland GmbH"));
		assertEquals(ClientType.RESIDENTIAL, service.classify(3320L, "Deutsche Telekom AG"));

		// Unknown organization without hosting, mobile, or residential keywords -> UNKNOWN (no false RESIDENTIAL fallback)
		assertEquals(ClientType.UNKNOWN, service.classify(999999L, "Random Enterprise LLC"));
		assertEquals(ClientType.UNKNOWN, service.classify(12345L, "Acme Industrial Corporation"));

		// Null/empty
		assertEquals(ClientType.UNKNOWN, service.classify(null, null));
		assertEquals(ClientType.UNKNOWN, service.classify(null, ""));
	}
}
