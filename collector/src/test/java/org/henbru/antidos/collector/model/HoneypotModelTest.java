package org.henbru.antidos.collector.model;

import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HoneypotModelTest {

	@Test
	void testMonitoredValveIsHoneypot() {
		MonitoredValve honeypotValve = new MonitoredValve(
				"node-1", "HONEYPOT-PROBE-VALVE", "Honeypot trap", 1, "BLOCKING",
				false, true, 429, 0, 60, 5, 0.8f, 32, 64,
				1000, 1000, ".*\\.php", null, null, null,
				"/antidos-status", null, "auto", false, "_adv", Instant.now(), 12345
		);
		assertTrue(honeypotValve.isHoneypot());

		MonitoredValve lowerCaseHoneypot = new MonitoredValve(
				"node-1", "trap_honeypot_crawler", "Crawler trap", 2, "BLOCKING",
				false, true, 429, 0, 60, 5, 0.8f, 32, 64,
				1000, 1000, ".*", null, null, null,
				"/antidos-status", null, "auto", false, "_adv", Instant.now(), 12345
		);
		assertTrue(lowerCaseHoneypot.isHoneypot());

		MonitoredValve standardValve = new MonitoredValve(
				"node-1", "API-Rate-Limiter", "Standard API rate limiter", 3, "BLOCKING",
				false, false, 429, 50, 60, 5, 0.8f, 32, 64,
				1000, 1000, null, null, null, null,
				"/antidos-status", null, "auto", false, "_adv", Instant.now(), 12345
		);
		assertFalse(standardValve.isHoneypot());

		MonitoredValve nullNamedValve = new MonitoredValve(
				"node-1", null, null, 4, "BLOCKING",
				false, false, 429, 50, 60, 5, 0.8f, 32, 64,
				1000, 1000, null, null, null, null,
				"/antidos-status", null, "auto", false, "_adv", Instant.now(), 12345
		);
		assertFalse(nullNamedValve.isHoneypot());
	}

	@Test
	void testClientEventIsHoneypot() {
		Instant now = Instant.now();
		ClientEvent honeypotEvent = new ClientEvent(
				1L, "node-1", "HONEYPOT-TRAP", 100L, now, "198.51.100.42",
				4, 32, 0L, 0L, null, null, "198.51.100.0/24",
				1, 0, true, "BLOCKED", true, now,
				null, null, "DE", ClientType.DATACENTER, EnrichmentStatus.ENRICHED,
				null, 1, null, null
		);
		assertTrue(honeypotEvent.isHoneypot());

		ClientEvent regularEvent = new ClientEvent(
				2L, "node-1", "API-LIMITER", 100L, now, "198.51.100.42",
				4, 32, 0L, 0L, null, null, "198.51.100.0/24",
				55, 10, true, "BLOCKED", true, now,
				null, null, "DE", ClientType.DATACENTER, EnrichmentStatus.ENRICHED,
				null, 1, null, null
		);
		assertFalse(regularEvent.isHoneypot());

		ClientEvent nullValveEvent = new ClientEvent(
				3L, "node-1", null, 100L, now, "198.51.100.42",
				4, 32, 0L, 0L, null, null, "198.51.100.0/24",
				1, 0, true, "BLOCKED", true, now,
				null, null, "DE", ClientType.DATACENTER, EnrichmentStatus.ENRICHED,
				null, 1, null, null
		);
		assertFalse(nullValveEvent.isHoneypot());
	}
}
