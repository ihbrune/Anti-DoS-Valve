package org.henbru.antidos.collector.config;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

class EndpointConfigTest {

	@Test
	void testConstructorWithStringsAndConfigs() {
		EndpointConfig ep = new EndpointConfig(
				"Test-Node", "http://test", "tok", false, true,
				List.of("Simple-Valve", new EndpointValveConfig("Overridden-Valve", true, 5, "2000"))
		);

		assertEquals(2, ep.getValves().size());
		assertTrue(ep.isValveIncluded("simple-valve"));
		assertTrue(ep.isValveIncluded("Overridden-Valve"));
		assertFalse(ep.isValveIncluded("Unknown-Valve"));

		assertTrue(ep.findValveConfig("Overridden-Valve").isPresent());
		assertEquals(5, ep.findValveConfig("Overridden-Valve").get().getActiveMinCount());
		assertEquals("2000", ep.findValveConfig("Overridden-Valve").get().getActiveLimit());
	}

	@Test
	void testStringConverter() {
		StringToEndpointValveConfigConverter converter = new StringToEndpointValveConfigConverter();
		EndpointValveConfig config = converter.convert("  My-Limiter  ");

		assertNotNull(config);
		assertEquals("My-Limiter", config.getName());
		assertNull(config.getCollectActive());

		assertNull(converter.convert("   "));
	}
}
