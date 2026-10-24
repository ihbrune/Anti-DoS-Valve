package org.henbru.antidos.collector.config;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValveRuleResolverTest {

	private CollectorProperties properties;
	private ValveRuleResolver resolver;

	@BeforeEach
	void setUp() {
		properties = new CollectorProperties();
		resolver = new ValveRuleResolver(properties);
	}

	@Test
	void testFallbackToGlobalDefaultWhenNoRulesDefined() {
		// Global default is collectActive=false, activeMinCount=10, activeLimit="1000"
		EndpointConfig endpoint = new EndpointConfig("Node-1", "http://localhost:8080", null, false, true);

		EffectiveValveRule rule = resolver.resolve(endpoint, "Any-Unconfigured-Valve");

		assertFalse(rule.collectActive());
		assertEquals(10, rule.activeMinCount());
		assertEquals("1000", rule.activeLimit());
		assertEquals(EffectiveValveRule.RuleSource.GLOBAL_DEFAULT, rule.source());
		assertTrue(rule.isIncluded());
	}

	@Test
	void testGlobalValveRuleMatchesByNameCaseInsensitively() {
		// Rule for Subnet-24-Limiter: activeMinCount=1
		properties.getValveRules().put("Subnet-24-Limiter", new ValveRuleConfig(true, 1, "5000"));

		EndpointConfig endpoint = new EndpointConfig("Node-1", "http://localhost:8080", null, false, true);

		// Resolve with lowercase matching
		EffectiveValveRule rule = resolver.resolve(endpoint, "subnet-24-limiter");

		assertTrue(rule.collectActive());
		assertEquals(1, rule.activeMinCount());
		assertEquals("5000", rule.activeLimit());
		assertEquals(EffectiveValveRule.RuleSource.VALVE_RULE, rule.source());
	}

	@Test
	void testGlobalValveRuleExplicitlyDisablingActiveTracking() {
		// Rule for Overlapping-Valve: collectActive=false to prevent double counting
		properties.getValveRules().put("Overlapping-Valve", new ValveRuleConfig(false, 10, "0"));

		EndpointConfig endpoint = new EndpointConfig("Node-1", "http://localhost:8080", null, false, true);

		EffectiveValveRule rule = resolver.resolve(endpoint, "Overlapping-Valve");

		assertFalse(rule.collectActive());
		assertEquals(EffectiveValveRule.RuleSource.VALVE_RULE, rule.source());
	}

	@Test
	void testEndpointOverrideTakesHighestPrecedence() {
		// Global rule: minCount=15
		properties.getValveRules().put("Standard-Limiter", new ValveRuleConfig(true, 15, "1000"));

		// Endpoint specifies an override: minCount=3, limit="200"
		EndpointValveConfig epValve = new EndpointValveConfig("Standard-Limiter", true, 3, "200");
		EndpointConfig endpoint = new EndpointConfig("Staging-Node", "http://localhost:8080", null, false, true, List.of(epValve));

		EffectiveValveRule rule = resolver.resolve(endpoint, "Standard-Limiter");

		assertTrue(rule.collectActive());
		assertEquals(3, rule.activeMinCount());
		assertEquals("200", rule.activeLimit());
		assertEquals(EffectiveValveRule.RuleSource.ENDPOINT_OVERRIDE, rule.source());
		assertTrue(rule.isIncluded());
	}

	@Test
	void testActiveMinCountZeroDisablesActiveTracking() {
		properties.getValveRules().put("Test-Limiter", new ValveRuleConfig(true, 0, "1000"));

		EffectiveValveRule rule = resolver.resolve(null, "Test-Limiter");

		assertFalse(rule.collectActive(), "minCount <= 0 must disable active tracking");
		assertEquals(0, rule.activeMinCount());
	}

	@Test
	void testValveInclusionStatusReflected() {
		EndpointConfig endpoint = new EndpointConfig("Filtered-Node", "http://localhost:8080", null, false, true, List.of("Wanted-Valve"));

		EffectiveValveRule wanted = resolver.resolve(endpoint, "Wanted-Valve");
		EffectiveValveRule unwanted = resolver.resolve(endpoint, "Unwanted-Valve");

		assertTrue(wanted.isIncluded());
		assertFalse(unwanted.isIncluded());
	}

	@Test
	void testGlobalValveRuleMatchesRelaxedWhenSpringBootStripsSpaces() {
		// When a user configures 'SUBNET MONITORING:' in YAML without brackets,
		// Spring Boot's relaxed binder strips the spaces, storing the key as 'SUBNETMONITORING'.
		properties.getValveRules().put("SUBNETMONITORING", new ValveRuleConfig(true, 1, "2000"));

		// The Tomcat valve reports its configured name with spaces: 'SUBNET MONITORING'
		EffectiveValveRule rule = resolver.resolve(null, "SUBNET MONITORING");

		assertTrue(rule.collectActive());
		assertEquals(1, rule.activeMinCount());
		assertEquals("2000", rule.activeLimit());
		assertEquals(EffectiveValveRule.RuleSource.VALVE_RULE, rule.source());
		assertEquals("SUBNET MONITORING", rule.valveName());
	}

	@Test
	void testGlobalValveRuleMatchesRelaxedWithDashesAndUnderscores() {
		properties.getValveRules().put("Subnet-24-Limiter", new ValveRuleConfig(true, 2, "3000"));

		// Match with spaces
		EffectiveValveRule ruleSpaces = resolver.resolve(null, "Subnet 24 Limiter");
		assertEquals(EffectiveValveRule.RuleSource.VALVE_RULE, ruleSpaces.source());
		assertEquals(2, ruleSpaces.activeMinCount());

		// Match with underscores
		EffectiveValveRule ruleUnderscores = resolver.resolve(null, "SUBNET_24_LIMITER");
		assertEquals(EffectiveValveRule.RuleSource.VALVE_RULE, ruleUnderscores.source());
		assertEquals(2, ruleUnderscores.activeMinCount());
	}

	@Test
	void testExactMatchTakesPrecedenceOverRelaxedMatch() {
		properties.getValveRules().put("SUBNETMONITORING", new ValveRuleConfig(true, 1, "1000"));
		properties.getValveRules().put("SUBNET MONITORING", new ValveRuleConfig(true, 5, "5000"));

		EffectiveValveRule exact = resolver.resolve(null, "SUBNET MONITORING");
		assertEquals(5, exact.activeMinCount());
		assertEquals("5000", exact.activeLimit());

		EffectiveValveRule stripped = resolver.resolve(null, "SUBNETMONITORING");
		assertEquals(1, stripped.activeMinCount());
		assertEquals("1000", stripped.activeLimit());
	}
}
