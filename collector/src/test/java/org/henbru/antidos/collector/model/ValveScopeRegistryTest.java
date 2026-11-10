package org.henbru.antidos.collector.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

class ValveScopeRegistryTest {

	@Test
	void testResolutionAndFallbacks() {
		ValveScopeRegistry registry = new ValveScopeRegistry(Map.of(
				"node1:api-valve", "UNAUTHENTICATED_ONLY",
				"node1:member-valve", "AUTHENTICATED_ONLY",
				"shared-valve", "UNAUTHENTICATED_ONLY"
		));

		// Server + Valve match
		assertEquals("UNAUTHENTICATED_ONLY", registry.getScope("node1", "api-valve"));
		assertTrue(registry.isUnauthenticatedOnly("node1", "api-valve"));
		assertFalse(registry.isAuthenticatedOnly("node1", "api-valve"));
		assertEquals("badge-warning", registry.getScopeBadgeClass("node1", "api-valve"));
		assertEquals("ANON ONLY", registry.getScopeLabel("node1", "api-valve"));
		assertTrue(registry.getScopeTooltip("node1", "api-valve").contains("UNAUTHENTICATED_ONLY"));

		assertEquals("AUTHENTICATED_ONLY", registry.getScope("node1", "member-valve"));
		assertFalse(registry.isUnauthenticatedOnly("node1", "member-valve"));
		assertTrue(registry.isAuthenticatedOnly("node1", "member-valve"));
		assertEquals("badge-success", registry.getScopeBadgeClass("node1", "member-valve"));
		assertEquals("AUTH ONLY", registry.getScopeLabel("node1", "member-valve"));
		assertTrue(registry.getScopeTooltip("node1", "member-valve").contains("AUTHENTICATED_ONLY"));

		// Fallback to valveName alone
		assertEquals("UNAUTHENTICATED_ONLY", registry.getScope("otherNode", "shared-valve"));
		assertTrue(registry.isUnauthenticatedOnly("otherNode", "shared-valve"));

		// Unknown defaults to ALL
		assertEquals("ALL", registry.getScope("unknown", "unknown"));
		assertFalse(registry.isUnauthenticatedOnly("unknown", "unknown"));
		assertFalse(registry.isAuthenticatedOnly("unknown", "unknown"));
		assertEquals("badge-secondary", registry.getScopeBadgeClass("unknown", "unknown"));
		assertEquals("ALL", registry.getScopeLabel("unknown", "unknown"));
		assertTrue(registry.getScopeTooltip("unknown", "unknown").contains("ALL"));
	}

	@Test
	void testNullSafeHandling() {
		ValveScopeRegistry registry = new ValveScopeRegistry(null);
		assertEquals("ALL", registry.getScope(null, null));
		assertFalse(registry.isUnauthenticatedOnly(null, null));
		assertFalse(registry.isAuthenticatedOnly(null, null));
		assertEquals("badge-secondary", registry.getScopeBadgeClass(null, null));
	}
}

