package org.henbru.antidos.collector.model;

import java.util.Collections;
import java.util.Map;

/**
 * In-memory registry and lookup helper for runtime Valve authentication scopes (ALL, UNAUTHENTICATED_ONLY, AUTHENTICATED_ONLY).
 * Used by UI templates and analytical evaluations to determine whether a valve evaluates all requests
 * or only unauthenticated/authenticated traffic.
 */
public class ValveScopeRegistry {

	private final Map<String, String> scopeMap;

	public ValveScopeRegistry(Map<String, String> scopeMap) {
		this.scopeMap = scopeMap != null ? Collections.unmodifiableMap(scopeMap) : Map.of();
	}

	/**
	 * Resolves the configured relevantAuthScope for the given server and valve name.
	 * Falls back to valveName alone if server-specific key is not found, or defaults to "ALL".
	 */
	public String getScope(String serverId, String valveName) {
		if (serverId != null && valveName != null) {
			String scope = scopeMap.get(serverId + ":" + valveName);
			if (scope != null) {
				return scope;
			}
		}
		if (valveName != null) {
			String scope = scopeMap.get(valveName);
			if (scope != null) {
				return scope;
			}
		}
		return "ALL";
	}

	public boolean isUnauthenticatedOnly(String serverId, String valveName) {
		return "UNAUTHENTICATED_ONLY".equalsIgnoreCase(getScope(serverId, valveName));
	}

	public boolean isAuthenticatedOnly(String serverId, String valveName) {
		return "AUTHENTICATED_ONLY".equalsIgnoreCase(getScope(serverId, valveName));
	}

	public String getScopeBadgeClass(String serverId, String valveName) {
		String scope = getScope(serverId, valveName).toUpperCase();
		return switch (scope) {
			case "AUTHENTICATED_ONLY" -> "badge-success";
			case "UNAUTHENTICATED_ONLY" -> "badge-warning";
			default -> "badge-secondary";
		};
	}

	public String getScopeLabel(String serverId, String valveName) {
		String scope = getScope(serverId, valveName).toUpperCase();
		return switch (scope) {
			case "AUTHENTICATED_ONLY" -> "AUTH ONLY";
			case "UNAUTHENTICATED_ONLY" -> "ANON ONLY";
			default -> "ALL";
		};
	}

	public String getScopeTooltip(String serverId, String valveName) {
		String scope = getScope(serverId, valveName).toUpperCase();
		return switch (scope) {
			case "AUTHENTICATED_ONLY" -> "Valve scope is AUTHENTICATED_ONLY: Evaluates only authenticated requests; unauthenticated requests bypass this valve.";
			case "UNAUTHENTICATED_ONLY" -> "Valve scope is UNAUTHENTICATED_ONLY: Evaluates only unauthenticated requests; authenticated sessions bypass this valve.";
			default -> "Valve scope is ALL: Evaluates all incoming requests regardless of authentication state.";
		};
	}

	public Map<String, String> asMap() {
		return scopeMap;
	}
}

