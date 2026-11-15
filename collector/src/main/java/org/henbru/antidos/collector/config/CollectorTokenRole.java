package org.henbru.antidos.collector.config;

import java.util.Locale;

/**
 * Authorization roles assignable to configured Collector authentication tokens.
 */
public enum CollectorTokenRole {
	/**
	 * Full administrative privileges (bounded by the instance's {@link CollectorMode}).
	 */
	ADMIN,
	/**
	 * Analyst &amp; operator permissions: read dashboards/APIs plus manage notes, daily report notes/regeneration,
	 * and dynamic mitigation rules. System/maintenance admin endpoints remain forbidden (HTTP 403).
	 */
	OPERATOR,
	/**
	 * Autonomous AI assistant / bot triage role: operator-level write capabilities constrained by strict
	 * AI safety guardrails (TTL caps, hourly rate caps, prefix limits, minimum reason length, ownership checks).
	 */
	AI_AGENT,
	/**
	 * Strict read-only access to dashboards and read-only JSON GET APIs.
	 */
	VIEWER;

	public boolean canPerformSystemAdmin() {
		return this == ADMIN;
	}

	public boolean canModifyOperationalData() {
		return this == ADMIN || this == OPERATOR || this == AI_AGENT;
	}

	public boolean isAiAgent() {
		return this == AI_AGENT;
	}

	public boolean isViewer() {
		return this == VIEWER;
	}

	public boolean isOperatorEquivalent() {
		return this == OPERATOR || this == AI_AGENT;
	}

	public static CollectorTokenRole fromString(String value) {
		if (value == null || value.isBlank()) {
			return VIEWER;
		}
		String normalized = value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
		return switch (normalized) {
			case "ADMIN" -> ADMIN;
			case "OPERATOR" -> OPERATOR;
			case "AI_AGENT", "AI", "AGENT" -> AI_AGENT;
			case "VIEWER", "READ", "READ_ONLY", "READONLY" -> VIEWER;
			default -> throw new IllegalArgumentException(
					"Unknown collector token role '" + value + "'. Valid values: ADMIN, OPERATOR, AI_AGENT, VIEWER");
		};
	}
}
