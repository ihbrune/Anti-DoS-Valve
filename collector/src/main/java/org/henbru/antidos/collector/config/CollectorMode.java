package org.henbru.antidos.collector.config;

import java.util.Locale;

/**
 * Operational mode of the Anti-DoS Collector.
 */
public enum CollectorMode {

	/**
	 * Default full operational mode: runs background pollers, enrichment, mitigation,
	 * rollups, and the web dashboard/API.
	 */
	FULL,

	/**
	 * Background-only mode: runs all pollers, enrichment, mitigation, and rollups
	 * without starting an embedded web server or exposing HTTP endpoints.
	 */
	HEADLESS,

	/**
	 * Analyst and operator web UI mode: allows creating/editing network notes, commenting on and
	 * regenerating daily reports, and managing dynamic mitigation rules without background polling
	 * or system/admin maintenance access.
	 */
	OPERATOR,

	/**
	 * Strictly read-only web UI and REST API viewer for inspecting a Collector database
	 * without performing any database writes, migrations, or background processing.
	 */
	VIEWER;

	/**
	 * @return {@code true} if the embedded web server and HTTP controllers should run.
	 */
	public boolean isWebEnabled() {
		return this == FULL || this == OPERATOR || this == VIEWER;
	}

	/**
	 * @return {@code true} if background polling, enrichment, mitigation, and aggregation should run.
	 */
	public boolean isBackgroundProcessingEnabled() {
		return this == FULL || this == HEADLESS;
	}

	/**
	 * @return {@code true} if running in read-only {@link #VIEWER} mode.
	 */
	public boolean isViewer() {
		return this == VIEWER;
	}

	/**
	 * @return {@code true} if running in {@link #HEADLESS} mode.
	 */
	public boolean isHeadless() {
		return this == HEADLESS;
	}

	/**
	 * @return {@code true} if running in {@link #OPERATOR} mode.
	 */
	public boolean isOperator() {
		return this == OPERATOR;
	}

	/**
	 * @return {@code true} if operator/analyst actions (notes, daily reports, dynamic mitigation rules) are permitted.
	 */
	public boolean canModifyOperationalData() {
		return this == FULL || this == OPERATOR;
	}

	/**
	 * @return {@code true} if system/admin maintenance and configuration mutations are permitted.
	 */
	public boolean canPerformSystemAdmin() {
		return this == FULL;
	}

	/**
	 * Parses a case-insensitive mode name. Blank or null input returns {@link #FULL}.
	 *
	 * @param raw raw mode value
	 * @return parsed {@link CollectorMode}
	 */
	public static CollectorMode fromString(String raw) {
		if (raw == null || raw.isBlank()) {
			return FULL;
		}
		String normalized = raw.trim().toUpperCase(Locale.ROOT);
		for (CollectorMode candidate : values()) {
			if (candidate.name().equals(normalized)) {
				return candidate;
			}
		}
		throw new IllegalArgumentException(
				"Invalid collector.mode '" + raw + "'. Supported values: FULL, HEADLESS, OPERATOR, VIEWER.");
	}
}
