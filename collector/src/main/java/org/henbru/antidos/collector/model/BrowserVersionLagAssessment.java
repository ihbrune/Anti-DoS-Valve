package org.henbru.antidos.collector.model;

/**
 * Analytical assessment of an observed client User-Agent version against authoritative release references.
 */
public enum BrowserVersionLagAssessment {
	CURRENT_STABLE("Current Stable", "badge-success", false),
	PRE_RELEASE_PLAUSIBLE("Preview Build", "badge-neutral", false),
	SUPPORTED_LEGACY("Supported Legacy", "badge-info", false),
	OUTDATED_LAG("Outdated Release", "badge-warning", false),
	OBSOLETE_ANOMALY("Obsolete Version (>3 yrs)", "badge-danger", true),
	IMPLAUSIBLE_FUTURE("Implausible Future Version", "badge-danger", true),
	UNTRACKED("Standard", "badge-neutral", false);

	private final String label;
	private final String badgeClass;
	private final boolean suspicious;

	BrowserVersionLagAssessment(String label, String badgeClass, boolean suspicious) {
		this.label = label;
		this.badgeClass = badgeClass;
		this.suspicious = suspicious;
	}

	public String label() {
		return label;
	}

	public String badgeClass() {
		return badgeClass;
	}

	public boolean isSuspicious() {
		return suspicious;
	}
}
