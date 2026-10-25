package org.henbru.antidos.collector.model;

/**
 * Categorization verdict for a network annotation.
 */
public enum AnnotationVerdict {
	LEGITIMATE("Legitimate", "badge-success", "🟢", "#10b981"),
	INTERNAL("Internal Network", "badge-info", "🔵", "#38bdf8"),
	SUSPICIOUS("Suspicious", "badge-warning", "🟡", "#f59e0b"),
	MALICIOUS("Malicious", "badge-danger", "🔴", "#f43f5e"),
	INFO("Info", "badge-secondary", "⚪", "#94a3b8");

	private final String displayName;
	private final String badgeClass;
	private final String icon;
	private final String colorHex;

	AnnotationVerdict(String displayName, String badgeClass, String icon, String colorHex) {
		this.displayName = displayName;
		this.badgeClass = badgeClass;
		this.icon = icon;
		this.colorHex = colorHex;
	}

	public String displayName() {
		return displayName;
	}

	public String badgeClass() {
		return badgeClass;
	}

	public String icon() {
		return icon;
	}

	public String colorHex() {
		return colorHex;
	}
}
