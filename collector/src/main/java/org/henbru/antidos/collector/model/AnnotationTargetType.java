package org.henbru.antidos.collector.model;

/**
 * Target type for a network annotation: an entire Autonomous System (ASN) or a Subnet (/24 or /64).
 */
public enum AnnotationTargetType {
	ASN("ASN", "Autonomous System"),
	SUBNET("Subnet", "IP Subnet (/24 or /64)");

	private final String displayName;
	private final String description;

	AnnotationTargetType(String displayName, String description) {
		this.displayName = displayName;
		this.description = description;
	}

	public String displayName() {
		return displayName;
	}

	public String description() {
		return description;
	}
}
