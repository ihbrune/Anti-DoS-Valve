package org.henbru.antidos.collector.model;

/**
 * Result of matching an IP address or subnet against configured internal / campus networks.
 */
public record InternalNetworkMatch(
		String cidr,
		String name,
		String description
) {
	public String effectiveName() {
		return (name != null && !name.isBlank()) ? name.trim() : "Internal Network";
	}
}

