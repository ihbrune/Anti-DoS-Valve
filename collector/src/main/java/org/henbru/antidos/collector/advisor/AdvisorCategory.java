package org.henbru.antidos.collector.advisor;

/**
 * Functional category of a configuration or false-positive diagnostic finding.
 */
public enum AdvisorCategory {
	SEARCH_ENGINE_COLLATERAL("Search Engine Collateral", "Verified search engine crawlers blocked from indexing content"),
	INTERNAL_INFRASTRUCTURE("Internal / RFC 1918 Blocked", "Internal intranet, campus networks, health checks, or unforwarded reverse proxies blocked"),
	AUTHENTICATED_COLLATERAL("Authenticated User Collateral", "Legitimate authenticated users or active login sessions blocked by rate limits"),
	RESIDENTIAL_TUNING("Legitimate User / NAT Risk", "High-returning residential users or shared NAT gateways hitting strict rate caps"),
	DATACENTER_OFFLOAD("Datacenter Scraping Offload", "Massive cloud and bot scraping waves mitigated by Valve; edge offload candidate"),
	STEALTH_CARPET_ATTACK("Stealth Carpet Attack", "Distributed multi-subnet traffic waves evading local thresholds with low or zero blocks"),
	CHAMELEON_BOT("Chameleon Scraper / Bot", "Rotated user-agent fingerprints from single IP or subnet with zero authenticated or returning sessions"),
	SAMPLING_TUNING("Forensic Sampling Recommendation", "Valves handling subnet-aggregated traffic without forensic active request sampling");

	private final String label;
	private final String description;

	AdvisorCategory(String label, String description) {
		this.label = label;
		this.description = description;
	}

	public String getLabel() {
		return label;
	}

	public String getDescription() {
		return description;
	}
}
