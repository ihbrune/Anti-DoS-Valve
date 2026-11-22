package org.henbru.antidos.collector.model;

/**
 * Automated 3-pillar heuristic verdict (plus Stage-0 immunity protections)
 * assigned by the User-Agent memory and analytics engine.
 */
public enum UserAgentAutoVerdict {
	IMMUNE_INTERNAL("Internal / Campus Network", "badge-success", "&#x1F3DB;&#xFE0F;", true, false, "IMMUNITY"),
	IMMUNE_SEARCH_ENGINE("Verified Search Engine", "badge-info", "&#x1F50D;", true, false, "IMMUNITY"),
	IMMUNE_AUTHENTICATED("Authenticated User / App", "badge-success", "&#x2705;", true, false, "IMMUNITY"),
	SUSPICIOUS_ULTRA_SPREAD("Pillar 1: Ultra-Spread Botnet", "badge-danger", "&#x1F310;", false, true, "PILLAR_1"),
	SUSPICIOUS_CORRELATED("Pillar 2: Mitigation / Incident Correlated", "badge-danger", "&#x1F517;", false, true, "PILLAR_2"),
	SUSPICIOUS_DATACENTER("Pillar 3: Datacenter Zero-Auth Scraper", "badge-danger", "&#x1F3E2;", false, true, "PILLAR_3"),
	SUSPICIOUS_SIGNATURE("Automated Tool / Version Anomaly", "badge-warning", "&#x1F916;", false, true, "SIGNATURE"),
	NEUTRAL("Standard / Below Threshold", "badge-neutral", "&#x26AA;", false, false, "NONE");

	private final String displayName;
	private final String badgeClass;
	private final String icon;
	private final boolean immune;
	private final boolean suspicious;
	private final String pillarCode;

	UserAgentAutoVerdict(
			String displayName,
			String badgeClass,
			String icon,
			boolean immune,
			boolean suspicious,
			String pillarCode
	) {
		this.displayName = displayName;
		this.badgeClass = badgeClass;
		this.icon = icon;
		this.immune = immune;
		this.suspicious = suspicious;
		this.pillarCode = pillarCode;
	}

	public String displayName() { return displayName; }
	public String badgeClass() { return badgeClass; }
	public String icon() { return icon; }
	public boolean isImmune() { return immune; }
	public boolean isSuspicious() { return suspicious; }
	public String pillarCode() { return pillarCode; }

	public static UserAgentAutoVerdict fromString(String raw) {
		if (raw == null || raw.isBlank()) {
			return NEUTRAL;
		}
		try {
			return UserAgentAutoVerdict.valueOf(raw.trim().toUpperCase());
		} catch (IllegalArgumentException e) {
			return NEUTRAL;
		}
	}
}
