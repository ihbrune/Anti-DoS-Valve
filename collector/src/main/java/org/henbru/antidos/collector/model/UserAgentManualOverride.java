package org.henbru.antidos.collector.model;

/**
 * Administrative manual override status for a User-Agent profile.
 * Never overwritten by automatic heuristic evaluations.
 */
public enum UserAgentManualOverride {
	AUTO("Automatic (Follow Heuristic)", "badge-neutral", "&#x1F916;"),
	ALWAYS_ALLOW("Always Allowed (Protected)", "badge-success", "&#x1F6E1;&#xFE0F;"),
	MANUAL_BLOCK("Manual Block Candidate", "badge-danger", "&#x1F6AB;"),
	OBSERVE_ONLY("Observe Only (Watchlist)", "badge-warning", "&#x1F441;&#xFE0F;");

	private final String displayName;
	private final String badgeClass;
	private final String icon;

	UserAgentManualOverride(String displayName, String badgeClass, String icon) {
		this.displayName = displayName;
		this.badgeClass = badgeClass;
		this.icon = icon;
	}

	public String displayName() { return displayName; }
	public String badgeClass() { return badgeClass; }
	public String icon() { return icon; }

	public boolean isManual() {
		return this != AUTO;
	}

	public boolean isEffectiveSuspicious(UserAgentAutoVerdict autoVerdict) {
		return switch (this) {
			case MANUAL_BLOCK -> true;
			case ALWAYS_ALLOW, OBSERVE_ONLY -> false;
			case AUTO -> autoVerdict != null && autoVerdict.isSuspicious();
		};
	}

	public boolean isEffectiveProtected(UserAgentAutoVerdict autoVerdict) {
		if (this == ALWAYS_ALLOW) {
			return true;
		}
		if (this == MANUAL_BLOCK || this == OBSERVE_ONLY) {
			return false;
		}
		return autoVerdict != null && autoVerdict.isImmune();
	}

	public static UserAgentManualOverride fromString(String raw) {
		if (raw == null || raw.isBlank()) {
			return AUTO;
		}
		try {
			return UserAgentManualOverride.valueOf(raw.trim().toUpperCase());
		} catch (IllegalArgumentException e) {
			return AUTO;
		}
	}
}
