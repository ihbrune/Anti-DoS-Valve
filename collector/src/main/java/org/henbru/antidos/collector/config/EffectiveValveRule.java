package org.henbru.antidos.collector.config;

/**
 * Effective resolved telemetry and active tracking configuration for a valve.
 */
public record EffectiveValveRule(
		String valveName,
		boolean collectActive,
		int activeMinCount,
		String activeLimit,
		RuleSource source,
		boolean isIncluded
) {
	public enum RuleSource {
		ENDPOINT_OVERRIDE("Endpoint Override"),
		VALVE_RULE("Global Valve Rule"),
		GLOBAL_DEFAULT("Global Default"),
		SYSTEM_DEFAULT("System Default");

		private final String label;

		RuleSource(String label) {
			this.label = label;
		}

		public String getLabel() {
			return label;
		}
	}
}
