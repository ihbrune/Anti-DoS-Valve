package org.henbru.antidos.collector.model;

/**
 * Effective configuration for the 3-Pillar User-Agent heuristic and Stage-0 immunity barriers,
 * merging YAML defaults with live system_settings overrides.
 */
public record EffectiveUaHeuristicSettings(
		double internalImmunityMinRatioPct,
		long internalImmunityMinRequests,
		double searchEngineImmunityMinRatioPct,
		double authImmunityMinSampleRatioPct,
		double authImmunityMinSlotRatioPct,
		long spreadMinRequests,
		int spreadMinSubnets,
		int spreadMinAsns,
		double spreadMaxAvgSlotRequests,
		int spreadMinVersionLagMajors,
		long correlatedMinRequests,
		double correlatedMinIncidentRatioPct,
		double correlatedMinMitigatedAsnRatioPct,
		double correlatedMinUaMismatchRatioPct,
		long datacenterMinRequests,
		double datacenterMinRatioPct,
		boolean hasDatabaseOverrides
) {
	public static EffectiveUaHeuristicSettings defaults() {
		return new EffectiveUaHeuristicSettings(
				5.0, 100L, 50.0, 1.0, 2.0,
				2500L, 100, 20, 10.0, 2,
				2000L, 30.0, 40.0, 20.0,
				1500L, 80.0,
				false
		);
	}
}
