package org.henbru.antidos.collector.model;

/**
 * Summary statistics representing key counts for subnet profiles and anomaly radars.
 */
public record SubnetProfileStats(
		long totalProfiles,
		long active24h,
		long highSurge,
		long newSubnets,
		long dormantBreaks,
		long proxyPools
) {
	public static SubnetProfileStats empty() {
		return new SubnetProfileStats(0, 0, 0, 0, 0, 0);
	}
}
