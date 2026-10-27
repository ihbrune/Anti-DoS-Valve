package org.henbru.antidos.collector.model;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Encapsulates the freshness and data cutoff state of calculated subnet profiles and rollups,
 * exposing any lag between real-time incoming events and completed periodic rollup windows.
 */
public record SubnetProfileFreshness(
		Instant latestRollupEnd,
		Instant latestEventTime,
		Instant lastProfilesRefreshedAt,
		int rollupWindowMinutes,
		boolean hasUnaggregatedEvents,
		long unaggregatedMinutes,
		long rollupAgeMinutes
) {

	public static SubnetProfileFreshness of(
			Instant latestRollupEnd,
			Instant latestEventTime,
			Instant lastProfilesRefreshedAt,
			int rollupWindowMinutes
	) {
		Instant now = Instant.now();
		long rollupAgeMinutes = (latestRollupEnd != null)
				? Math.max(0, ChronoUnit.MINUTES.between(latestRollupEnd, now))
				: -1;

		boolean hasUnaggregated = false;
		long unaggregatedMinutes = 0;

		if (latestEventTime != null) {
			if (latestRollupEnd == null) {
				hasUnaggregated = true;
				unaggregatedMinutes = Math.max(0, ChronoUnit.MINUTES.between(latestEventTime, now));
			} else if (latestEventTime.isAfter(latestRollupEnd)) {
				long diffMinutes = ChronoUnit.MINUTES.between(latestRollupEnd, latestEventTime);
				if (diffMinutes > 0) {
					hasUnaggregated = true;
					unaggregatedMinutes = diffMinutes;
				}
			}
		}

		return new SubnetProfileFreshness(
				latestRollupEnd,
				latestEventTime,
				lastProfilesRefreshedAt,
				rollupWindowMinutes,
				hasUnaggregated,
				unaggregatedMinutes,
				rollupAgeMinutes
		);
	}

	public boolean hasData() {
		return latestRollupEnd != null;
	}

	public boolean isFresh() {
		return !hasUnaggregatedEvents || unaggregatedMinutes < 5;
	}
}
