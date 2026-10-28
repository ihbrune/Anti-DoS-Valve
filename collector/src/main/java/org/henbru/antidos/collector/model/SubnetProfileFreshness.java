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
		Instant earliestRollupStart,
		Instant lastProfilesRefreshedAt,
		int rollupWindowMinutes,
		boolean hasUnaggregatedEvents,
		long unaggregatedMinutes,
		long rollupAgeMinutes,
		double historyDays,
		boolean isCalibrating,
		boolean isInitializing
) {

	public static SubnetProfileFreshness of(
			Instant latestRollupEnd,
			Instant latestEventTime,
			Instant lastProfilesRefreshedAt,
			int rollupWindowMinutes
	) {
		return of(latestRollupEnd, latestEventTime, null, lastProfilesRefreshedAt, rollupWindowMinutes);
	}

	public static SubnetProfileFreshness of(
			Instant latestRollupEnd,
			Instant latestEventTime,
			Instant earliestRollupStart,
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

		double historyDays = 0.0;
		if (earliestRollupStart != null) {
			long hours = ChronoUnit.HOURS.between(earliestRollupStart, now);
			historyDays = Math.round((hours / 24.0) * 10.0) / 10.0;
		}

		boolean isInitializing = historyDays < 1.0;
		boolean isCalibrating = historyDays < 7.0;

		return new SubnetProfileFreshness(
				latestRollupEnd,
				latestEventTime,
				earliestRollupStart,
				lastProfilesRefreshedAt,
				rollupWindowMinutes,
				hasUnaggregated,
				unaggregatedMinutes,
				rollupAgeMinutes,
				historyDays,
				isCalibrating,
				isInitializing
		);
	}

	public boolean hasData() {
		return latestRollupEnd != null;
	}

	public String calibrationProgressText() {
		if (isInitializing) {
			return "Tag 1 (Initialisierung)";
		}
		int day = (int) Math.floor(historyDays) + 1;
		return "Tag " + Math.min(day, 7) + " von 7 (Kalibrierung)";
	}

	public String historyDaysText() {
		if (historyDays < 1.0) {
			long hours = (earliestRollupStart != null) ? ChronoUnit.HOURS.between(earliestRollupStart, Instant.now()) : 0;
			return hours + " Stunden";
		}
		return historyDays + " Tage";
	}

	public boolean isFresh() {
		return !hasUnaggregatedEvents || unaggregatedMinutes < 5;
	}
}
