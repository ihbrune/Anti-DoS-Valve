package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Entity representing a permanent operational daily summary report.
 * Generated automatically before nightly retention cleanups to preserve
 * fleet-wide metrics, normalized peak rates, connectivity logs, and top threats.
 */
public record DailyReport(
		Long id,
		String reportDate, // "YYYY-MM-DD"
		String status,     // "NORMAL", "DEGRADED", "ATTACK_MITIGATED"
		long totalRequests,
		long totalBlocked,
		double peakRequestsPerSec,
		double peakBlockedPerSec,
		String peakValveName,
		String peakServerId,
		int serverCount,
		int incidentCount,
		String reportMarkdown,
		Instant createdAt,
		Instant updatedAt
) {

	public double blockRatePercentage() {
		if (totalRequests <= 0) {
			return 0.0;
		}
		return (totalBlocked * 100.0) / totalRequests;
	}

	public String formattedBlockRate() {
		return String.format(java.util.Locale.US, "%.2f%%", blockRatePercentage());
	}

	public String formattedPeakRequestsPerSec() {
		return String.format(java.util.Locale.US, "%.1f", peakRequestsPerSec);
	}

	public String formattedPeakBlockedPerSec() {
		return String.format(java.util.Locale.US, "%.1f", peakBlockedPerSec);
	}

	public String statusBadgeClass() {
		if (status == null) {
			return "badge-success";
		}
		return switch (status.toUpperCase()) {
			case "ATTACK_MITIGATED" -> "badge-danger";
			case "DEGRADED", "WARNING" -> "badge-warning";
			default -> "badge-success";
		};
	}

	public String statusIcon() {
		if (status == null) {
			return "🟢";
		}
		return switch (status.toUpperCase()) {
			case "ATTACK_MITIGATED" -> "🔴";
			case "DEGRADED", "WARNING" -> "🟡";
			default -> "🟢";
		};
	}

	public String statusLabel() {
		if (status == null) {
			return "OPERATIONAL";
		}
		return switch (status.toUpperCase()) {
			case "ATTACK_MITIGATED" -> "ATTACK MITIGATED";
			case "DEGRADED" -> "DEGRADED";
			case "WARNING" -> "WARNING";
			default -> "OPERATIONAL";
		};
	}
}
