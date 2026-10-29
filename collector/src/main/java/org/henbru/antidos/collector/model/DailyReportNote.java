package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Entity representing operator notes and forensic annotations for a specific day.
 * Immune to automated report re-aggregations and retention purges.
 */
public record DailyReportNote(
		Long id,
		String reportDate, // "YYYY-MM-DD"
		String noteMarkdown,
		Instant createdAt,
		Instant updatedAt
) {
	public boolean hasContent() {
		return noteMarkdown != null && !noteMarkdown.isBlank();
	}
}

