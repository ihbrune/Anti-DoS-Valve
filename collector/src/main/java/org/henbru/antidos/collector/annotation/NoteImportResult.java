package org.henbru.antidos.collector.annotation;

import java.util.List;

/**
 * Result metrics and error messages returned after importing notes.
 */
public record NoteImportResult(
		int totalProcessed,
		int createdCount,
		int updatedCount,
		int skippedCount,
		List<String> warnings
) {
	public boolean hasWarnings() {
		return warnings != null && !warnings.isEmpty();
	}

	public String summaryMessage() {
		StringBuilder sb = new StringBuilder();
		sb.append("Import completed: ").append(createdCount).append(" created, ")
				.append(updatedCount).append(" updated, ")
				.append(skippedCount).append(" skipped (total: ").append(totalProcessed).append(").");
		return sb.toString();
	}
}
