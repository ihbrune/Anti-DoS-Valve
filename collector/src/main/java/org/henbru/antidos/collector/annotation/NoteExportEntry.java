package org.henbru.antidos.collector.annotation;

import java.time.Instant;
import org.henbru.antidos.collector.model.AnnotationTargetType;
import org.henbru.antidos.collector.model.AnnotationVerdict;

/**
 * Data transfer record representing a single exported/imported network annotation entry.
 */
public record NoteExportEntry(
		AnnotationTargetType targetType,
		String targetKey,
		AnnotationVerdict verdict,
		String noteMarkdown,
		Instant createdAt,
		Instant updatedAt
) {
}
