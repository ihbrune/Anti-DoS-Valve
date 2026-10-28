package org.henbru.antidos.collector.annotation;

import java.time.Instant;
import java.util.List;

/**
 * Root JSON document container for exporting and importing network notes.
 */
public record NoteExportDocument(
		int version,
		Instant exportedAt,
		int count,
		List<NoteExportEntry> notes
) {
	public static final int CURRENT_VERSION = 1;

	public NoteExportDocument(List<NoteExportEntry> notes) {
		this(CURRENT_VERSION, Instant.now(), notes != null ? notes.size() : 0, notes != null ? List.copyOf(notes) : List.of());
	}
}
