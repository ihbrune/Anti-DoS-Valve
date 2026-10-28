package org.henbru.antidos.collector.annotation;

/**
 * Strategy applied when importing a network annotation whose target (ASN or Subnet)
 * already exists in the local database.
 */
public enum NoteImportConflictStrategy {
	/**
	 * Append imported note markdown to existing note markdown.
	 * If the text content is already identical, no changes are made.
	 */
	APPEND("Append note content (smart diff)"),

	/**
	 * Completely replace existing verdict and markdown with imported values.
	 */
	OVERWRITE("Overwrite existing note"),

	/**
	 * Retain existing note without any modifications.
	 */
	SKIP("Skip if already exists");

	private final String displayName;

	NoteImportConflictStrategy(String displayName) {
		this.displayName = displayName;
	}

	public String displayName() {
		return displayName;
	}
}
