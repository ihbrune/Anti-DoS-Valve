package org.henbru.antidos.collector.annotation;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.henbru.antidos.collector.model.AnnotationTargetType;
import org.henbru.antidos.collector.model.AnnotationVerdict;
import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.henbru.antidos.collector.model.NetworkAnnotation;
import org.henbru.antidos.collector.storage.NetworkAnnotationRepository;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Service managing persistent network annotations (ASN and Subnet notes).
 * Maintains an in-memory index for zero-latency lookup during event and forensic table rendering.
 */
@Service
public class NetworkAnnotationService {

	private static final Logger log = LoggerFactory.getLogger(NetworkAnnotationService.class);

	private final NetworkAnnotationRepository repository;
	private final AnnotationMarkdownService markdownService;
	private final ObjectMapper objectMapper;

	private final Map<Long, NetworkAnnotation> asnCache = new ConcurrentHashMap<>();
	private final Map<String, NetworkAnnotation> subnetCache = new ConcurrentHashMap<>();

	public NetworkAnnotationService(NetworkAnnotationRepository repository, AnnotationMarkdownService markdownService, ObjectMapper objectMapper) {
		this.repository = repository;
		this.markdownService = markdownService;
		this.objectMapper = objectMapper;
	}

	@PostConstruct
	public void loadCache() {
		refreshCache();
	}

	public synchronized void refreshCache() {
		try {
			List<NetworkAnnotation> all = repository.findAll("updated_desc");
			Map<Long, NetworkAnnotation> newAsn = new ConcurrentHashMap<>();
			Map<String, NetworkAnnotation> newSubnet = new ConcurrentHashMap<>();

			for (NetworkAnnotation a : all) {
				if (a.isAsn() && a.asn() != null) {
					newAsn.put(a.asn(), a);
				} else if (a.isSubnet()) {
					if (a.subnetGroup() != null && !a.subnetGroup().isBlank()) {
						newSubnet.put(a.subnetGroup(), a);
					}
					if (a.targetKey() != null && !a.targetKey().isBlank()) {
						newSubnet.put(a.targetKey(), a);
					}
				}
			}

			asnCache.clear();
			asnCache.putAll(newAsn);

			subnetCache.clear();
			subnetCache.putAll(newSubnet);

			log.info("Loaded {} network annotations into memory cache ({} ASNs, {} Subnets)",
					all.size(), newAsn.size(), newSubnet.size());
		} catch (Exception e) {
			log.warn("Could not populate annotation cache during startup: {}", e.getMessage());
		}
	}

	public List<NetworkAnnotation> getAnnotationsFiltered(AnnotationTargetType targetType, AnnotationVerdict verdict, String query, String sortBy) {
		return repository.findFiltered(targetType, verdict, query, sortBy);
	}

	public Optional<NetworkAnnotation> getAnnotationById(long id) {
		return repository.findById(id);
	}

	public Optional<NetworkAnnotation> getAnnotationByTarget(AnnotationTargetType targetType, String targetKey) {
		if (targetType == AnnotationTargetType.ASN) {
			Long asnNum = parseAsnNumber(targetKey);
			if (asnNum != null) {
				NetworkAnnotation cached = asnCache.get(asnNum);
				if (cached != null) return Optional.of(cached);
			}
		} else if (targetType == AnnotationTargetType.SUBNET && targetKey != null) {
			NetworkAnnotation cached = subnetCache.get(targetKey.trim());
			if (cached != null) return Optional.of(cached);
		}
		return repository.findByTarget(targetType, targetKey);
	}

	public NetworkAnnotation saveAnnotation(
			Long existingId,
			AnnotationTargetType targetType,
			String rawTargetKey,
			AnnotationVerdict verdict,
			String noteMarkdown
	) {
		if (targetType == null) {
			throw new IllegalArgumentException("Target type (ASN or SUBNET) is required");
		}
		if (rawTargetKey == null || rawTargetKey.trim().isEmpty()) {
			throw new IllegalArgumentException("Target key is required");
		}
		if (verdict == null) {
			verdict = AnnotationVerdict.INFO;
		}
		if (noteMarkdown == null) {
			noteMarkdown = "";
		}

		String cleanKey = rawTargetKey.trim();
		Long asn = null;
		String subnetGroup = null;
		int ipVersion = 4;
		int cidrPrefix = 32;
		Long v4Start = null;
		Long v4End = null;
		String v6Start = null;
		String v6End = null;

		if (targetType == AnnotationTargetType.ASN) {
			asn = parseAsnNumber(cleanKey);
			if (asn == null) {
				throw new IllegalArgumentException("Invalid ASN specification: '" + cleanKey + "'. Expected format: AS12345 or 12345");
			}
			cleanKey = "AS" + asn;
		} else {
			IpNetworkInfo netInfo = IpNetworkUtil.parse(cleanKey);
			subnetGroup = (netInfo.subnetGroup() != null && !netInfo.subnetGroup().isBlank())
					? netInfo.subnetGroup()
					: cleanKey;
			cleanKey = subnetGroup;
			IpNetworkInfo effectiveInfo = cleanKey.contains("/") ? IpNetworkUtil.parse(cleanKey) : netInfo;
			ipVersion = effectiveInfo.version();
			cidrPrefix = effectiveInfo.prefix();
			v4Start = effectiveInfo.v4Start();
			v4End = effectiveInfo.v4End();
			v6Start = effectiveInfo.v6Start();
			v6End = effectiveInfo.v6End();
		}

		Instant now = Instant.now();
		Instant createdAt = now;

		if (existingId != null) {
			Optional<NetworkAnnotation> existing = repository.findById(existingId);
			if (existing.isPresent()) {
				createdAt = existing.get().createdAt();
			}
		} else {
			Optional<NetworkAnnotation> existingByTarget = repository.findByTarget(targetType, cleanKey);
			if (existingByTarget.isPresent()) {
				createdAt = existingByTarget.get().createdAt();
			}
		}

		NetworkAnnotation annotation = new NetworkAnnotation(
				existingId,
				targetType,
				cleanKey,
				asn,
				subnetGroup,
				ipVersion,
				cidrPrefix,
				v4Start,
				v4End,
				v6Start,
				v6End,
				verdict,
				noteMarkdown.trim(),
				createdAt,
				now
		);

		repository.upsert(annotation);
		refreshCache();

		return getAnnotationByTarget(targetType, cleanKey).orElse(annotation);
	}

	public boolean deleteAnnotation(long id) {
		boolean deleted = repository.deleteById(id);
		if (deleted) {
			refreshCache();
		}
		return deleted;
	}

	public Optional<NetworkAnnotation> findForAsn(Long asn) {
		if (asn == null) {
			return Optional.empty();
		}
		NetworkAnnotation cached = asnCache.get(asn);
		if (cached != null) {
			return Optional.of(cached);
		}
		return repository.findByAsn(asn);
	}

	public Optional<NetworkAnnotation> findForSubnet(String subnetGroup) {
		if (subnetGroup == null || subnetGroup.isBlank()) {
			return Optional.empty();
		}
		NetworkAnnotation cached = subnetCache.get(subnetGroup.trim());
		if (cached != null) {
			return Optional.of(cached);
		}
		return repository.findBySubnet(subnetGroup);
	}

	public Map<Long, NetworkAnnotation> getAsnAnnotationMap() {
		return Collections.unmodifiableMap(asnCache);
	}

	public Map<String, NetworkAnnotation> getSubnetAnnotationMap() {
		return Collections.unmodifiableMap(subnetCache);
	}

	public Map<AnnotationVerdict, Long> getVerdictCounts() {
		return repository.countByVerdict();
	}

	public long getTotalCount() {
		return repository.count();
	}

	public String renderMarkdown(String markdown) {
		return markdownService.renderToHtml(markdown);
	}

	/**
	 * Exports all network annotations in a clean JSON-serializable document.
	 */
	public NoteExportDocument exportAnnotations() {
		List<NetworkAnnotation> all = repository.findAll("target");
		List<NoteExportEntry> entries = new ArrayList<>(all.size());
		for (NetworkAnnotation a : all) {
			entries.add(new NoteExportEntry(
					a.targetType(),
					a.targetKey(),
					a.verdict(),
					a.noteMarkdown() != null ? a.noteMarkdown() : "",
					a.createdAt(),
					a.updatedAt()
			));
		}
		return new NoteExportDocument(entries);
	}

	/**
	 * Imports network annotations from an input stream containing JSON data.
	 *
	 * @param inputStream      JSON stream
	 * @param conflictStrategy Strategy to use when an annotation for the target already exists (APPEND, OVERWRITE, SKIP)
	 * @return NoteImportResult containing counts of created, updated, skipped notes and any warnings
	 */
	public NoteImportResult importAnnotations(InputStream inputStream, NoteImportConflictStrategy conflictStrategy) {
		if (conflictStrategy == null) {
			conflictStrategy = NoteImportConflictStrategy.APPEND;
		}

		NoteExportDocument doc;
		try {
			doc = objectMapper.readValue(inputStream, NoteExportDocument.class);
		} catch (Exception e) {
			log.error("Failed to parse notes JSON document: {}", e.getMessage(), e);
			return new NoteImportResult(0, 0, 0, 0, List.of("Invalid JSON format: " + e.getMessage()));
		}

		if (doc == null || doc.notes() == null || doc.notes().isEmpty()) {
			return new NoteImportResult(0, 0, 0, 0, List.of("Import document contained no note entries."));
		}

		int created = 0;
		int updated = 0;
		int skipped = 0;
		List<String> warnings = new ArrayList<>();

		for (NoteExportEntry entry : doc.notes()) {
			if (entry == null || entry.targetType() == null || entry.targetKey() == null || entry.targetKey().isBlank()) {
				skipped++;
				warnings.add("Skipped invalid entry with missing targetType or targetKey.");
				continue;
			}

			try {
				String rawKey = entry.targetKey().trim();
				AnnotationTargetType type = entry.targetType();
				AnnotationVerdict verdict = entry.verdict() != null ? entry.verdict() : AnnotationVerdict.INFO;
				String incomingMarkdown = entry.noteMarkdown() != null ? entry.noteMarkdown().trim() : "";

				// Look up existing annotation
				Optional<NetworkAnnotation> existingOpt = getAnnotationByTarget(type, rawKey);

				if (existingOpt.isEmpty()) {
					// New note
					saveAnnotation(null, type, rawKey, verdict, incomingMarkdown);
					created++;
				} else {
					NetworkAnnotation existing = existingOpt.get();
					String existingMarkdown = existing.noteMarkdown() != null ? existing.noteMarkdown().trim() : "";

					switch (conflictStrategy) {
						case SKIP -> {
							skipped++;
						}
						case OVERWRITE -> {
							// Check if there is any difference
							boolean verdictChanged = existing.verdict() != verdict;
							boolean textChanged = !existingMarkdown.equals(incomingMarkdown);
							if (verdictChanged || textChanged) {
								saveAnnotation(existing.id(), type, rawKey, verdict, incomingMarkdown);
								updated++;
							} else {
								// Completely identical
								skipped++;
							}
						}
						case APPEND -> {
							// Text comparison: does incoming text differ from existing text?
							// If incoming note is empty, or identical to existing note, skip.
							if (incomingMarkdown.isEmpty() || existingMarkdown.equals(incomingMarkdown)) {
								// Check if verdict differs
								if (existing.verdict() != verdict && verdict != AnnotationVerdict.INFO) {
									saveAnnotation(existing.id(), type, rawKey, verdict, existingMarkdown);
									updated++;
								} else {
									skipped++;
								}
							} else if (existingMarkdown.contains(incomingMarkdown)) {
								// Incoming content is already a substring/part of the existing note
								if (existing.verdict() != verdict && verdict != AnnotationVerdict.INFO) {
									saveAnnotation(existing.id(), type, rawKey, verdict, existingMarkdown);
									updated++;
								} else {
									skipped++;
								}
							} else {
								// Distinct text -> append with divider
								String mergedText;
								if (existingMarkdown.isEmpty()) {
									mergedText = incomingMarkdown;
								} else {
									mergedText = existingMarkdown + "\n\n---\n\n" + incomingMarkdown;
								}
								// If existing verdict is INFO and imported has a specific verdict, upgrade to imported verdict
								AnnotationVerdict effectiveVerdict = (existing.verdict() == AnnotationVerdict.INFO && verdict != AnnotationVerdict.INFO)
										? verdict
										: existing.verdict();

								saveAnnotation(existing.id(), type, rawKey, effectiveVerdict, mergedText);
								updated++;
							}
						}
					}
				}
			} catch (Exception ex) {
				log.warn("Failed to import note entry {}: {}", entry.targetKey(), ex.getMessage());
				skipped++;
				warnings.add("Failed to process '" + entry.targetKey() + "': " + ex.getMessage());
			}
		}

		refreshCache();
		return new NoteImportResult(doc.notes().size(), created, updated, skipped, warnings);
	}

	private Long parseAsnNumber(String input) {
		if (input == null || input.isBlank()) {
			return null;
		}
		String s = input.trim().toUpperCase();
		if (s.startsWith("AS")) {
			s = s.substring(2).trim();
		}
		try {
			return Long.parseLong(s);
		} catch (NumberFormatException e) {
			return null;
		}
	}
}
