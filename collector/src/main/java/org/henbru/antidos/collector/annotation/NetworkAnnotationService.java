package org.henbru.antidos.collector.annotation;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
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

	private final Map<Long, NetworkAnnotation> asnCache = new ConcurrentHashMap<>();
	private final Map<String, NetworkAnnotation> subnetCache = new ConcurrentHashMap<>();

	public NetworkAnnotationService(NetworkAnnotationRepository repository, AnnotationMarkdownService markdownService) {
		this.repository = repository;
		this.markdownService = markdownService;
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
