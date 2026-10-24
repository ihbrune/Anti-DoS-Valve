package org.henbru.antidos.collector.enrichment;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.henbru.antidos.collector.model.ClientType;
import org.henbru.antidos.collector.model.IntelRange;
import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.henbru.antidos.collector.storage.IntelRangeRepository;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

/**
 * In-memory index of all active CIDR ranges and metadata across intelligence sources.
 * Provides sub-microsecond interval-overlap lookups for client IP addresses and subnets.
 */
@Component
public class IntelRegistry {

	private static final Logger log = LoggerFactory.getLogger(IntelRegistry.class);

	public record IntelLookupResult(
			List<IntelRange> matches,
			Set<String> categories,
			String tags,
			ClientType preferredClientType,
			String primaryLabel
	) {
		public static final IntelLookupResult EMPTY = new IntelLookupResult(
				List.of(), Set.of(), null, null, null);
	}

	private final IntelRangeRepository intelRangeRepository;
	private final List<IntelRange> v4Ranges = new CopyOnWriteArrayList<>();
	private final List<IntelRange> v6Ranges = new CopyOnWriteArrayList<>();

	@Autowired
	public IntelRegistry(IntelRangeRepository intelRangeRepository) {
		this.intelRangeRepository = intelRangeRepository;
	}

	@PostConstruct
	public void init() {
		reload();
	}

	/**
	 * Re-indexes all intelligence ranges from storage into memory.
	 */
	public synchronized void reload() {
		List<IntelRange> all = intelRangeRepository.findAll();
		List<IntelRange> v4 = new ArrayList<>();
		List<IntelRange> v6 = new ArrayList<>();

		for (IntelRange r : all) {
			if (r.ipVersion() == 4 && r.ipV4Start() != null && r.ipV4End() != null) {
				v4.add(r);
			} else if (r.ipVersion() == 6 && r.ipV6Start() != null && r.ipV6End() != null) {
				v6.add(r);
			}
		}

		v4Ranges.clear();
		v4Ranges.addAll(v4);

		v6Ranges.clear();
		v6Ranges.addAll(v6);

		log.info("IntelRegistry loaded {} IPv4 and {} IPv6 intelligence ranges into memory", v4.size(), v6.size());
	}

	public int size() {
		return v4Ranges.size() + v6Ranges.size();
	}

	public int getV4RangeCount() {
		return v4Ranges.size();
	}

	public int getV6RangeCount() {
		return v6Ranges.size();
	}

	/**
	 * Looks up all matching intelligence ranges overlapping the specified IP or subnet clientKey.
	 */
	public IntelLookupResult lookup(String clientKey) {
		if (clientKey == null || clientKey.trim().isEmpty()) {
			return IntelLookupResult.EMPTY;
		}

		IpNetworkInfo net = IpNetworkUtil.parse(clientKey);
		List<IntelRange> matched = new ArrayList<>();

		if (net.version() == 4 && net.v4Start() != null) {
			long qStart = net.v4Start();
			long qEnd = net.v4End() != null ? net.v4End() : qStart;
			for (IntelRange r : v4Ranges) {
				if (r.ipV4Start() <= qEnd && r.ipV4End() >= qStart) {
					matched.add(r);
				}
			}
		} else if (net.version() == 6 && net.v6Start() != null) {
			String qStart = net.v6Start();
			String qEnd = net.v6End() != null ? net.v6End() : qStart;
			for (IntelRange r : v6Ranges) {
				if (r.ipV6Start().compareTo(qEnd) <= 0 && r.ipV6End().compareTo(qStart) >= 0) {
					matched.add(r);
				}
			}
		}

		if (matched.isEmpty()) {
			return IntelLookupResult.EMPTY;
		}

		Set<String> categories = new LinkedHashSet<>();
		List<String> tagList = new ArrayList<>();
		String primaryLabel = null;
		ClientType preferredType = null;

		for (IntelRange r : matched) {
			if (r.category() != null && !r.category().isBlank()) {
				String cat = r.category().trim();
				categories.add(cat);
				if (!tagList.contains(cat)) {
					tagList.add(cat);
				}
			}
			if (primaryLabel == null && r.label() != null && !r.label().isBlank()) {
				primaryLabel = r.label();
			}
		}

		// Priority resolution for ClientType:
		// SEARCH_ENGINE / AI_CRAWLER > TOR_EXIT_NODE
		if (categories.contains("AI_CRAWLER")) {
			preferredType = ClientType.AI_CRAWLER;
		} else if (categories.contains("SEARCH_ENGINE")) {
			preferredType = ClientType.SEARCH_ENGINE;
		} else if (categories.contains("TOR_EXIT_NODE")) {
			preferredType = ClientType.TOR_EXIT_NODE;
		}

		String tags = tagList.isEmpty() ? null : String.join(",", tagList);
		return new IntelLookupResult(Collections.unmodifiableList(matched), categories, tags, preferredType, primaryLabel);
	}
}
