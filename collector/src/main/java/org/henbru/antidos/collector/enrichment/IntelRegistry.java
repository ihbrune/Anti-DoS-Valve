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

	private record IndexSnapshot(
			List<IntelRange> v4Ranges,
			long[] v4MaxEnd,
			List<IntelRange> v6Ranges,
			String[] v6MaxEnd
	) {
		static final IndexSnapshot EMPTY = new IndexSnapshot(
				List.of(), new long[0], List.of(), new String[0]);
	}

	private final IntelRangeRepository intelRangeRepository;
	private volatile IndexSnapshot snapshot = IndexSnapshot.EMPTY;

	@Autowired
	public IntelRegistry(IntelRangeRepository intelRangeRepository) {
		this.intelRangeRepository = intelRangeRepository;
	}

	@PostConstruct
	public void init() {
		reload();
	}

	/**
	 * Re-indexes all intelligence ranges from storage into memory using sorted interval arrays
	 * with prefix-maximum bounds for sub-microsecond O(log N) binary search lookups.
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

		v4.sort((a, b) -> {
			int cmp = Long.compare(a.ipV4Start(), b.ipV4Start());
			return cmp != 0 ? cmp : Long.compare(a.ipV4End(), b.ipV4End());
		});
		long[] v4MaxEnd = new long[v4.size()];
		long runningMaxV4 = Long.MIN_VALUE;
		for (int i = 0; i < v4.size(); i++) {
			long end = v4.get(i).ipV4End();
			if (end > runningMaxV4) {
				runningMaxV4 = end;
			}
			v4MaxEnd[i] = runningMaxV4;
		}

		v6.sort((a, b) -> {
			int cmp = a.ipV6Start().compareTo(b.ipV6Start());
			return cmp != 0 ? cmp : a.ipV6End().compareTo(b.ipV6End());
		});
		String[] v6MaxEnd = new String[v6.size()];
		String runningMaxV6 = "";
		for (int i = 0; i < v6.size(); i++) {
			String end = v6.get(i).ipV6End();
			if (end.compareTo(runningMaxV6) > 0) {
				runningMaxV6 = end;
			}
			v6MaxEnd[i] = runningMaxV6;
		}

		this.snapshot = new IndexSnapshot(
				Collections.unmodifiableList(v4),
				v4MaxEnd,
				Collections.unmodifiableList(v6),
				v6MaxEnd
		);

		log.info("IntelRegistry loaded {} IPv4 and {} IPv6 intelligence ranges into memory", v4.size(), v6.size());
	}

	public int size() {
		IndexSnapshot snap = this.snapshot;
		return snap.v4Ranges().size() + snap.v6Ranges().size();
	}

	public int getV4RangeCount() {
		return this.snapshot.v4Ranges().size();
	}

	public int getV6RangeCount() {
		return this.snapshot.v6Ranges().size();
	}

	/**
	 * Looks up all matching intelligence ranges overlapping the specified IP or subnet clientKey.
	 */
	public IntelLookupResult lookup(String clientKey) {
		if (clientKey == null || clientKey.trim().isEmpty()) {
			return IntelLookupResult.EMPTY;
		}

		IndexSnapshot snap = this.snapshot;
		IpNetworkInfo net = IpNetworkUtil.parse(clientKey);
		List<IntelRange> matched = new ArrayList<>();

		if (net.version() == 4 && net.v4Start() != null) {
			long qStart = net.v4Start();
			long qEnd = net.v4End() != null ? net.v4End() : qStart;
			List<IntelRange> v4 = snap.v4Ranges();
			long[] maxEnd = snap.v4MaxEnd();

			int low = 0;
			int high = v4.size() - 1;
			int rightMost = -1;
			while (low <= high) {
				int mid = (low + high) >>> 1;
				if (v4.get(mid).ipV4Start() <= qEnd) {
					rightMost = mid;
					low = mid + 1;
				} else {
					high = mid - 1;
				}
			}
			for (int i = rightMost; i >= 0; i--) {
				if (maxEnd[i] < qStart) {
					break;
				}
				IntelRange r = v4.get(i);
				if (r.ipV4End() >= qStart) {
					matched.add(r);
				}
			}
		} else if (net.version() == 6 && net.v6Start() != null) {
			String qStart = net.v6Start();
			String qEnd = net.v6End() != null ? net.v6End() : qStart;
			List<IntelRange> v6 = snap.v6Ranges();
			String[] maxEnd = snap.v6MaxEnd();

			int low = 0;
			int high = v6.size() - 1;
			int rightMost = -1;
			while (low <= high) {
				int mid = (low + high) >>> 1;
				if (v6.get(mid).ipV6Start().compareTo(qEnd) <= 0) {
					rightMost = mid;
					low = mid + 1;
				} else {
					high = mid - 1;
				}
			}
			for (int i = rightMost; i >= 0; i--) {
				if (maxEnd[i].compareTo(qStart) < 0) {
					break;
				}
				IntelRange r = v6.get(i);
				if (r.ipV6End().compareTo(qStart) >= 0) {
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
		// SEARCH_ENGINE / AI_CRAWLER > PRIVACY_RELAY > TOR_EXIT_NODE
		if (categories.contains("AI_CRAWLER")) {
			preferredType = ClientType.AI_CRAWLER;
		} else if (categories.contains("SEARCH_ENGINE")) {
			preferredType = ClientType.SEARCH_ENGINE;
		} else if (categories.contains("PRIVACY_RELAY")) {
			preferredType = ClientType.PRIVACY_RELAY;
		} else if (categories.contains("TOR_EXIT_NODE")) {
			preferredType = ClientType.TOR_EXIT_NODE;
		}

		String tags = tagList.isEmpty() ? null : String.join(",", tagList);
		return new IntelLookupResult(Collections.unmodifiableList(matched), categories, tags, preferredType, primaryLabel);
	}
}
