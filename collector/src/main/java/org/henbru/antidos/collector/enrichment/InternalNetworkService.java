package org.henbru.antidos.collector.enrichment;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.InternalNetworkConfig;
import org.henbru.antidos.collector.model.InternalNetworkMatch;
import org.henbru.antidos.collector.model.IpNetworkInfo;
import org.henbru.antidos.collector.util.IpNetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

/**
 * Service that maintains an in-memory index of configured corporate, campus, and intranet
 * IP network ranges and matches incoming client IPs and subnets against them.
 */
@Service
public class InternalNetworkService {

	private static final Logger log = LoggerFactory.getLogger(InternalNetworkService.class);

	public record ParsedInternalRange(
			String rawInput,
			String canonicalCidr,
			String name,
			String description,
			int ipVersion,
			Long v4Start,
			Long v4End,
			String v6Start,
			String v6End
	) {}

	private final CollectorProperties properties;
	private volatile List<ParsedInternalRange> activeRanges = Collections.emptyList();

	@Autowired
	public InternalNetworkService(CollectorProperties properties) {
		this.properties = properties;
		reload();
	}

	@PostConstruct
	public void init() {
		reload();
	}

	public synchronized void reload() {
		if (properties == null || properties.getInternalNetworks() == null) {
			this.activeRanges = Collections.emptyList();
			return;
		}

		List<ParsedInternalRange> parsed = new ArrayList<>();
		for (InternalNetworkConfig cfg : properties.getInternalNetworks()) {
			if (cfg == null || cfg.getCidr() == null || cfg.getCidr().isBlank()) {
				continue;
			}
			try {
				String raw = cfg.getCidr().trim();
				String normalizedCidr = normalizeWildcardOrCidr(raw);
				IpNetworkInfo info = IpNetworkUtil.parse(normalizedCidr);
				if (info != null && (info.v4Start() != null || info.v6Start() != null)) {
					String effectiveName = (cfg.getName() != null && !cfg.getName().isBlank())
							? cfg.getName().trim() : normalizedCidr;
					parsed.add(new ParsedInternalRange(
							raw,
							normalizedCidr,
							effectiveName,
							cfg.getDescription(),
							info.ipVersion(),
							info.v4Start(),
							info.v4End(),
							info.v6Start(),
							info.v6End()
					));
				} else {
					log.warn("Could not parse internal network configuration: '{}'", raw);
				}
			} catch (Exception e) {
				log.warn("Failed to parse internal network '{}': {}", cfg.getCidr(), e.getMessage());
			}
		}

		this.activeRanges = Collections.unmodifiableList(parsed);
		if (!parsed.isEmpty()) {
			log.info("Loaded {} internal/campus network ranges into memory index", parsed.size());
		}
	}

	/**
	 * Matches an IP address, client key, or subnet against the configured internal networks.
	 *
	 * @param clientKeyOrIp IP address (e.g. "198.51.100.42"), IP with port, or CIDR string
	 * @return InternalNetworkMatch with matched CIDR and metadata, or null if not matched
	 */
	public InternalNetworkMatch findMatch(String clientKeyOrIp) {
		if (clientKeyOrIp == null || clientKeyOrIp.isBlank() || activeRanges.isEmpty()) {
			return null;
		}

		String cleanIp = extractCleanIp(clientKeyOrIp);
		IpNetworkInfo clientNet = IpNetworkUtil.parse(cleanIp);
		if (clientNet == null) {
			return null;
		}

		if (clientNet.ipVersion() == 4 && clientNet.v4Start() != null) {
			long ip = clientNet.v4Start();
			for (ParsedInternalRange r : activeRanges) {
				if (r.ipVersion() == 4 && r.v4Start() != null && r.v4End() != null) {
					if (ip >= r.v4Start() && ip <= r.v4End()) {
						return new InternalNetworkMatch(r.canonicalCidr(), r.name(), r.description());
					}
				}
			}
		} else if (clientNet.ipVersion() == 6 && clientNet.v6Start() != null) {
			String v6Start = clientNet.v6Start();
			for (ParsedInternalRange r : activeRanges) {
				if (r.ipVersion() == 6 && r.v6Start() != null && r.v6End() != null) {
					if (v6Start.compareTo(r.v6Start()) >= 0 && v6Start.compareTo(r.v6End()) <= 0) {
						return new InternalNetworkMatch(r.canonicalCidr(), r.name(), r.description());
					}
				}
			}
		}

		return null;
	}

	public boolean isInternalNetwork(String clientKeyOrIp) {
		return findMatch(clientKeyOrIp) != null;
	}

	public List<ParsedInternalRange> getActiveRanges() {
		return activeRanges;
	}

	/**
	 * Normalizes wildcard or IP strings into standard CIDR notation:
	 * <ul>
	 *   <li>"198.51.100.*" &rarr; "198.51.100.0/24"</li>
	 *   <li>"198.51.*.*" or "198.51.*" &rarr; "198.51.0.0/16"</li>
	 *   <li>"10.*" &rarr; "10.0.0.0/8"</li>
	 *   <li>"198.51.100.5" &rarr; "198.51.100.5/32"</li>
	 *   <li>"198.51.100.0/24" &rarr; "198.51.100.0/24" (untouched)</li>
	 * </ul>
	 */
	public static String normalizeWildcardOrCidr(String input) {
		if (input == null || input.isBlank()) {
			return "";
		}
		String s = input.trim();
		if (s.contains("/")) {
			return s;
		}
		if (s.contains("*")) {
			String[] parts = s.split("\\.");
			StringBuilder ip = new StringBuilder();
			int definedOctets = 0;
			for (int i = 0; i < 4; i++) {
				if (i > 0) ip.append(".");
				if (i < parts.length && !parts[i].trim().equals("*") && !parts[i].trim().isEmpty()) {
					ip.append(parts[i].trim());
					definedOctets++;
				} else {
					ip.append("0");
				}
			}
			int prefix = definedOctets * 8;
			return ip.toString() + "/" + prefix;
		}
		if (s.contains(":")) {
			return s + "/128";
		}
		return s + "/32";
	}

	private static String extractCleanIp(String clientKey) {
		String s = clientKey.trim();
		int slash = s.indexOf('/');
		if (slash >= 0) {
			s = s.substring(0, slash);
		}
		int colon = s.indexOf(':');
		if (colon >= 0 && s.indexOf(':', colon + 1) < 0) {
			s = s.substring(0, colon);
		}
		if (s.startsWith("[") && s.endsWith("]")) {
			s = s.substring(1, s.length() - 1);
		}
		return s;
	}
}

