package org.henbru.antidos.collector.enrichment;

import jakarta.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.model.ClientType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Service managing hosting/cloud ASN sets and classifying client organizations into
 * DATACENTER, RESIDENTIAL, MOBILE, or UNKNOWN categories.
 */
@Service
public class AsnClassifierService {

	private static final Logger log = LoggerFactory.getLogger(AsnClassifierService.class);

	private static final List<String> HOSTING_KEYWORDS = List.of(
			"hosting", "cloud", "datacenter", "data center", "dedicated",
			"vps", "servers", "server", "colocation", "colo", "hoster",
			"fastly", "cloudflare", "akamai", "cdn"
	);

	private static final List<String> MOBILE_KEYWORDS = List.of(
			"cellular", "mobile", "wireless", "4g", "5g", "cgnat"
	);

	private static final List<String> RESIDENTIAL_KEYWORDS = List.of(
			"telekom", "vodafone", "telefonica", "o2", "orange", "dsl", "cable",
			"fiber", "broadband", "residential", "consumer", "dialup", "ftth", "gpon",
			"isp", "telecom", "comcast", "charter", "spectrum", "cox", "verizon",
			"centurylink", "swisscom", "kpn", "ziggo", "fastweb", "windtre", "iliad",
			"t-online", "netcologne", "m-net", "proximus", "telenet", "virgin media",
			"sky broadband", "talktalk", "bell canada", "rogers", "shaw", "telus",
			"optimum", "frontier", "vnpt", "viettel"
	);

	private final CollectorProperties properties;
	private final Set<Long> hostingAsns = new HashSet<>();

	public AsnClassifierService(CollectorProperties properties) {
		this.properties = properties;
	}

	@PostConstruct
	public void loadAsnDefinitions() {
		hostingAsns.clear();

		// 1. Load built-in default datacenter ASNs from classpath
		loadClasspathDefaults();

		// 2. Load custom datacenter ASNs from external file (overlay)
		String customFile = properties.getEnrichment().getCustomDatacenterAsnsFile();
		if (customFile != null && !customFile.trim().isEmpty()) {
			loadCustomFileOverlay(new File(customFile.trim()));
		}

		// 3. Load explicit numeric ASNs from collector-config.yaml / application.yaml
		List<Long> yamlCustom = properties.getEnrichment().getCustomDatacenterAsns();
		if (yamlCustom != null && !yamlCustom.isEmpty()) {
			hostingAsns.addAll(yamlCustom);
		}

		log.info("Initialized ASN classifier with {} known datacenter/cloud ASNs", hostingAsns.size());
	}

	private void loadClasspathDefaults() {
		InputStream stream = getClass().getResourceAsStream("/asns/default-datacenter-asns.txt");
		if (stream == null) {
			// Fallback for legacy resource path
			stream = getClass().getResourceAsStream("/asns/default-hosting-asns.txt");
		}
		if (stream == null) {
			log.warn("Default datacenter ASNs file '/asns/default-datacenter-asns.txt' not found on classpath");
			return;
		}
		try (InputStream is = stream; BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
			String line;
			while ((line = reader.readLine()) != null) {
				parseLine(line, true);
			}
		} catch (Exception e) {
			log.error("Failed to load default datacenter ASNs from classpath: {}", e.getMessage(), e);
		}
	}

	private void loadCustomFileOverlay(File file) {
		if (!file.exists() || !file.isFile()) {
			log.debug("Custom hosting ASNs file not present: {} (skipping overlay)", file.getAbsolutePath());
			return;
		}
		try (BufferedReader reader = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
			String line;
			int added = 0;
			int removed = 0;
			while ((line = reader.readLine()) != null) {
				String trimmed = line.trim();
				if (trimmed.startsWith("-")) {
					Long asn = parseAsn(trimmed.substring(1));
					if (asn != null && hostingAsns.remove(asn)) {
						removed++;
					}
				} else {
					String token = trimmed.startsWith("+") ? trimmed.substring(1) : trimmed;
					Long asn = parseAsn(token);
					if (asn != null && hostingAsns.add(asn)) {
						added++;
					}
				}
			}
			log.info("Loaded custom ASN overlay from {}: +{} added, -{} excluded", file.getAbsolutePath(), added, removed);
		} catch (Exception e) {
			log.warn("Failed to read custom hosting ASNs overlay from {}: {}", file.getAbsolutePath(), e.getMessage());
		}
	}

	private void parseLine(String line, boolean add) {
		String trimmed = line.trim();
		if (trimmed.isEmpty() || trimmed.startsWith("#")) {
			return;
		}
		// Strip comments
		int hashIdx = trimmed.indexOf('#');
		if (hashIdx >= 0) {
			trimmed = trimmed.substring(0, hashIdx).trim();
		}
		Long asn = parseAsn(trimmed);
		if (asn != null) {
			if (add) {
				hostingAsns.add(asn);
			} else {
				hostingAsns.remove(asn);
			}
		}
	}

	private Long parseAsn(String token) {
		if (token == null) {
			return null;
		}
		String clean = token.trim();
		int hashIdx = clean.indexOf('#');
		if (hashIdx >= 0) {
			clean = clean.substring(0, hashIdx).trim();
		}
		if (clean.toUpperCase(Locale.ROOT).startsWith("AS")) {
			clean = clean.substring(2).trim();
		}
		try {
			return Long.valueOf(clean);
		} catch (NumberFormatException ignored) {
			return null;
		}
	}

	public Set<Long> getHostingAsns() {
		return Collections.unmodifiableSet(hostingAsns);
	}

	public ClientType classify(Long asn, String asOrg) {
		if (asn == null && (asOrg == null || asOrg.trim().isEmpty())) {
			return ClientType.UNKNOWN;
		}

		if (asn != null && hostingAsns.contains(asn)) {
			return ClientType.DATACENTER;
		}

		if (asOrg != null && !asOrg.trim().isEmpty()) {
			String lower = asOrg.toLowerCase(Locale.ROOT);
			for (String kw : HOSTING_KEYWORDS) {
				if (lower.contains(kw)) {
					return ClientType.DATACENTER;
				}
			}
			for (String kw : MOBILE_KEYWORDS) {
				if (lower.contains(kw)) {
					return ClientType.MOBILE;
				}
			}
			for (String kw : RESIDENTIAL_KEYWORDS) {
				if (lower.contains(kw)) {
					return ClientType.RESIDENTIAL;
				}
			}
		}

		return ClientType.UNKNOWN;
	}

	public int getHostingAsnCount() {
		return hostingAsns.size();
	}
}
