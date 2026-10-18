package org.henbru.antidos.collector.enrichment;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CountryResponse;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * High-performance offline reader for MaxMind and DB-IP Lite binary .mmdb databases (ASN and Country).
 */
public class MmdbEnrichmentProvider implements AutoCloseable {

	private static final Logger log = LoggerFactory.getLogger(MmdbEnrichmentProvider.class);

	public record RawGeoAsn(Long asn, String asOrg, String countryCode) {
	}

	private final DatabaseReader asnReader;
	private final DatabaseReader countryReader;

	public MmdbEnrichmentProvider(String asnDbPath, String countryDbPath) {
		this.asnReader = initReader(asnDbPath, "ASN");
		this.countryReader = initReader(countryDbPath, "Country");
	}

	private DatabaseReader initReader(String path, String label) {
		if (path == null || path.trim().isEmpty()) {
			return null;
		}
		File file = new File(path.trim());
		if (!file.exists() || !file.isFile()) {
			log.info("MMDB {} database not found at path: {} (enrichment for this type will be skipped)", label, path);
			return null;
		}
		try {
			DatabaseReader reader = new DatabaseReader.Builder(file).build();
			log.info("Successfully loaded MMDB {} database from: {}", label, file.getAbsolutePath());
			return reader;
		} catch (IOException e) {
			log.warn("Failed to load MMDB {} database from {}: {}", label, path, e.getMessage());
			return null;
		}
	}

	public boolean isAvailable() {
		return asnReader != null || countryReader != null;
	}

	public RawGeoAsn lookup(InetAddress address) {
		if (address == null) {
			return new RawGeoAsn(null, null, null);
		}

		Long asn = null;
		String asOrg = null;
		String countryCode = null;

		if (asnReader != null) {
			try {
				AsnResponse resp = asnReader.asn(address);
				asn = resp.getAutonomousSystemNumber();
				asOrg = resp.getAutonomousSystemOrganization();
			} catch (AddressNotFoundException ignored) {
				// IP not in ASN database
			} catch (IOException | GeoIp2Exception e) {
				log.debug("Error querying MMDB ASN for {}: {}", address, e.getMessage());
			}
		}

		if (countryReader != null) {
			try {
				CountryResponse resp = countryReader.country(address);
				if (resp.getCountry() != null) {
					countryCode = resp.getCountry().getIsoCode();
				}
			} catch (AddressNotFoundException ignored) {
				// IP not in Country database
			} catch (IOException | GeoIp2Exception e) {
				log.debug("Error querying MMDB Country for {}: {}", address, e.getMessage());
			}
		}

		return new RawGeoAsn(asn, asOrg, countryCode);
	}

	@Override
	public void close() {
		if (asnReader != null) {
			try {
				asnReader.close();
			} catch (IOException ignored) {
			}
		}
		if (countryReader != null) {
			try {
				countryReader.close();
			} catch (IOException ignored) {
			}
		}
	}
}
