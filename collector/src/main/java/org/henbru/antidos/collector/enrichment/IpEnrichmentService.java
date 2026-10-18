package org.henbru.antidos.collector.enrichment;

import org.henbru.antidos.collector.model.IpEnrichmentResult;

/**
 * Service for enriching an IP address or subnet partition with ASN, Geo, and classification metadata.
 */
public interface IpEnrichmentService {

	/**
	 * Enriches the given client IP or CIDR key.
	 *
	 * @param clientKey IP address or CIDR string (e.g. "198.51.100.42", "2001:db8::1/64")
	 * @return enriched result with ASN, organisation, country, and classification type
	 */
	IpEnrichmentResult enrich(String clientKey);
}
