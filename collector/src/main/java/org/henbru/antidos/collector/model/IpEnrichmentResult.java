package org.henbru.antidos.collector.model;

/**
 * Result of resolving ASN, Geo, and Client Classification metadata for an IP.
 */
public record IpEnrichmentResult(
		Long asn,
		String asOrg,
		String countryCode,
		ClientType clientType
) {
	public static final IpEnrichmentResult UNKNOWN = new IpEnrichmentResult(null, null, null, ClientType.UNKNOWN);

	public static IpEnrichmentResult of(Long asn, String asOrg, String countryCode, ClientType clientType) {
		return new IpEnrichmentResult(asn, asOrg, countryCode, clientType != null ? clientType : ClientType.UNKNOWN);
	}
}
