package org.henbru.antidos.collector.model;

import java.time.Instant;
import org.henbru.antidos.collector.util.IpNetworkUtil;

/**
 * Normalized network intelligence entity representing a unique clientKey (IP address or aggregated subnet).
 * Resolves ASN, organization, country, verified crawler / Tor / private classifications, and tags once per clientKey.
 */
public record NetworkEntity(
		Long id,
		String clientKey,
		int ipVersion,
		int cidrPrefix,
		Long ipV4Start,
		Long ipV4End,
		String ipV6Start,
		String ipV6End,
		String subnetGroup,
		String mmdbNetwork,
		Long asn,
		String asOrg,
		String countryCode,
		ClientType clientType,
		String tags,
		EnrichmentStatus enrichmentStatus,
		Instant resolvedAt,
		String resolvedVersions,
		Instant firstSeen,
		Instant lastSeen
) {
	/**
	 * Creates a pending network entity initialized from an IP/CIDR string.
	 */
	public static NetworkEntity pending(String clientKey, IpNetworkInfo net, Instant seenAt) {
		boolean isPrivate = IpNetworkUtil.isPrivateOrLocal(clientKey);
		String desc = isPrivate ? IpNetworkUtil.getPrivateNetworkDescription(clientKey) : null;
		return new NetworkEntity(
				null,
				clientKey,
				net.version(),
				net.prefix(),
				net.v4Start(),
				net.v4End(),
				net.v6Start(),
				net.v6End(),
				net.subnetGroup(),
				null,
				null,
				desc,
				null,
				isPrivate ? ClientType.PRIVATE_NETWORK : ClientType.UNKNOWN,
				isPrivate ? "PRIVATE_NETWORK" : null,
				isPrivate ? EnrichmentStatus.ENRICHED : EnrichmentStatus.PENDING,
				isPrivate ? seenAt : null,
				isPrivate ? "static" : null,
				seenAt,
				seenAt
		);
	}

	public NetworkEntity withId(Long newId) {
		return new NetworkEntity(
				newId,
				clientKey,
				ipVersion,
				cidrPrefix,
				ipV4Start,
				ipV4End,
				ipV6Start,
				ipV6End,
				subnetGroup,
				mmdbNetwork,
				asn,
				asOrg,
				countryCode,
				clientType,
				tags,
				enrichmentStatus,
				resolvedAt,
				resolvedVersions,
				firstSeen,
				lastSeen
		);
	}
}
