package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * An individual IP address or CIDR range entry published by an intelligence source.
 */
public record IntelRange(
		Long id,
		String sourceKey,
		String cidr,
		int ipVersion,
		int cidrPrefix,
		Long ipV4Start,
		Long ipV4End,
		String ipV6Start,
		String ipV6End,
		Long asn,
		String countryCode,
		String category,
		String label,
		long sourceVersion,
		Instant createdAt
) {
}
