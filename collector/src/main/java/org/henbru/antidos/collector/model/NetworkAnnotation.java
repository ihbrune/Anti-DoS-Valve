package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * Domain entity representing a persistent operator annotation for an ASN or Subnet.
 * Completely immune to retention cleanup jobs.
 */
public record NetworkAnnotation(
		Long id,
		AnnotationTargetType targetType,
		String targetKey,
		Long asn,
		String subnetGroup,
		int ipVersion,
		int cidrPrefix,
		Long ipV4Start,
		Long ipV4End,
		String ipV6Start,
		String ipV6End,
		AnnotationVerdict verdict,
		String noteMarkdown,
		Instant createdAt,
		Instant updatedAt
) {
	public boolean isAsn() {
		return targetType == AnnotationTargetType.ASN;
	}

	public boolean isSubnet() {
		return targetType == AnnotationTargetType.SUBNET;
	}

	public String displayTitle() {
		if (isAsn()) {
			return targetKey != null && targetKey.toUpperCase().startsWith("AS") ? targetKey.toUpperCase() : "AS" + asn;
		}
		return subnetGroup != null ? subnetGroup : targetKey;
	}
}
