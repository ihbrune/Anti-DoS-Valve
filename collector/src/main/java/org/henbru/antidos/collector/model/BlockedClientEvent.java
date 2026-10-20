package org.henbru.antidos.collector.model;

import java.time.Instant;
import org.henbru.antidos.collector.util.IpNetworkUtil;

/**
 * Details of an individual blocked client IP or subnet partition recorded during a slot.
 */
public record BlockedClientEvent(
		Long id,
		String serverId,
		String valveName,
		long slotKey,
		Instant slotTime,
		String clientKey,
		int ipVersion,
		int cidrPrefix,
		Long ipV4Start,
		Long ipV4End,
		String ipV6Start,
		String ipV6End,
		String subnetGroup,
		int requestCount,
		int retainedCount,
		boolean locked,
		boolean completed,
		Instant lastUpdatedAt,
		Long asn,
		String asOrg,
		String countryCode,
		ClientType clientType,
		EnrichmentStatus enrichmentStatus,
		Long entityId
) {

	/**
	 * Backwards-compatible convenience constructor that automatically resolves network metadata from clientKey
	 * and initializes enrichment fields to default PENDING state.
	 */
	public BlockedClientEvent(
			Long id,
			String serverId,
			String valveName,
			long slotKey,
			Instant slotTime,
			String clientKey,
			int requestCount,
			int retainedCount,
			boolean locked,
			boolean completed,
			Instant lastUpdatedAt
	) {
		this(
				id,
				serverId,
				valveName,
				slotKey,
				slotTime,
				clientKey,
				IpNetworkUtil.parse(clientKey),
				requestCount,
				retainedCount,
				locked,
				completed,
				lastUpdatedAt,
				null,
				null,
				null,
				ClientType.UNKNOWN,
				EnrichmentStatus.PENDING,
				null
		);
	}

	/**
	 * Backwards-compatible constructor without explicit enrichment parameters.
	 */
	public BlockedClientEvent(
			Long id,
			String serverId,
			String valveName,
			long slotKey,
			Instant slotTime,
			String clientKey,
			int ipVersion,
			int cidrPrefix,
			Long ipV4Start,
			Long ipV4End,
			String ipV6Start,
			String ipV6End,
			String subnetGroup,
			int requestCount,
			int retainedCount,
			boolean locked,
			boolean completed,
			Instant lastUpdatedAt
	) {
		this(
				id,
				serverId,
				valveName,
				slotKey,
				slotTime,
				clientKey,
				ipVersion,
				cidrPrefix,
				ipV4Start,
				ipV4End,
				ipV6Start,
				ipV6End,
				subnetGroup,
				requestCount,
				retainedCount,
				locked,
				completed,
				lastUpdatedAt,
				null,
				null,
				null,
				ClientType.UNKNOWN,
				EnrichmentStatus.PENDING,
				null
		);
	}

	/**
	 * Backwards-compatible constructor with enrichment parameters but without entityId.
	 */
	public BlockedClientEvent(
			Long id,
			String serverId,
			String valveName,
			long slotKey,
			Instant slotTime,
			String clientKey,
			int ipVersion,
			int cidrPrefix,
			Long ipV4Start,
			Long ipV4End,
			String ipV6Start,
			String ipV6End,
			String subnetGroup,
			int requestCount,
			int retainedCount,
			boolean locked,
			boolean completed,
			Instant lastUpdatedAt,
			Long asn,
			String asOrg,
			String countryCode,
			ClientType clientType,
			EnrichmentStatus enrichmentStatus
	) {
		this(
				id,
				serverId,
				valveName,
				slotKey,
				slotTime,
				clientKey,
				ipVersion,
				cidrPrefix,
				ipV4Start,
				ipV4End,
				ipV6Start,
				ipV6End,
				subnetGroup,
				requestCount,
				retainedCount,
				locked,
				completed,
				lastUpdatedAt,
				asn,
				asOrg,
				countryCode,
				clientType,
				enrichmentStatus,
				null
		);
	}

	private BlockedClientEvent(
			Long id,
			String serverId,
			String valveName,
			long slotKey,
			Instant slotTime,
			String clientKey,
			IpNetworkInfo net,
			int requestCount,
			int retainedCount,
			boolean locked,
			boolean completed,
			Instant lastUpdatedAt,
			Long asn,
			String asOrg,
			String countryCode,
			ClientType clientType,
			EnrichmentStatus enrichmentStatus,
			Long entityId
	) {
		this(
				id,
				serverId,
				valveName,
				slotKey,
				slotTime,
				clientKey,
				net.version(),
				net.prefix(),
				net.v4Start(),
				net.v4End(),
				net.v6Start(),
				net.v6End(),
				net.subnetGroup(),
				requestCount,
				retainedCount,
				locked,
				completed,
				lastUpdatedAt,
				asn,
				asOrg,
				countryCode,
				clientType,
				enrichmentStatus,
				entityId
		);
	}

	public int totalEffectiveCount() {
		return requestCount + retainedCount;
	}

	public BlockedClientEvent withEntityId(Long newEntityId) {
		return new BlockedClientEvent(
				id,
				serverId,
				valveName,
				slotKey,
				slotTime,
				clientKey,
				ipVersion,
				cidrPrefix,
				ipV4Start,
				ipV4End,
				ipV6Start,
				ipV6End,
				subnetGroup,
				requestCount,
				retainedCount,
				locked,
				completed,
				lastUpdatedAt,
				asn,
				asOrg,
				countryCode,
				clientType,
				enrichmentStatus,
				newEntityId
		);
	}

	public BlockedClientEvent withEnrichment(IpEnrichmentResult result) {
		return new BlockedClientEvent(
				id,
				serverId,
				valveName,
				slotKey,
				slotTime,
				clientKey,
				ipVersion,
				cidrPrefix,
				ipV4Start,
				ipV4End,
				ipV6Start,
				ipV6End,
				subnetGroup,
				requestCount,
				retainedCount,
				locked,
				completed,
				lastUpdatedAt,
				result.asn(),
				result.asOrg(),
				result.countryCode(),
				result.clientType(),
				EnrichmentStatus.ENRICHED,
				entityId
		);
	}
}
