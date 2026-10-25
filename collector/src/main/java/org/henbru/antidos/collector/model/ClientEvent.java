package org.henbru.antidos.collector.model;

import java.time.Instant;
import org.henbru.antidos.collector.util.IpNetworkUtil;

/**
 * Details of an individual client IP or subnet event recorded during a slot (status: BLOCKED or ACTIVE).
 */
public record ClientEvent(
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
		String status,
		boolean completed,
		Instant lastUpdatedAt,
		Long asn,
		String asOrg,
		String countryCode,
		ClientType clientType,
		EnrichmentStatus enrichmentStatus,
		Long entityId,
		int distinctClients
) {

	public static final String STATUS_BLOCKED = "BLOCKED";
	public static final String STATUS_ACTIVE = "ACTIVE";

	/**
	 * Backward-compatible constructor defaulting distinctClients to 1.
	 */
	public ClientEvent(
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
			String status,
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
				id, serverId, valveName, slotKey, slotTime, clientKey, ipVersion, cidrPrefix,
				ipV4Start, ipV4End, ipV6Start, ipV6End, subnetGroup, requestCount, retainedCount,
				locked, status, completed, lastUpdatedAt, asn, asOrg, countryCode, clientType,
				enrichmentStatus, entityId, 1
		);
	}

	/**
	 * Convenience constructor defaulting status to BLOCKED.
	 */
	public ClientEvent(
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
				locked ? STATUS_BLOCKED : STATUS_ACTIVE,
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

	public ClientEvent(
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
				locked ? STATUS_BLOCKED : STATUS_ACTIVE,
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

	public ClientEvent(
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
			String status,
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
				status,
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

	/**
	 * Convenience constructor with automatic network parsing, explicit status, and distinct client count.
	 */
	public ClientEvent(
			Long id,
			String serverId,
			String valveName,
			long slotKey,
			Instant slotTime,
			String clientKey,
			int requestCount,
			int retainedCount,
			boolean locked,
			String status,
			boolean completed,
			Instant lastUpdatedAt,
			int distinctClients
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
				status != null ? status : (locked ? STATUS_BLOCKED : STATUS_ACTIVE),
				completed,
				lastUpdatedAt,
				null,
				null,
				null,
				ClientType.UNKNOWN,
				EnrichmentStatus.PENDING,
				null,
				Math.max(1, distinctClients)
		);
	}

	/**
	 * Convenience constructor with automatic network parsing and explicit status.
	 */
	public ClientEvent(
			Long id,
			String serverId,
			String valveName,
			long slotKey,
			Instant slotTime,
			String clientKey,
			int requestCount,
			int retainedCount,
			boolean locked,
			String status,
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
				requestCount,
				retainedCount,
				locked,
				status,
				completed,
				lastUpdatedAt,
				1
		);
	}

	/**
	 * Convenience constructor with automatic network parsing defaulting status to BLOCKED.
	 */
	public ClientEvent(
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
				requestCount,
				retainedCount,
				locked,
				locked ? STATUS_BLOCKED : STATUS_ACTIVE,
				completed,
				lastUpdatedAt,
				1
		);
	}

	/**
	 * Internal constructor using pre-parsed IpNetworkInfo with distinct client count.
	 */
	public ClientEvent(
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
			String status,
			boolean completed,
			Instant lastUpdatedAt,
			Long asn,
			String asOrg,
			String countryCode,
			ClientType clientType,
			EnrichmentStatus enrichmentStatus,
			Long entityId,
			int distinctClients
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
				status,
				completed,
				lastUpdatedAt,
				asn,
				asOrg,
				countryCode,
				clientType,
				enrichmentStatus,
				entityId,
				Math.max(1, distinctClients)
		);
	}

	/**
	 * Internal constructor using pre-parsed IpNetworkInfo defaulting distinct clients to 1.
	 */
	public ClientEvent(
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
			String status,
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
				net,
				requestCount,
				retainedCount,
				locked,
				status,
				completed,
				lastUpdatedAt,
				asn,
				asOrg,
				countryCode,
				clientType,
				enrichmentStatus,
				entityId,
				1
		);
	}


	public int totalEffectiveCount() {
		return requestCount + retainedCount;
	}

	public boolean isBlocked() {
		return STATUS_BLOCKED.equalsIgnoreCase(status) || locked;
	}

	public ClientEvent withEntityId(Long newEntityId) {
		return new ClientEvent(
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
				status,
				completed,
				lastUpdatedAt,
				asn,
				asOrg,
				countryCode,
				clientType,
				enrichmentStatus,
				newEntityId,
				distinctClients
		);
	}

	public ClientEvent withEnrichment(IpEnrichmentResult result) {
		return new ClientEvent(
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
				status,
				completed,
				lastUpdatedAt,
				result.asn(),
				result.asOrg(),
				result.countryCode(),
				result.clientType(),
				EnrichmentStatus.ENRICHED,
				entityId,
				distinctClients
		);
	}
}
