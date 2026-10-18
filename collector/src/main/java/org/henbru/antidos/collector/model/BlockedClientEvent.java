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
		Instant lastUpdatedAt
) {

	/**
	 * Backwards-compatible convenience constructor that automatically resolves network metadata from clientKey.
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
				lastUpdatedAt
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
			Instant lastUpdatedAt
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
				lastUpdatedAt
		);
	}

	public int totalEffectiveCount() {
		return requestCount + retainedCount;
	}
}
