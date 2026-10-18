package org.henbru.antidos.collector.model;

import java.time.Instant;

/**
 * An individual IP CIDR prefix belonging to a verified crawler or bot.
 */
public record BotIpRange(
		Long id,
		String feedKey,
		String cidr,
		int ipVersion,
		Long ipV4Start,
		Long ipV4End,
		String ipV6Start,
		String ipV6End,
		Instant createdAt
) {
}
