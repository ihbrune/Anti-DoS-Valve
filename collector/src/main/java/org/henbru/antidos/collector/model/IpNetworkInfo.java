package org.henbru.antidos.collector.model;

/**
 * Normalized network attributes extracted from a client IP address or subnet partition string.
 */
public record IpNetworkInfo(
		int version,
		int prefix,
		Long v4Start,
		Long v4End,
		String v6Start,
		String v6End,
		String subnetGroup
) {
	public int ipVersion() { return version; }
	public int cidrPrefix() { return prefix; }
	public Long ipV4Start() { return v4Start; }
	public Long ipV4End() { return v4End; }
	public String ipV6Start() { return v6Start; }
	public String ipV6End() { return v6End; }
}
