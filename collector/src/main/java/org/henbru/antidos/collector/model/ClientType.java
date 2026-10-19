package org.henbru.antidos.collector.model;

/**
 * Classification category of a client IP address.
 */
public enum ClientType {
	DATACENTER,
	RESIDENTIAL,
	SEARCH_ENGINE,
	AI_CRAWLER,
	MOBILE,
	PRIVATE_NETWORK,
	TOR_EXIT_NODE,
	UNKNOWN
}
