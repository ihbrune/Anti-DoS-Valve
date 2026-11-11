package org.henbru.antidos.collector.config;

/**
 * Configuration for a corporate, campus, or intranet IP network range.
 */
public class InternalNetworkConfig {

	private String cidr;
	private String name;
	private String description;

	public InternalNetworkConfig() {
	}

	public InternalNetworkConfig(String cidr) {
		this.cidr = cidr;
	}

	public InternalNetworkConfig(String cidr, String name, String description) {
		this.cidr = cidr;
		this.name = name;
		this.description = description;
	}

	public String getCidr() {
		return cidr;
	}

	public void setCidr(String cidr) {
		this.cidr = cidr;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}
}

