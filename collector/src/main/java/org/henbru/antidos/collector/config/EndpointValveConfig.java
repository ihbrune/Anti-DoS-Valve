package org.henbru.antidos.collector.config;

/**
 * Definition of a valve configured on a specific monitored endpoint,
 * optionally specifying endpoint-level telemetry overrides.
 */
public class EndpointValveConfig extends ValveRuleConfig {

	private String name;

	public EndpointValveConfig() {
		super();
	}

	public EndpointValveConfig(String name) {
		super();
		this.name = name;
	}

	public EndpointValveConfig(String name, Boolean collectActive, Integer activeMinCount, String activeLimit) {
		super(collectActive, activeMinCount, activeLimit);
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return "EndpointValveConfig{" +
				"name='" + name + '\'' +
				", collectActive=" + getCollectActive() +
				", activeMinCount=" + getActiveMinCount() +
				", activeLimit='" + getActiveLimit() + '\'' +
				'}';
	}
}
