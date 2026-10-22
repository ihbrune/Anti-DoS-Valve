package org.henbru.antidos.collector.config;

/**
 * Telemetry and active tracking thresholds for AntiDoSValve instances.
 * Can be defined as a fleet-wide default, globally per valve name, or overridden per endpoint.
 */
public class ValveRuleConfig {

	private Boolean collectActive;
	private Integer activeMinCount;
	private String activeLimit;

	public ValveRuleConfig() {
	}

	public ValveRuleConfig(Boolean collectActive, Integer activeMinCount, String activeLimit) {
		this.collectActive = collectActive;
		this.activeMinCount = activeMinCount;
		this.activeLimit = activeLimit;
	}

	public Boolean getCollectActive() {
		return collectActive;
	}

	public void setCollectActive(Boolean collectActive) {
		this.collectActive = collectActive;
	}

	public Integer getActiveMinCount() {
		return activeMinCount;
	}

	public void setActiveMinCount(Integer activeMinCount) {
		this.activeMinCount = activeMinCount;
	}

	public String getActiveLimit() {
		return activeLimit;
	}

	public void setActiveLimit(String activeLimit) {
		this.activeLimit = activeLimit;
	}

	@Override
	public String toString() {
		return "ValveRuleConfig{" +
				"collectActive=" + collectActive +
				", activeMinCount=" + activeMinCount +
				", activeLimit='" + activeLimit + '\'' +
				'}';
	}
}
