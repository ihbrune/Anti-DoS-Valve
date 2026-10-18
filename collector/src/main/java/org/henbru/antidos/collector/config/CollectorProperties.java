package org.henbru.antidos.collector.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Global configuration properties for the Anti-DoS Collector service.
 */
@ConfigurationProperties(prefix = "collector")
public class CollectorProperties {

	private String configFile = "collector-config.yaml";
	private int pollIntervalSeconds = 15;
	private int retentionDays = 30;
	private int pollLogRetentionDays = 1;
	private int slowPollThresholdMs = 1000;
	private boolean demoMode = false;
	private List<EndpointConfig> endpoints = new ArrayList<>();

	public String getConfigFile() {
		return configFile;
	}

	public void setConfigFile(String configFile) {
		this.configFile = configFile;
	}

	public int getPollIntervalSeconds() {
		return pollIntervalSeconds;
	}

	public void setPollIntervalSeconds(int pollIntervalSeconds) {
		this.pollIntervalSeconds = pollIntervalSeconds;
	}

	public int getRetentionDays() {
		return retentionDays;
	}

	public void setRetentionDays(int retentionDays) {
		this.retentionDays = retentionDays;
	}

	public int getPollLogRetentionDays() {
		return pollLogRetentionDays;
	}

	public void setPollLogRetentionDays(int pollLogRetentionDays) {
		this.pollLogRetentionDays = pollLogRetentionDays;
	}

	public int getSlowPollThresholdMs() {
		return slowPollThresholdMs;
	}

	public void setSlowPollThresholdMs(int slowPollThresholdMs) {
		this.slowPollThresholdMs = slowPollThresholdMs;
	}

	public boolean isDemoMode() {
		return demoMode;
	}

	public void setDemoMode(boolean demoMode) {
		this.demoMode = demoMode;
	}

	public List<EndpointConfig> getEndpoints() {
		return endpoints;
	}

	public void setEndpoints(List<EndpointConfig> endpoints) {
		this.endpoints = endpoints != null ? endpoints : new ArrayList<>();
	}
}
