package org.henbru.antidos.collector.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
	private int entityRetentionDays = 60;
	private int slowPollThresholdMs = 1000;
	private boolean demoMode = false;
	private int demoInstanceCount = 1;
	private boolean parallelFleetPolling = true;
	private int rollupWindowMinutes = 60;
	private int rollupRetentionDays = 180;
	private boolean rollupEnabled = true;
	private boolean reportEnabled = true;
	private String reportCron = "0 0 1 * * *"; // Daily at 01:00 AM (2 hours prior to 03:00 AM retention cleanup)
	private List<EndpointConfig> endpoints = new ArrayList<>();
	private EnrichmentConfig enrichment = new EnrichmentConfig();

	/**
	 * Fleet-wide fallback rule for telemetry and active tracking.
	 * Default: collectActive=false (activeLimit=0), activeMinCount=10, activeLimit="1000".
	 */
	private ValveRuleConfig defaultValveRules = new ValveRuleConfig(false, 10, "1000");

	/**
	 * Global telemetry rules keyed by valve name (case-insensitive lookup).
	 * Applies across all servers in the fleet unless overridden at endpoint level.
	 */
	private Map<String, ValveRuleConfig> valveRules = new LinkedHashMap<>();

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

	public int getEntityRetentionDays() {
		return entityRetentionDays;
	}

	public void setEntityRetentionDays(int entityRetentionDays) {
		this.entityRetentionDays = entityRetentionDays;
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

	public int getDemoInstanceCount() {
		return demoInstanceCount;
	}

	public void setDemoInstanceCount(int demoInstanceCount) {
		this.demoInstanceCount = demoInstanceCount;
	}

	public boolean isParallelFleetPolling() {
		return parallelFleetPolling;
	}

	public void setParallelFleetPolling(boolean parallelFleetPolling) {
		this.parallelFleetPolling = parallelFleetPolling;
	}

	public List<EndpointConfig> getEndpoints() {
		return endpoints;
	}

	public void setEndpoints(List<EndpointConfig> endpoints) {
		this.endpoints = endpoints != null ? endpoints : new ArrayList<>();
	}

	public EnrichmentConfig getEnrichment() {
		return enrichment;
	}

	public void setEnrichment(EnrichmentConfig enrichment) {
		this.enrichment = enrichment != null ? enrichment : new EnrichmentConfig();
	}

	public ValveRuleConfig getDefaultValveRules() {
		return defaultValveRules;
	}

	public void setDefaultValveRules(ValveRuleConfig defaultValveRules) {
		this.defaultValveRules = defaultValveRules != null ? defaultValveRules : new ValveRuleConfig(false, 10, "1000");
	}

	public Map<String, ValveRuleConfig> getValveRules() {
		return valveRules;
	}

	public void setValveRules(Map<String, ValveRuleConfig> valveRules) {
		this.valveRules = valveRules != null ? valveRules : new LinkedHashMap<>();
	}

	public int getRollupWindowMinutes() {
		return rollupWindowMinutes;
	}

	public void setRollupWindowMinutes(int rollupWindowMinutes) {
		this.rollupWindowMinutes = Math.max(1, rollupWindowMinutes);
	}

	public int getRollupRetentionDays() {
		return rollupRetentionDays;
	}

	public void setRollupRetentionDays(int rollupRetentionDays) {
		this.rollupRetentionDays = Math.max(1, rollupRetentionDays);
	}

	public boolean isRollupEnabled() {
		return rollupEnabled;
	}

	public void setRollupEnabled(boolean rollupEnabled) {
		this.rollupEnabled = rollupEnabled;
	}

	public boolean isReportEnabled() {
		return reportEnabled;
	}

	public void setReportEnabled(boolean reportEnabled) {
		this.reportEnabled = reportEnabled;
	}

	public String getReportCron() {
		return reportCron;
	}

	public void setReportCron(String reportCron) {
		this.reportCron = reportCron;
	}
}
