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
	private int activeEventRetentionHours = 24;
	private int pollLogRetentionDays = 1;
	private int entityRetentionDays = 60;
	private int slowPollThresholdMs = 1000;
	private boolean demoMode = false;
	private int demoInstanceCount = 1;
	private boolean parallelFleetPolling = true;
	private int rollupWindowMinutes = 60;
	private int rollupRetentionDays = 30;
	private int lowActivityRollupRetentionDays = 7;
	private long lowActivityRollupMaxRequests = 5L;
	private boolean autoVacuumEnabled = true;
	private long vacuumThresholdBytes = 50L * 1024L * 1024L; // 50 MB freespace threshold for auto-vacuum
	private boolean rollupEnabled = true;
	private boolean reportEnabled = true;
	private String reportCron = "0 0 1 * * *"; // Daily at 01:00 AM (2 hours prior to 03:00 AM retention cleanup)
	private long surgeMinRequests = 1000L; // De minimis volume threshold: min. 24h requests required to qualify as High Surge
	private double surgeMultiplierAlert = 5.0; // Multiplier threshold above 30d baseline to qualify as High Surge
	private String mitigationToken; // Optional fleet-wide default write token for dynamic CIDR mitigation
	private int defaultMitigationTtlMinutes = 60;
	private AutoMitigationConfig autoMitigation = new AutoMitigationConfig();
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

	public int getActiveEventRetentionHours() {
		return activeEventRetentionHours;
	}

	public void setActiveEventRetentionHours(int activeEventRetentionHours) {
		this.activeEventRetentionHours = Math.max(1, activeEventRetentionHours);
	}

	public boolean isAutoVacuumEnabled() {
		return autoVacuumEnabled;
	}

	public void setAutoVacuumEnabled(boolean autoVacuumEnabled) {
		this.autoVacuumEnabled = autoVacuumEnabled;
	}

	public long getVacuumThresholdBytes() {
		return vacuumThresholdBytes;
	}

	public void setVacuumThresholdBytes(long vacuumThresholdBytes) {
		this.vacuumThresholdBytes = Math.max(1024L * 1024L, vacuumThresholdBytes);
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

	public int getLowActivityRollupRetentionDays() {
		return lowActivityRollupRetentionDays;
	}

	public void setLowActivityRollupRetentionDays(int lowActivityRollupRetentionDays) {
		this.lowActivityRollupRetentionDays = Math.max(1, lowActivityRollupRetentionDays);
	}

	public long getLowActivityRollupMaxRequests() {
		return lowActivityRollupMaxRequests;
	}

	public void setLowActivityRollupMaxRequests(long lowActivityRollupMaxRequests) {
		this.lowActivityRollupMaxRequests = Math.max(0L, lowActivityRollupMaxRequests);
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

	public long getSurgeMinRequests() {
		return surgeMinRequests;
	}

	public void setSurgeMinRequests(long surgeMinRequests) {
		this.surgeMinRequests = Math.max(1L, surgeMinRequests);
	}

	public double getSurgeMultiplierAlert() {
		return surgeMultiplierAlert;
	}

	public void setSurgeMultiplierAlert(double surgeMultiplierAlert) {
		this.surgeMultiplierAlert = Math.max(1.0, surgeMultiplierAlert);
	}

	public String getMitigationToken() {
		return mitigationToken;
	}

	public void setMitigationToken(String mitigationToken) {
		this.mitigationToken = mitigationToken;
	}

	public int getDefaultMitigationTtlMinutes() {
		return defaultMitigationTtlMinutes;
	}

	public void setDefaultMitigationTtlMinutes(int defaultMitigationTtlMinutes) {
		this.defaultMitigationTtlMinutes = Math.max(1, defaultMitigationTtlMinutes);
	}

	public AutoMitigationConfig getAutoMitigation() {
		return autoMitigation;
	}

	public void setAutoMitigation(AutoMitigationConfig autoMitigation) {
		this.autoMitigation = autoMitigation != null ? autoMitigation : new AutoMitigationConfig();
	}

	/**
	 * Configuration properties for autonomous mitigation engine.
	 */
	public static class AutoMitigationConfig {
		private boolean enabled = false;
		private boolean dryRun = true;
		private int carpetMinSubnets = 8;
		private long carpetMinRequests = 5000L;
		private double maxReturningRatioPct = 5.0;
		private int maxActiveRules = 100;
		private int defaultTtlMinutes = 60;
		private boolean autoExtendPersistent = true;
		private int maxExtensionHours = 12;

		public boolean isEnabled() { return enabled; }
		public void setEnabled(boolean enabled) { this.enabled = enabled; }
		public boolean isDryRun() { return dryRun; }
		public void setDryRun(boolean dryRun) { this.dryRun = dryRun; }
		public int getCarpetMinSubnets() { return carpetMinSubnets; }
		public void setCarpetMinSubnets(int carpetMinSubnets) { this.carpetMinSubnets = Math.max(2, carpetMinSubnets); }
		public long getCarpetMinRequests() { return carpetMinRequests; }
		public void setCarpetMinRequests(long carpetMinRequests) { this.carpetMinRequests = Math.max(100L, carpetMinRequests); }
		public double getMaxReturningRatioPct() { return maxReturningRatioPct; }
		public void setMaxReturningRatioPct(double maxReturningRatioPct) { this.maxReturningRatioPct = Math.max(0.0, Math.min(100.0, maxReturningRatioPct)); }
		public int getMaxActiveRules() { return maxActiveRules; }
		public void setMaxActiveRules(int maxActiveRules) { this.maxActiveRules = Math.max(1, maxActiveRules); }
		public int getDefaultTtlMinutes() { return defaultTtlMinutes; }
		public void setDefaultTtlMinutes(int defaultTtlMinutes) { this.defaultTtlMinutes = Math.max(5, defaultTtlMinutes); }
		public boolean isAutoExtendPersistent() { return autoExtendPersistent; }
		public void setAutoExtendPersistent(boolean autoExtendPersistent) { this.autoExtendPersistent = autoExtendPersistent; }
		public int getMaxExtensionHours() { return maxExtensionHours; }
		public void setMaxExtensionHours(int maxExtensionHours) { this.maxExtensionHours = Math.max(1, maxExtensionHours); }
	}
}
