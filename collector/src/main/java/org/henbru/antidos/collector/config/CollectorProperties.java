package org.henbru.antidos.collector.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.henbru.antidos.collector.security.CollectorAuthContext;
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
	private int maxCatchUpSlotsPerPoll = 2;
	private int maxCatchUpLagSlots = 6;
	private long endpointPollTimeoutMs = 25_000L;
	private int hostConcurrencyTimeoutSeconds = 15;
	private CollectorMode mode = CollectorMode.FULL;
	private boolean viewerMigrateOnStartup = false;
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
	private UserAgentHeuristicConfig userAgentHeuristics = new UserAgentHeuristicConfig();
	private NotificationConfig notification = new NotificationConfig();
	private BrowserReferenceConfig browserReference = new BrowserReferenceConfig();
	private SecurityConfig security = new SecurityConfig();
	private SelfProtectionConfig selfProtection = new SelfProtectionConfig();
	private List<EndpointConfig> endpoints = new ArrayList<>();
	private EnrichmentConfig enrichment = new EnrichmentConfig();
	private List<InternalNetworkConfig> internalNetworks = new ArrayList<>();

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

	public int getMaxCatchUpSlotsPerPoll() {
		return maxCatchUpSlotsPerPoll;
	}

	public void setMaxCatchUpSlotsPerPoll(int maxCatchUpSlotsPerPoll) {
		this.maxCatchUpSlotsPerPoll = Math.max(1, maxCatchUpSlotsPerPoll);
	}

	public int getMaxCatchUpLagSlots() {
		return maxCatchUpLagSlots;
	}

	public void setMaxCatchUpLagSlots(int maxCatchUpLagSlots) {
		this.maxCatchUpLagSlots = Math.max(1, maxCatchUpLagSlots);
	}

	public long getEndpointPollTimeoutMs() {
		return endpointPollTimeoutMs;
	}

	public void setEndpointPollTimeoutMs(long endpointPollTimeoutMs) {
		this.endpointPollTimeoutMs = Math.max(1000L, endpointPollTimeoutMs);
	}

	public int getHostConcurrencyTimeoutSeconds() {
		return hostConcurrencyTimeoutSeconds;
	}

	public void setHostConcurrencyTimeoutSeconds(int hostConcurrencyTimeoutSeconds) {
		this.hostConcurrencyTimeoutSeconds = hostConcurrencyTimeoutSeconds;
	}

	public CollectorMode getMode() {
		return mode != null ? mode : CollectorMode.FULL;
	}

	public void setMode(CollectorMode mode) {
		this.mode = mode != null ? mode : CollectorMode.FULL;
	}

	/**
	 * Resolves the effective runtime mode for the current request by intersecting the
	 * instance-wide {@link #getMode()} with any authenticated request token or session role.
	 */
	public CollectorMode getEffectiveMode() {
		CollectorMode base = getMode();
		if (base == CollectorMode.HEADLESS || base == CollectorMode.VIEWER) {
			return base;
		}
		CollectorAuthContext.AuthPrincipal principal = CollectorAuthContext.get();
		if (principal == null || principal.role() == null) {
			return base;
		}
		if (principal.role().isViewer()) {
			return CollectorMode.VIEWER;
		}
		if (principal.role().isOperatorEquivalent()) {
			return CollectorMode.OPERATOR;
		}
		return base;
	}

	public boolean isViewerMode() {
		return getEffectiveMode().isViewer();
	}

	public boolean isHeadlessMode() {
		return getMode().isHeadless();
	}

	public boolean isOperatorMode() {
		return getEffectiveMode().isOperator();
	}

	public boolean canModifyOperationalData() {
		return getEffectiveMode().canModifyOperationalData();
	}

	public boolean canPerformSystemAdmin() {
		return getEffectiveMode().canPerformSystemAdmin();
	}

	public SecurityConfig getSecurity() {
		if (security == null) {
			security = new SecurityConfig();
		}
		return security;
	}

	public void setSecurity(SecurityConfig security) {
		this.security = security != null ? security : new SecurityConfig();
	}

	public SelfProtectionConfig getSelfProtection() {
		if (selfProtection == null) {
			selfProtection = new SelfProtectionConfig();
		}
		return selfProtection;
	}

	public void setSelfProtection(SelfProtectionConfig selfProtection) {
		this.selfProtection = selfProtection != null ? selfProtection : new SelfProtectionConfig();
	}

	public boolean isViewerMigrateOnStartup() {
		return viewerMigrateOnStartup;
	}

	public void setViewerMigrateOnStartup(boolean viewerMigrateOnStartup) {
		this.viewerMigrateOnStartup = viewerMigrateOnStartup;
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

	public List<InternalNetworkConfig> getInternalNetworks() {
		return internalNetworks;
	}

	public void setInternalNetworks(List<InternalNetworkConfig> internalNetworks) {
		this.internalNetworks = internalNetworks != null ? internalNetworks : new ArrayList<>();
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

	public UserAgentHeuristicConfig getUserAgentHeuristics() {
		if (userAgentHeuristics == null) {
			userAgentHeuristics = new UserAgentHeuristicConfig();
		}
		return userAgentHeuristics;
	}

	public void setUserAgentHeuristics(UserAgentHeuristicConfig userAgentHeuristics) {
		this.userAgentHeuristics = userAgentHeuristics != null ? userAgentHeuristics : new UserAgentHeuristicConfig();
	}

	public NotificationConfig getNotification() {
		return notification;
	}

	public void setNotification(NotificationConfig notification) {
		this.notification = notification != null ? notification : new NotificationConfig();
	}

	public BrowserReferenceConfig getBrowserReference() {
		return browserReference;
	}

	public void setBrowserReference(BrowserReferenceConfig browserReference) {
		this.browserReference = browserReference != null ? browserReference : new BrowserReferenceConfig();
	}

	/**
	 * Configuration properties for authoritative browser release version intelligence.
	 */
	public static class BrowserReferenceConfig {
		private boolean enabled = true;
		private String chromeApiUrl = "https://versionhistory.googleapis.com/v1/chrome/platforms/all/channels/all/versions";
		private String firefoxApiUrl = "https://product-details.mozilla.org/1.0/firefox_versions.json";
		private List<String> safariVersions = new ArrayList<>(List.of("26.2 STP", "26.1", "26.0", "18.2", "17.6"));
		private int syncIntervalHours = 24;

		public boolean isEnabled() { return enabled; }
		public void setEnabled(boolean enabled) { this.enabled = enabled; }
		public String getChromeApiUrl() { return chromeApiUrl; }
		public void setChromeApiUrl(String chromeApiUrl) { this.chromeApiUrl = chromeApiUrl; }
		public String getFirefoxApiUrl() { return firefoxApiUrl; }
		public void setFirefoxApiUrl(String firefoxApiUrl) { this.firefoxApiUrl = firefoxApiUrl; }
		public List<String> getSafariVersions() { return safariVersions; }
		public void setSafariVersions(List<String> safariVersions) {
			if (safariVersions != null && !safariVersions.isEmpty()) {
				this.safariVersions = new ArrayList<>(safariVersions);
			}
		}
		public int getSyncIntervalHours() { return syncIntervalHours; }
		public void setSyncIntervalHours(int syncIntervalHours) { this.syncIntervalHours = Math.max(1, syncIntervalHours); }
	}

	/**
	 * Configuration properties for alert and webhook notifications (Slack, Teams, Discord, Generic).
	 */
	public static class NotificationConfig {
		private boolean enabled = false;
		private String webhookUrl;
		private boolean notifyOnDryRun = true;
		private boolean notifyOnAutoBlock = true;
		private boolean notifyOnEmergencyFlush = true;
		private boolean notifyOnCircuitBreaker = true;

		public boolean isEnabled() { return enabled; }
		public void setEnabled(boolean enabled) { this.enabled = enabled; }
		public String getWebhookUrl() { return webhookUrl; }
		public void setWebhookUrl(String webhookUrl) { this.webhookUrl = webhookUrl; }
		public boolean isNotifyOnDryRun() { return notifyOnDryRun; }
		public void setNotifyOnDryRun(boolean notifyOnDryRun) { this.notifyOnDryRun = notifyOnDryRun; }
		public boolean isNotifyOnAutoBlock() { return notifyOnAutoBlock; }
		public void setNotifyOnAutoBlock(boolean notifyOnAutoBlock) { this.notifyOnAutoBlock = notifyOnAutoBlock; }
		public boolean isNotifyOnEmergencyFlush() { return notifyOnEmergencyFlush; }
		public void setNotifyOnEmergencyFlush(boolean notifyOnEmergencyFlush) { this.notifyOnEmergencyFlush = notifyOnEmergencyFlush; }
		public boolean isNotifyOnCircuitBreaker() { return notifyOnCircuitBreaker; }
		public void setNotifyOnCircuitBreaker(boolean notifyOnCircuitBreaker) { this.notifyOnCircuitBreaker = notifyOnCircuitBreaker; }
	}

	/**
	 * Configuration properties for autonomous mitigation engine.
	 */
	public static class AutoMitigationConfig {
		private boolean enabled = false;
		private boolean dryRun = true;
		private int carpetMinSubnets = 8;
		private long carpetMinRequests = 5000L;
		private int carpetWindowHours = 1;
		private String protectedAsns = "8075,16509,14618,15169,13335";
		private double maxReturningRatioPct = 5.0;
		private long maxAuthenticatedRequests = 0L;
		/**
		 * Minimum requests a single subnet must have produced within the lookback window to be eligible
		 * for an autonomous block. Filters out rotating residential proxy subnets that only send a handful
		 * of requests before moving on (blocking them after the fact has no effect). 0 disables the filter.
		 */
		private long carpetMinRequestsPerSubnet = 20L;
		private int maxActiveRules = 100;
		private int defaultTtlMinutes = 60;
		private boolean autoExtendPersistent = true;
		private int maxExtensionHours = 12;

		public boolean isEnabled() { return enabled; }
		public void setEnabled(boolean enabled) { this.enabled = enabled; }
		public boolean isDryRun() { return dryRun; }
		public void setDryRun(boolean dryRun) { this.dryRun = dryRun; }
		public int getCarpetMinSubnets() { return carpetMinSubnets; }
		public void setCarpetMinSubnets(int carpetMinSubnets) { this.carpetMinSubnets = Math.max(1, carpetMinSubnets); }
		public long getCarpetMinRequests() { return carpetMinRequests; }
		public void setCarpetMinRequests(long carpetMinRequests) { this.carpetMinRequests = Math.max(1L, carpetMinRequests); }
		public int getCarpetWindowHours() { return carpetWindowHours; }
		public void setCarpetWindowHours(int carpetWindowHours) { this.carpetWindowHours = Math.max(1, Math.min(720, carpetWindowHours)); }
		public String getProtectedAsns() { return protectedAsns; }
		public void setProtectedAsns(String protectedAsns) { this.protectedAsns = protectedAsns != null ? protectedAsns.trim() : ""; }
		public Set<Long> getProtectedAsnSet() { return parseAsnSet(this.protectedAsns); }
		public double getMaxReturningRatioPct() { return maxReturningRatioPct; }
		public void setMaxReturningRatioPct(double maxReturningRatioPct) { this.maxReturningRatioPct = Math.max(0.0, Math.min(100.0, maxReturningRatioPct)); }
		public long getMaxAuthenticatedRequests() { return maxAuthenticatedRequests; }
		public void setMaxAuthenticatedRequests(long maxAuthenticatedRequests) { this.maxAuthenticatedRequests = Math.max(0L, maxAuthenticatedRequests); }
		public long getCarpetMinRequestsPerSubnet() { return carpetMinRequestsPerSubnet; }
		public void setCarpetMinRequestsPerSubnet(long carpetMinRequestsPerSubnet) { this.carpetMinRequestsPerSubnet = Math.max(0L, carpetMinRequestsPerSubnet); }
		public int getMaxActiveRules() { return maxActiveRules; }
		public void setMaxActiveRules(int maxActiveRules) { this.maxActiveRules = Math.max(1, maxActiveRules); }
		public int getDefaultTtlMinutes() { return defaultTtlMinutes; }
		public void setDefaultTtlMinutes(int defaultTtlMinutes) { this.defaultTtlMinutes = Math.max(1, defaultTtlMinutes); }
		public boolean isAutoExtendPersistent() { return autoExtendPersistent; }
		public void setAutoExtendPersistent(boolean autoExtendPersistent) { this.autoExtendPersistent = autoExtendPersistent; }
		public int getMaxExtensionHours() { return maxExtensionHours; }
		public void setMaxExtensionHours(int maxExtensionHours) { this.maxExtensionHours = Math.max(1, maxExtensionHours); }

		public static Set<Long> parseAsnSet(String csv) {
			if (csv == null || csv.isBlank()) {
				return Set.of();
			}
			Set<Long> set = new HashSet<>();
			for (String part : csv.split(",")) {
				String clean = part.trim().toUpperCase(Locale.ROOT);
				if (clean.startsWith("AS")) {
					clean = clean.substring(2).trim();
				}
				if (!clean.isEmpty()) {
					try {
						long val = Long.parseLong(clean);
						if (val > 0) {
							set.add(val);
						}
					} catch (NumberFormatException ignored) {}
				}
			}
			return Collections.unmodifiableSet(set);
		}
	}

	/**
	 * Configuration properties for the 3-pillar User-Agent heuristic and Stage-0 immunity thresholds.
	 */
	public static class UserAgentHeuristicConfig {
		private double internalImmunityMinRatioPct = 5.0;
		private long internalImmunityMinRequests = 100L;
		private double searchEngineImmunityMinRatioPct = 50.0;
		private double authImmunityMinSampleRatioPct = 1.0;
		private double authImmunityMinSlotRatioPct = 2.0;

		private long spreadMinRequests = 10000L;
		private int spreadMinSubnets = 200;
		private int spreadMinAsns = 30;
		private double spreadMaxAvgSlotRequests = 10.0;
		private int spreadMinVersionLagMajors = 2;

		private long correlatedMinRequests = 2000L;
		private double correlatedMinIncidentRatioPct = 30.0;
		private double correlatedMinMitigatedAsnRatioPct = 40.0;
		private double correlatedMinUaMismatchRatioPct = 20.0;

		private long datacenterMinRequests = 5000L;
		private double datacenterMinRatioPct = 80.0;

		public double getInternalImmunityMinRatioPct() { return internalImmunityMinRatioPct; }
		public void setInternalImmunityMinRatioPct(double v) { this.internalImmunityMinRatioPct = Math.max(0.0, Math.min(100.0, v)); }
		public long getInternalImmunityMinRequests() { return internalImmunityMinRequests; }
		public void setInternalImmunityMinRequests(long v) { this.internalImmunityMinRequests = Math.max(1L, v); }
		public double getSearchEngineImmunityMinRatioPct() { return searchEngineImmunityMinRatioPct; }
		public void setSearchEngineImmunityMinRatioPct(double v) { this.searchEngineImmunityMinRatioPct = Math.max(0.0, Math.min(100.0, v)); }
		public double getAuthImmunityMinSampleRatioPct() { return authImmunityMinSampleRatioPct; }
		public void setAuthImmunityMinSampleRatioPct(double v) { this.authImmunityMinSampleRatioPct = Math.max(0.0, Math.min(100.0, v)); }
		public double getAuthImmunityMinSlotRatioPct() { return authImmunityMinSlotRatioPct; }
		public void setAuthImmunityMinSlotRatioPct(double v) { this.authImmunityMinSlotRatioPct = Math.max(0.0, Math.min(100.0, v)); }
		public long getSpreadMinRequests() { return spreadMinRequests; }
		public void setSpreadMinRequests(long v) { this.spreadMinRequests = Math.max(1L, v); }
		public int getSpreadMinSubnets() { return spreadMinSubnets; }
		public void setSpreadMinSubnets(int v) { this.spreadMinSubnets = Math.max(1, v); }
		public int getSpreadMinAsns() { return spreadMinAsns; }
		public void setSpreadMinAsns(int v) { this.spreadMinAsns = Math.max(1, v); }
		public double getSpreadMaxAvgSlotRequests() { return spreadMaxAvgSlotRequests; }
		public void setSpreadMaxAvgSlotRequests(double v) { this.spreadMaxAvgSlotRequests = Math.max(0.1, v); }
		public int getSpreadMinVersionLagMajors() { return spreadMinVersionLagMajors; }
		public void setSpreadMinVersionLagMajors(int v) { this.spreadMinVersionLagMajors = Math.max(1, v); }
		public long getCorrelatedMinRequests() { return correlatedMinRequests; }
		public void setCorrelatedMinRequests(long v) { this.correlatedMinRequests = Math.max(1L, v); }
		public double getCorrelatedMinIncidentRatioPct() { return correlatedMinIncidentRatioPct; }
		public void setCorrelatedMinIncidentRatioPct(double v) { this.correlatedMinIncidentRatioPct = Math.max(0.0, Math.min(100.0, v)); }
		public double getCorrelatedMinMitigatedAsnRatioPct() { return correlatedMinMitigatedAsnRatioPct; }
		public void setCorrelatedMinMitigatedAsnRatioPct(double v) { this.correlatedMinMitigatedAsnRatioPct = Math.max(0.0, Math.min(100.0, v)); }
		public double getCorrelatedMinUaMismatchRatioPct() { return correlatedMinUaMismatchRatioPct; }
		public void setCorrelatedMinUaMismatchRatioPct(double v) { this.correlatedMinUaMismatchRatioPct = Math.max(0.0, Math.min(100.0, v)); }
		public long getDatacenterMinRequests() { return datacenterMinRequests; }
		public void setDatacenterMinRequests(long v) { this.datacenterMinRequests = Math.max(1L, v); }
		public double getDatacenterMinRatioPct() { return datacenterMinRatioPct; }
		public void setDatacenterMinRatioPct(double v) { this.datacenterMinRatioPct = Math.max(0.0, Math.min(100.0, v)); }
	}

	/**
	 * Multi-token authentication, brute-force protection, read access policy, and AI guardrails.
	 */
	public static class SecurityConfig {
		private boolean requireAuthForRead = true;
		private boolean apiEnabled = true;
		private int sessionTtlSeconds = 28800;
		private int maxAuthFailures = 5;
		private int authLockoutSeconds = 300;
		private List<TokenEntry> tokens = new ArrayList<>();
		private AiGuardrailsConfig aiGuardrails = new AiGuardrailsConfig();

		public boolean isRequireAuthForRead() { return requireAuthForRead; }
		public void setRequireAuthForRead(boolean requireAuthForRead) { this.requireAuthForRead = requireAuthForRead; }
		public boolean isApiEnabled() { return apiEnabled; }
		public void setApiEnabled(boolean apiEnabled) { this.apiEnabled = apiEnabled; }
		public int getSessionTtlSeconds() { return sessionTtlSeconds; }
		public void setSessionTtlSeconds(int sessionTtlSeconds) { this.sessionTtlSeconds = Math.max(60, sessionTtlSeconds); }
		public int getMaxAuthFailures() { return maxAuthFailures; }
		public void setMaxAuthFailures(int maxAuthFailures) { this.maxAuthFailures = Math.max(1, maxAuthFailures); }
		public int getAuthLockoutSeconds() { return authLockoutSeconds; }
		public void setAuthLockoutSeconds(int authLockoutSeconds) { this.authLockoutSeconds = Math.max(10, authLockoutSeconds); }
		public List<TokenEntry> getTokens() { return tokens; }
		public void setTokens(List<TokenEntry> tokens) { this.tokens = tokens != null ? tokens : new ArrayList<>(); }
		public AiGuardrailsConfig getAiGuardrails() {
			if (aiGuardrails == null) {
				aiGuardrails = new AiGuardrailsConfig();
			}
			return aiGuardrails;
		}
		public void setAiGuardrails(AiGuardrailsConfig aiGuardrails) {
			this.aiGuardrails = aiGuardrails != null ? aiGuardrails : new AiGuardrailsConfig();
		}
	}

	/**
	 * Named authentication token entry with scoped authorization role.
	 */
	public static class TokenEntry {
		private String name;
		private CollectorTokenRole role = CollectorTokenRole.VIEWER;
		private String token;
		private boolean enabled = true;

		public TokenEntry() {}

		public TokenEntry(String name, CollectorTokenRole role, String token, boolean enabled) {
			this.name = name;
			this.role = role != null ? role : CollectorTokenRole.VIEWER;
			this.token = token;
			this.enabled = enabled;
		}

		public String getName() { return name; }
		public void setName(String name) { this.name = name != null ? name.trim() : null; }
		public CollectorTokenRole getRole() { return role != null ? role : CollectorTokenRole.VIEWER; }
		public void setRole(CollectorTokenRole role) { this.role = role != null ? role : CollectorTokenRole.VIEWER; }
		public String getToken() { return token; }
		public void setToken(String token) { this.token = token != null ? token.trim() : null; }
		public boolean isEnabled() { return enabled; }
		public void setEnabled(boolean enabled) { this.enabled = enabled; }
	}

	/**
	 * Safety guardrails applied automatically to tokens with {@link CollectorTokenRole#AI_AGENT}.
	 */
	public static class AiGuardrailsConfig {
		private int maxTtlMinutes = 120;
		private int maxBlocksPerHour = 20;
		private int minReasonLength = 15;
		private boolean allowAsnBatchBlock = false;
		private int minIpv4Prefix = 24;
		private int minIpv6Prefix = 48;

		public int getMaxTtlMinutes() { return maxTtlMinutes; }
		public void setMaxTtlMinutes(int maxTtlMinutes) { this.maxTtlMinutes = Math.max(1, maxTtlMinutes); }
		public int getMaxBlocksPerHour() { return maxBlocksPerHour; }
		public void setMaxBlocksPerHour(int maxBlocksPerHour) { this.maxBlocksPerHour = Math.max(1, maxBlocksPerHour); }
		public int getMinReasonLength() { return minReasonLength; }
		public void setMinReasonLength(int minReasonLength) { this.minReasonLength = Math.max(0, minReasonLength); }
		public boolean isAllowAsnBatchBlock() { return allowAsnBatchBlock; }
		public void setAllowAsnBatchBlock(boolean allowAsnBatchBlock) { this.allowAsnBatchBlock = allowAsnBatchBlock; }
		public int getMinIpv4Prefix() { return minIpv4Prefix; }
		public void setMinIpv4Prefix(int minIpv4Prefix) { this.minIpv4Prefix = Math.max(16, Math.min(32, minIpv4Prefix)); }
		public int getMinIpv6Prefix() { return minIpv6Prefix; }
		public void setMinIpv6Prefix(int minIpv6Prefix) { this.minIpv6Prefix = Math.max(32, Math.min(128, minIpv6Prefix)); }
	}

	/**
	 * Configuration for the embedded {@code AntiDoSValve} protecting the Collector's own Tomcat HTTP server.
	 */
	public static class SelfProtectionConfig {
		private boolean enabled = true;
		private String monitorName = "Collector-Self-Protection";
		private int slotLength = 60;
		private int numberOfSlots = 5;
		private int allowedRequestsPerSlot = 600;
		private float shareOfRetainedFormerRequests = 0.25f;
		private int maxIpCacheSize = 10000;
		private int ipv4SubnetMask = 32;
		private int ipv6SubnetMask = 64;
		private String nonRelevantPaths = ".*\\.(css|js|png|jpg|jpeg|gif|ico|woff|woff2|svg)$";
		private boolean alwaysAllowPrivateIPs = false;
		private String statusUri = null;

		public boolean isEnabled() { return enabled; }
		public void setEnabled(boolean enabled) { this.enabled = enabled; }
		public String getMonitorName() { return monitorName; }
		public void setMonitorName(String monitorName) {
			if (monitorName != null && !monitorName.isBlank()) {
				this.monitorName = monitorName.trim();
			}
		}
		public int getSlotLength() { return slotLength; }
		public void setSlotLength(int slotLength) { this.slotLength = Math.max(1, slotLength); }
		public int getNumberOfSlots() { return numberOfSlots; }
		public void setNumberOfSlots(int numberOfSlots) { this.numberOfSlots = Math.max(1, numberOfSlots); }
		public int getAllowedRequestsPerSlot() { return allowedRequestsPerSlot; }
		public void setAllowedRequestsPerSlot(int allowedRequestsPerSlot) { this.allowedRequestsPerSlot = Math.max(1, allowedRequestsPerSlot); }
		public float getShareOfRetainedFormerRequests() { return shareOfRetainedFormerRequests; }
		public void setShareOfRetainedFormerRequests(float shareOfRetainedFormerRequests) {
			this.shareOfRetainedFormerRequests = Math.max(0.0f, Math.min(1.0f, shareOfRetainedFormerRequests));
		}
		public int getMaxIpCacheSize() { return maxIpCacheSize; }
		public void setMaxIpCacheSize(int maxIpCacheSize) { this.maxIpCacheSize = Math.max(100, maxIpCacheSize); }
		public int getIpv4SubnetMask() { return ipv4SubnetMask; }
		public void setIpv4SubnetMask(int ipv4SubnetMask) { this.ipv4SubnetMask = Math.max(1, Math.min(32, ipv4SubnetMask)); }
		public int getIpv6SubnetMask() { return ipv6SubnetMask; }
		public void setIpv6SubnetMask(int ipv6SubnetMask) { this.ipv6SubnetMask = Math.max(1, Math.min(128, ipv6SubnetMask)); }
		public String getNonRelevantPaths() { return nonRelevantPaths; }
		public void setNonRelevantPaths(String nonRelevantPaths) { this.nonRelevantPaths = nonRelevantPaths; }
		public boolean isAlwaysAllowPrivateIPs() { return alwaysAllowPrivateIPs; }
		public void setAlwaysAllowPrivateIPs(boolean alwaysAllowPrivateIPs) { this.alwaysAllowPrivateIPs = alwaysAllowPrivateIPs; }
		public String getStatusUri() { return statusUri; }
		public void setStatusUri(String statusUri) { this.statusUri = (statusUri != null && !statusUri.isBlank()) ? statusUri.trim() : null; }
	}
}
