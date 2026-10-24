package org.henbru.antidos.collector.config;

import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Service resolving effective telemetry and active tracking configuration for a valve
 * using a 3-tier cascade:
 * <ol>
 *   <li>Endpoint-specific override (e.g. {@code endpoints[].valves[name="..."]})</li>
 *   <li>Global rule for valve name across fleet (e.g. {@code collector.valve-rules[name]})</li>
 *   <li>Global default rule (e.g. {@code collector.default-valve-rules})</li>
 * </ol>
 */
@Component
public class ValveRuleResolver {

	private final CollectorProperties properties;

	public ValveRuleResolver(CollectorProperties properties) {
		this.properties = properties;
	}

	public EffectiveValveRule resolve(EndpointConfig endpoint, String valveName) {
		String cleanName = valveName != null ? valveName.trim() : "DEFAULT";
		boolean isIncluded = (endpoint == null) || endpoint.isValveIncluded(cleanName);

		Optional<EndpointValveConfig> epConfig = (endpoint != null) ? endpoint.findValveConfig(cleanName) : Optional.empty();
		ValveRuleConfig valveRule = findGlobalValveRule(cleanName);
		ValveRuleConfig globalDefault = properties.getDefaultValveRules();

		// 1. Resolve collectActive & RuleSource
		boolean collectActive;
		EffectiveValveRule.RuleSource source;

		if (epConfig.isPresent() && epConfig.get().getCollectActive() != null) {
			collectActive = epConfig.get().getCollectActive();
			source = EffectiveValveRule.RuleSource.ENDPOINT_OVERRIDE;
		} else if (epConfig.isPresent() && epConfig.get().getActiveMinCount() != null) {
			collectActive = epConfig.get().getActiveMinCount() > 0;
			source = EffectiveValveRule.RuleSource.ENDPOINT_OVERRIDE;
		} else if (valveRule != null && valveRule.getCollectActive() != null) {
			collectActive = valveRule.getCollectActive();
			source = EffectiveValveRule.RuleSource.VALVE_RULE;
		} else if (valveRule != null && valveRule.getActiveMinCount() != null) {
			collectActive = valveRule.getActiveMinCount() > 0;
			source = EffectiveValveRule.RuleSource.VALVE_RULE;
		} else if (globalDefault != null && globalDefault.getCollectActive() != null) {
			collectActive = globalDefault.getCollectActive();
			source = EffectiveValveRule.RuleSource.GLOBAL_DEFAULT;
		} else if (globalDefault != null && globalDefault.getActiveMinCount() != null) {
			collectActive = globalDefault.getActiveMinCount() > 0;
			source = EffectiveValveRule.RuleSource.GLOBAL_DEFAULT;
		} else {
			collectActive = false;
			source = EffectiveValveRule.RuleSource.SYSTEM_DEFAULT;
		}

		// 2. Resolve activeMinCount
		int activeMinCount;
		if (epConfig.isPresent() && epConfig.get().getActiveMinCount() != null) {
			activeMinCount = epConfig.get().getActiveMinCount();
		} else if (valveRule != null && valveRule.getActiveMinCount() != null) {
			activeMinCount = valveRule.getActiveMinCount();
		} else if (globalDefault != null && globalDefault.getActiveMinCount() != null) {
			activeMinCount = globalDefault.getActiveMinCount();
		} else {
			activeMinCount = 10;
		}

		// Safeguard: min-count <= 0 disables active collection
		if (activeMinCount <= 0) {
			collectActive = false;
		}

		// 3. Resolve activeLimit
		String activeLimit;
		if (epConfig.isPresent() && epConfig.get().getActiveLimit() != null && !epConfig.get().getActiveLimit().isBlank()) {
			activeLimit = epConfig.get().getActiveLimit().trim();
		} else if (valveRule != null && valveRule.getActiveLimit() != null && !valveRule.getActiveLimit().isBlank()) {
			activeLimit = valveRule.getActiveLimit().trim();
		} else if (globalDefault != null && globalDefault.getActiveLimit() != null && !globalDefault.getActiveLimit().isBlank()) {
			activeLimit = globalDefault.getActiveLimit().trim();
		} else {
			activeLimit = "1000";
		}

		return new EffectiveValveRule(cleanName, collectActive, activeMinCount, activeLimit, source, isIncluded);
	}

	private ValveRuleConfig findGlobalValveRule(String valveName) {
		if (properties.getValveRules() == null || properties.getValveRules().isEmpty() || valveName == null) {
			return null;
		}
		// 1. Exact match (case-insensitive)
		for (Map.Entry<String, ValveRuleConfig> entry : properties.getValveRules().entrySet()) {
			if (entry.getKey() != null && entry.getKey().trim().equalsIgnoreCase(valveName.trim())) {
				return entry.getValue();
			}
		}
		// 2. Relaxed match: Spring Boot's YAML relaxed binder strips spaces and non-alphanumeric chars
		// from unbracketed map keys (e.g. 'SUBNET MONITORING' -> 'SUBNETMONITORING').
		// We normalize both sides by removing whitespace, hyphens, and underscores.
		String normalizedTarget = normalizeValveName(valveName);
		if (!normalizedTarget.isEmpty()) {
			for (Map.Entry<String, ValveRuleConfig> entry : properties.getValveRules().entrySet()) {
				if (entry.getKey() != null && normalizeValveName(entry.getKey()).equals(normalizedTarget)) {
					return entry.getValue();
				}
			}
		}
		return null;
	}

	/**
	 * Normalizes a valve name for relaxed matching by removing whitespace, hyphens, and underscores,
	 * and converting to lower case.
	 */
	public static String normalizeValveName(String name) {
		if (name == null) {
			return "";
		}
		return name.replaceAll("[\\s-_]+", "").toLowerCase(java.util.Locale.ROOT);
	}
}
