package org.henbru.antidos.collector.security;

import org.henbru.antidos.AntiDoSValve;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers an embedded {@link AntiDoSValve} instance directly in the Collector's own Tomcat
 * request pipeline for lock-free rate limiting and DoS protection.
 */
@Configuration
@ConditionalOnWebApplication
@ConditionalOnClass(TomcatServletWebServerFactory.class)
public class CollectorSelfProtectionConfig {

	private static final Logger log = LoggerFactory.getLogger(CollectorSelfProtectionConfig.class);

	@Bean
	public WebServerFactoryCustomizer<TomcatServletWebServerFactory> collectorAntiDoSValveCustomizer(
			CollectorProperties properties) {
		return factory -> {
			CollectorProperties.SelfProtectionConfig cfg = properties.getSelfProtection();
			if (!cfg.isEnabled()) {
				log.info("Collector self-protection AntiDoSValve is disabled via configuration.");
				return;
			}
			AntiDoSValve valve = buildSelfProtectionValve(cfg);
			factory.addContextValves(valve);
			log.info("Registered embedded AntiDoSValve '{}' on Collector Tomcat pipeline ({} req/{}s slot, IPv4 /{}/IPv6 /{})",
					cfg.getMonitorName(),
					cfg.getAllowedRequestsPerSlot(),
					cfg.getSlotLength(),
					cfg.getIpv4SubnetMask(),
					cfg.getIpv6SubnetMask());
		};
	}

	static AntiDoSValve buildSelfProtectionValve(CollectorProperties.SelfProtectionConfig cfg) {
		AntiDoSValve valve = new AntiDoSValve();
		valve.setMonitorName(cfg.getMonitorName());
		valve.setDescription("Embedded Anti-DoS self-protection valve for Anti-DoS Collector");
		if (cfg.getNonRelevantPaths() != null && !cfg.getNonRelevantPaths().isBlank()) {
			valve.setNonRelevantPaths(cfg.getNonRelevantPaths());
		}
		valve.setSlotLength(cfg.getSlotLength());
		valve.setNumberOfSlots(cfg.getNumberOfSlots());
		valve.setAllowedRequestsPerSlot(cfg.getAllowedRequestsPerSlot());
		valve.setShareOfRetainedFormerRequests(cfg.getShareOfRetainedFormerRequests());
		valve.setMaxIPCacheSize(cfg.getMaxIpCacheSize());
		valve.setIpv4SubnetMask(cfg.getIpv4SubnetMask());
		valve.setIpv6SubnetMask(cfg.getIpv6SubnetMask());
		valve.setAlwaysAllowPrivateIPs(cfg.isAlwaysAllowPrivateIPs());
		valve.setCollectorIntegration("false");
		if (cfg.getStatusUri() != null && !cfg.getStatusUri().isBlank()) {
			valve.setStatusUri(cfg.getStatusUri());
		}
		return valve;
	}
}
