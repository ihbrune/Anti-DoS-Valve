package org.henbru.antidos.collector.config;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * Configures Spring Boot runtime properties (embedded web server, keep-alive, Flyway)
 * according to the resolved {@code collector.mode} before context initialization.
 */
public class CollectorModeEnvironmentListener
		implements ApplicationListener<ApplicationEnvironmentPreparedEvent>, Ordered {

	static final String PROPERTY_SOURCE_NAME = "collectorModeOverrides";

	@Override
	public int getOrder() {
		return Ordered.LOWEST_PRECEDENCE;
	}

	@Override
	public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
		ConfigurableEnvironment env = event.getEnvironment();
		String rawMode = env.getProperty("collector.mode", "FULL");
		CollectorMode mode = CollectorMode.fromString(rawMode);

		boolean demoMode = Boolean.parseBoolean(env.getProperty("collector.demo-mode", "false"));
		if (demoMode && mode != CollectorMode.FULL) {
			throw new IllegalStateException(
					"Demo mode cannot be combined with collector.mode=" + mode + ". "
							+ "Remove demo flags/COLLECTOR_DEMO_MODE or run in FULL mode.");
		}

		Map<String, Object> overrides = new LinkedHashMap<>();
		if (mode == CollectorMode.HEADLESS) {
			overrides.put("spring.main.web-application-type", "none");
			overrides.put("spring.main.keep-alive", "true");
		} else if (mode == CollectorMode.VIEWER || mode == CollectorMode.OPERATOR) {
			boolean migrateOnStartup = Boolean.parseBoolean(
					env.getProperty("collector.viewer-migrate-on-startup", "false"));
			if (!migrateOnStartup) {
				overrides.put("spring.flyway.enabled", "false");
			}
			overrides.put("collector.auto-mitigation.enabled", "false");
		}

		if (!overrides.isEmpty()) {
			env.getPropertySources().addFirst(new MapPropertySource(PROPERTY_SOURCE_NAME, overrides));
		}
	}
}
