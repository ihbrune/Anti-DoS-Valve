package org.henbru.antidos.collector.demo;

import jakarta.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

/**
 * Service orchestrating demo mode provisioning.
 * Automatically configures simulated endpoints pointing to internal mock valves
 * and updates URLs with the dynamic server port upon startup.
 */
@Service
@ConditionalOnProperty(name = "collector.demo-mode", havingValue = "true")
public class DemoModeService {

	private static final Logger log = LoggerFactory.getLogger(DemoModeService.class);

	private final CollectorProperties properties;

	public DemoModeService(CollectorProperties properties) {
		this.properties = properties;
	}

	@PostConstruct
	public void initDefaultDemoEndpoints() {
		registerDemoEndpoints(8090, false);
	}

	@EventListener(WebServerInitializedEvent.class)
	public void onWebServerInitialized(WebServerInitializedEvent event) {
		int port = event.getWebServer().getPort();
		if (port > 0) {
			registerDemoEndpoints(port, true);
		}
	}

	public synchronized void registerDemoEndpoints(int port, boolean printBanner) {
		// Clean out the default placeholder template if present
		properties.getEndpoints().removeIf(e -> "Monitored-Server".equals(e.getName()) && e.getUrl().contains(":8013"));

		boolean alreadyConfigured = properties.getEndpoints().stream()
				.anyMatch(e -> e.getName().startsWith("Demo-"));

		int instanceCount = Math.max(1, Math.min(26, properties.getDemoInstanceCount()));

		if (alreadyConfigured) {
			// Update port for all demo endpoints in case the port changed (e.g. random port in tests)
			for (EndpointConfig ep : properties.getEndpoints()) {
				if (ep.getName().startsWith("Demo-")) {
					ep.setUrl(ep.getUrl().replaceAll(":\\d+/", ":" + port + "/"));
				}
			}
		} else {
			List<EndpointConfig> demoEndpoints = createDemoEndpoints(port, instanceCount);
			properties.getEndpoints().addAll(demoEndpoints);
		}

		if (printBanner) {
			List<EndpointConfig> currentDemo = properties.getEndpoints().stream()
					.filter(e -> e.getName().startsWith("Demo-"))
					.toList();
			log.info("================================================================================");
			if (instanceCount > 1) {
				log.info(" Anti-DoS Collector: DEMO MODE ACTIVE (Fleet Scale: {} instances/type, {} total servers)",
						instanceCount, currentDemo.size());
			} else {
				log.info(" Anti-DoS Collector: DEMO MODE ACTIVE");
			}
			log.info(" Database:             Isolated SQLite (antidos-collector-demo.db)");
			log.info("                       [Production database remains completely untouched]");
			log.info(" Registered {} simulated AntiDoSValve endpoints on port {}:", currentDemo.size(), port);
			for (EndpointConfig ep : currentDemo) {
				log.info("   - {:<22} {}", ep.getName() + ":", ep.getUrl());
			}
			log.info(" Access the live web dashboard at: http://localhost:{}/", port);
			log.info("================================================================================");
		}
	}

	public static List<EndpointConfig> createDemoEndpoints(int port, int instanceCount) {
		int count = Math.max(1, Math.min(26, instanceCount));
		List<EndpointConfig> demoEndpoints = new ArrayList<>();
		if (count == 1) {
			demoEndpoints.add(new EndpointConfig(
					"Demo-Edge-EU",
					"http://localhost:" + port + "/mock-valve/edge-eu/antidos-status",
					"demo-token",
					false,
					true,
					List.of("Primary-Rate-Limiter", "Subnet-Guard", "IPv6-Rate-Limiter")
			));
			demoEndpoints.add(new EndpointConfig(
					"Demo-API-Gateway",
					"http://localhost:" + port + "/mock-valve/api-gateway/antidos-status",
					"demo-token",
					false,
					true,
					List.of("API-DoS-Shield")
			));
			demoEndpoints.add(new EndpointConfig(
					"Demo-Staging-Node",
					"http://localhost:" + port + "/mock-valve/staging-node/antidos-status",
					"demo-token",
					false,
					true,
					List.of("Staging-Limiter")
			));
		} else {
			for (int i = 0; i < count; i++) {
				char letter = (char) ('A' + i);
				char letterLower = Character.toLowerCase(letter);
				demoEndpoints.add(new EndpointConfig(
						"Demo-Edge-EU " + letter,
						"http://localhost:" + port + "/mock-valve/edge-eu-" + letterLower + "/antidos-status",
						"demo-token",
						false,
						true,
						List.of("Primary-Rate-Limiter", "Subnet-Guard", "IPv6-Rate-Limiter")
				));
				demoEndpoints.add(new EndpointConfig(
						"Demo-API-Gateway " + letter,
						"http://localhost:" + port + "/mock-valve/api-gateway-" + letterLower + "/antidos-status",
						"demo-token",
						false,
						true,
						List.of("API-DoS-Shield")
				));
				demoEndpoints.add(new EndpointConfig(
						"Demo-Staging-Node " + letter,
						"http://localhost:" + port + "/mock-valve/staging-node-" + letterLower + "/antidos-status",
						"demo-token",
						false,
						true,
						List.of("Staging-Limiter")
				));
			}
		}
		return demoEndpoints;
	}
}
