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

		if (alreadyConfigured) {
			// Update port for all demo endpoints in case the port changed (e.g. random port in tests)
			for (EndpointConfig ep : properties.getEndpoints()) {
				if (ep.getName().startsWith("Demo-")) {
					ep.setUrl(ep.getUrl().replaceAll(":\\d+/", ":" + port + "/"));
				}
			}
		} else {
			List<EndpointConfig> demoEndpoints = new ArrayList<>();
			demoEndpoints.add(new EndpointConfig(
					"Demo-Edge-EU",
					"http://localhost:" + port + "/mock-valve/edge-eu/antidos-status",
					"demo-token",
					false,
					true,
					List.of("Primary-Rate-Limiter", "Subnet-Guard")
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

			properties.getEndpoints().addAll(demoEndpoints);
		}

		if (printBanner) {
			log.info("================================================================================");
			log.info(" Anti-DoS Collector: DEMO MODE ACTIVE");
			log.info(" Database:             Isolated SQLite (antidos-collector-demo.db)");
			log.info("                       [Production database remains completely untouched]");
			log.info(" Registered 3 simulated AntiDoSValve endpoints on port {}:", port);
			log.info("   - Demo-Edge-EU:        http://localhost:{}/mock-valve/edge-eu/antidos-status", port);
			log.info("   - Demo-API-Gateway:    http://localhost:{}/mock-valve/api-gateway/antidos-status", port);
			log.info("   - Demo-Staging-Node:   http://localhost:{}/mock-valve/staging-node/antidos-status", port);
			log.info(" Access the live web dashboard at: http://localhost:{}/", port);
			log.info("================================================================================");
		}
	}
}
