package org.henbru.antidos.collector;

import org.henbru.antidos.collector.cli.CollectorCliRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main entry point for the Anti-DoS Collector and Analytics service.
 */
@SpringBootApplication
@EnableScheduling
@ConfigurationPropertiesScan
public class AntiDoSCollectorApplication {

	public static void main(String[] args) {
		if (CollectorCliRunner.isCliCommand(args)) {
			int exitCode = CollectorCliRunner.runCli(args);
			System.exit(exitCode);
			return;
		}

		java.util.List<String> effectiveList = new java.util.ArrayList<>(args != null ? java.util.Arrays.asList(args) : java.util.List.of());
		boolean isDemo = effectiveList.stream().anyMatch(a ->
				"demo".equalsIgnoreCase(a)
				|| "--demo".equalsIgnoreCase(a)
				|| a.contains("demo-mode=true")
		) || "true".equalsIgnoreCase(System.getenv("COLLECTOR_DEMO_MODE"));

		if (isDemo) {
			effectiveList.removeIf(a -> "demo".equalsIgnoreCase(a) || "--demo".equalsIgnoreCase(a));
			if (effectiveList.stream().noneMatch(a -> a.startsWith("--spring.profiles.active="))) {
				effectiveList.add("--spring.profiles.active=demo");
			}
			effectiveList.add("--collector.demo-mode=true");
		}

		SpringApplication.run(AntiDoSCollectorApplication.class, effectiveList.toArray(String[]::new));
	}
}
