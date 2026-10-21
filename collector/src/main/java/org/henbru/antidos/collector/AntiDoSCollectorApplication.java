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
		Integer demoCount = null;
		boolean isDemo = false;

		for (int i = 0; i < effectiveList.size(); i++) {
			String a = effectiveList.get(i);
			if ("demo".equalsIgnoreCase(a) || "--demo".equalsIgnoreCase(a)) {
				isDemo = true;
				effectiveList.remove(i);
				if (i < effectiveList.size() && effectiveList.get(i).matches("\\d+")) {
					try {
						demoCount = Integer.parseInt(effectiveList.get(i));
						effectiveList.remove(i);
					} catch (NumberFormatException ignored) {}
				}
				i--;
			} else if (a.toLowerCase().startsWith("demo=") || a.toLowerCase().startsWith("--demo=")) {
				isDemo = true;
				String val = a.substring(a.indexOf('=') + 1).trim();
				if (val.matches("\\d+")) {
					try {
						demoCount = Integer.parseInt(val);
					} catch (NumberFormatException ignored) {}
				}
				effectiveList.remove(i);
				i--;
			} else if (a.contains("demo-mode=true")) {
				isDemo = true;
			}
		}

		if (!isDemo && "true".equalsIgnoreCase(System.getenv("COLLECTOR_DEMO_MODE"))) {
			isDemo = true;
		}

		if (isDemo) {
			if (effectiveList.stream().noneMatch(a -> a.startsWith("--spring.profiles.active="))) {
				effectiveList.add("--spring.profiles.active=demo");
			}
			effectiveList.add("--collector.demo-mode=true");
			if (demoCount != null) {
				effectiveList.add("--collector.demo-instance-count=" + demoCount);
			}
		}

		SpringApplication.run(AntiDoSCollectorApplication.class, effectiveList.toArray(String[]::new));
	}
}
