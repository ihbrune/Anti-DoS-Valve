package org.henbru.antidos.collector;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.henbru.antidos.collector.cli.CollectorCliRunner;
import org.henbru.antidos.collector.config.CollectorMode;
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

		SpringApplication.run(AntiDoSCollectorApplication.class, resolveArgs(args));
	}

	static String[] resolveArgs(String[] args) {
		return resolveArgs(args, System.getenv());
	}

	static String[] resolveArgs(String[] args, Map<String, String> env) {
		List<String> effectiveList = new ArrayList<>(args != null ? Arrays.asList(args) : List.of());
		Integer demoCount = null;
		boolean isDemo = false;
		CollectorMode requestedMode = null;
		String viewerDbPath = null;

		for (int i = 0; i < effectiveList.size(); i++) {
			String a = effectiveList.get(i);
			String lower = a.toLowerCase(Locale.ROOT);
			if ("demo".equals(lower) || "--demo".equals(lower)) {
				isDemo = true;
				effectiveList.remove(i);
				if (i < effectiveList.size() && effectiveList.get(i).matches("\\d+")) {
					try {
						demoCount = Integer.valueOf(effectiveList.get(i));
						effectiveList.remove(i);
					} catch (NumberFormatException ignored) {}
				}
				i--;
			} else if (lower.startsWith("demo=") || lower.startsWith("--demo=")) {
				isDemo = true;
				String val = a.substring(a.indexOf('=') + 1).trim();
				if (val.matches("\\d+")) {
					try {
						demoCount = Integer.valueOf(val);
					} catch (NumberFormatException ignored) {}
				}
				effectiveList.remove(i);
				i--;
			} else if (a.contains("demo-mode=true")) {
				isDemo = true;
			} else if ("headless".equals(lower) || "--headless".equals(lower)) {
				requestedMode = selectMode(requestedMode, CollectorMode.HEADLESS);
				effectiveList.remove(i);
				i--;
			} else if ("viewer".equals(lower) || "--viewer".equals(lower)) {
				requestedMode = selectMode(requestedMode, CollectorMode.VIEWER);
				effectiveList.remove(i);
				if (i < effectiveList.size() && isPositionalDbPath(effectiveList.get(i))) {
					viewerDbPath = effectiveList.remove(i).trim();
				}
				i--;
			} else if (lower.startsWith("viewer=") || lower.startsWith("--viewer=")) {
				requestedMode = selectMode(requestedMode, CollectorMode.VIEWER);
				String val = a.substring(a.indexOf('=') + 1).trim();
				if (!val.isEmpty()) {
					viewerDbPath = val;
				}
				effectiveList.remove(i);
				i--;
			} else if ("operator".equals(lower) || "--operator".equals(lower)) {
				requestedMode = selectMode(requestedMode, CollectorMode.OPERATOR);
				effectiveList.remove(i);
				if (i < effectiveList.size() && isPositionalDbPath(effectiveList.get(i))) {
					viewerDbPath = effectiveList.remove(i).trim();
				}
				i--;
			} else if (lower.startsWith("operator=") || lower.startsWith("--operator=")) {
				requestedMode = selectMode(requestedMode, CollectorMode.OPERATOR);
				String val = a.substring(a.indexOf('=') + 1).trim();
				if (!val.isEmpty()) {
					viewerDbPath = val;
				}
				effectiveList.remove(i);
				i--;
			} else if (lower.startsWith("--collector.mode=") || lower.startsWith("collector.mode=")) {
				String val = a.substring(a.indexOf('=') + 1).trim();
				requestedMode = selectMode(requestedMode, CollectorMode.fromString(val));
			}
		}

		if (!isDemo && env != null && "true".equalsIgnoreCase(env.get("COLLECTOR_DEMO_MODE"))) {
			isDemo = true;
		}
		if (requestedMode == null && env != null) {
			String envMode = env.get("COLLECTOR_MODE");
			if (envMode != null && !envMode.isBlank()) {
				requestedMode = CollectorMode.fromString(envMode);
			}
		}

		if (isDemo && requestedMode != null && requestedMode != CollectorMode.FULL) {
			throw new IllegalArgumentException(
					"Demo mode cannot be combined with collector.mode=" + requestedMode + ".");
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

		if (requestedMode != null && effectiveList.stream()
				.noneMatch(a -> a.toLowerCase(Locale.ROOT).startsWith("--collector.mode=")
						|| a.toLowerCase(Locale.ROOT).startsWith("collector.mode="))) {
			effectiveList.add("--collector.mode=" + requestedMode.name());
		}

		if (viewerDbPath != null && effectiveList.stream()
				.noneMatch(a -> a.startsWith("--spring.datasource.url=") || a.startsWith("spring.datasource.url="))) {
			effectiveList.add("--spring.datasource.url=" + toSqliteJdbcUrl(viewerDbPath));
		}

		return effectiveList.toArray(String[]::new);
	}

	private static CollectorMode selectMode(CollectorMode current, CollectorMode next) {
		if (current != null && current != next) {
			throw new IllegalArgumentException(
					"Conflicting collector operational modes specified: " + current + " and " + next);
		}
		return next;
	}

	private static boolean isPositionalDbPath(String arg) {
		if (arg == null || arg.isBlank() || arg.startsWith("-")) {
			return false;
		}
		String lower = arg.toLowerCase(Locale.ROOT);
		return !"demo".equals(lower) && !"headless".equals(lower)
				&& !"operator".equals(lower) && !"viewer".equals(lower)
				&& !lower.contains("=");
	}

	private static String toSqliteJdbcUrl(String pathOrUrl) {
		if (pathOrUrl.startsWith("jdbc:")) {
			return pathOrUrl;
		}
		String separator = pathOrUrl.contains("?") ? "&" : "?";
		return pathOrUrl.contains("busy_timeout")
				? "jdbc:sqlite:" + pathOrUrl
				: "jdbc:sqlite:" + pathOrUrl + separator + "busy_timeout=60000";
	}
}
