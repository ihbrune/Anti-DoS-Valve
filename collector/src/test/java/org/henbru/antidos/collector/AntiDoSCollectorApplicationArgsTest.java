package org.henbru.antidos.collector;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

class AntiDoSCollectorApplicationArgsTest {

	@Test
	void headlessShortcutSetsModeAndPreservesOtherArgs() {
		String[] resolved = AntiDoSCollectorApplication.resolveArgs(
				new String[]{"headless", "--server.port=9090"},
				Map.of());
		assertArrayEquals(
				new String[]{"--server.port=9090", "--collector.mode=HEADLESS"},
				resolved);

		String[] resolvedDash = AntiDoSCollectorApplication.resolveArgs(
				new String[]{"--headless"},
				Map.of());
		assertArrayEquals(
				new String[]{"--collector.mode=HEADLESS"},
				resolvedDash);
	}

	@Test
	void viewerShortcutWithPositionalOrEqualsDbPathConfiguresSqliteUrl() {
		String[] positional = AntiDoSCollectorApplication.resolveArgs(
				new String[]{"viewer", "/var/lib/antidos/snapshot.db", "--server.port=8090"},
				Map.of());
		assertArrayEquals(
				new String[]{
						"--server.port=8090",
						"--collector.mode=VIEWER",
						"--spring.datasource.url=jdbc:sqlite:/var/lib/antidos/snapshot.db?busy_timeout=60000"
				},
				positional);

		String[] dashEquals = AntiDoSCollectorApplication.resolveArgs(
				new String[]{"--viewer=/tmp/collector-copy.db"},
				Map.of());
		assertArrayEquals(
				new String[]{
						"--collector.mode=VIEWER",
						"--spring.datasource.url=jdbc:sqlite:/tmp/collector-copy.db?busy_timeout=60000"
				},
				dashEquals);

		String[] equalsBare = AntiDoSCollectorApplication.resolveArgs(
				new String[]{"viewer=jdbc:sqlite:/tmp/raw.db?mode=ro"},
				Map.of());
		assertArrayEquals(
				new String[]{
						"--collector.mode=VIEWER",
						"--spring.datasource.url=jdbc:sqlite:/tmp/raw.db?mode=ro"
				},
				equalsBare);
	}

	@Test
	void viewerShortcutWithoutPathDoesNotOverwriteDatasourceUrl() {
		String[] viewerOnly = AntiDoSCollectorApplication.resolveArgs(
				new String[]{"--viewer"},
				Map.of());
		assertArrayEquals(new String[]{"--collector.mode=VIEWER"}, viewerOnly);

		String[] explicitDatasource = AntiDoSCollectorApplication.resolveArgs(
				new String[]{"viewer", "/ignored.db", "--spring.datasource.url=jdbc:sqlite:/explicit.db"},
				Map.of());
		assertArrayEquals(
				new String[]{
						"--spring.datasource.url=jdbc:sqlite:/explicit.db",
						"--collector.mode=VIEWER"
				},
				explicitDatasource);
	}

	@Test
	void resolvesModeFromEnvironmentUnlessOverriddenByCli() {
		String[] fromEnv = AntiDoSCollectorApplication.resolveArgs(
				new String[0],
				Map.of("COLLECTOR_MODE", "headless"));
		assertArrayEquals(new String[]{"--collector.mode=HEADLESS"}, fromEnv);

		String[] cliOverridesEnv = AntiDoSCollectorApplication.resolveArgs(
				new String[]{"--collector.mode=VIEWER"},
				Map.of("COLLECTOR_MODE", "HEADLESS"));
		assertArrayEquals(new String[]{"--collector.mode=VIEWER"}, cliOverridesEnv);
	}

	@Test
	void rejectsConflictingModesAndDemoCombinations() {
		assertThrows(IllegalArgumentException.class, () -> AntiDoSCollectorApplication.resolveArgs(
				new String[]{"headless", "viewer"},
				Map.of()));

		assertThrows(IllegalArgumentException.class, () -> AntiDoSCollectorApplication.resolveArgs(
				new String[]{"viewer", "--collector.mode=HEADLESS"},
				Map.of()));

		assertThrows(IllegalArgumentException.class, () -> AntiDoSCollectorApplication.resolveArgs(
				new String[]{"demo", "headless"},
				Map.of()));

		assertThrows(IllegalArgumentException.class, () -> AntiDoSCollectorApplication.resolveArgs(
				new String[]{"demo", "--collector.mode=VIEWER"},
				Map.of()));

		assertThrows(IllegalArgumentException.class, () -> AntiDoSCollectorApplication.resolveArgs(
				new String[]{"viewer"},
				Map.of("COLLECTOR_DEMO_MODE", "true")));

		assertThrows(IllegalArgumentException.class, () -> AntiDoSCollectorApplication.resolveArgs(
				new String[]{"demo"},
				Map.of("COLLECTOR_MODE", "HEADLESS")));
	}
}
