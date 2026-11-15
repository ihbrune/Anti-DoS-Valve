package org.henbru.antidos.collector.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.henbru.antidos.collector.config.CollectorTokenRole;
import org.henbru.antidos.collector.config.EndpointConfig;
import org.henbru.antidos.collector.model.ValveOverviewDto;
import org.henbru.antidos.collector.poller.ValveStatusClient;

/**
 * Lightweight, standalone command-line runner enabling operators to test endpoints
 * and generate configuration snippets without starting the web server or database.
 *
 * Example:
 *   java -jar anti-dos-collector-*.jar test-endpoint --url "http://localhost:8080/antidos-status" --token "secret" --name "Node-1"
 */
public class CollectorCliRunner {

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private final ValveStatusClient statusClient;

	public CollectorCliRunner(ValveStatusClient statusClient) {
		this.statusClient = statusClient;
	}

	public static boolean isCliCommand(String[] args) {
		if (args == null || args.length == 0) {
			return false;
		}
		String command = args[0].toLowerCase(Locale.ROOT);
		return "test-endpoint".equals(command)
				|| "add-endpoint".equals(command)
				|| "generate-token".equals(command)
				|| "--generate-token".equals(command)
				|| "--help".equals(command)
				|| "-h".equals(command)
				|| "help".equals(command);
	}

	public static String generateSecureHexToken(int numBytes) {
		int boundedBytes = Math.max(16, Math.min(64, numBytes));
		byte[] bytes = new byte[boundedBytes];
		SECURE_RANDOM.nextBytes(bytes);
		StringBuilder sb = new StringBuilder(boundedBytes * 2);
		for (byte b : bytes) {
			sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
			sb.append(Character.forDigit(b & 0xF, 16));
		}
		return sb.toString();
	}

	public static int runCli(String... args) {
		ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
		ValveStatusClient client = new ValveStatusClient(objectMapper);
		CollectorCliRunner runner = new CollectorCliRunner(client);
		return runner.execute(args);
	}

	public int execute(String... args) {
		if (args == null || args.length == 0) {
			printUsage();
			return 1;
		}

		String command = args[0].toLowerCase(Locale.ROOT);
		if ("--help".equals(command) || "-h".equals(command) || "help".equals(command)) {
			printUsage();
			return 0;
		}

		if ("generate-token".equals(command) || "--generate-token".equals(command)) {
			return executeGenerateToken(args);
		}

		if (!"test-endpoint".equals(command) && !"add-endpoint".equals(command)) {
			System.err.println("Unknown command: " + command);
			printUsage();
			return 1;
		}

		Map<String, String> params = parseArgs(args);
		String url = params.get("url");
		String token = params.get("token");
		String name = params.getOrDefault("name", "Monitored-Server");

		if (url == null || url.trim().isEmpty()) {
			System.err.println("Error: Missing required option --url <endpoint-url>");
			printUsage();
			return 1;
		}

		System.out.println("================================================================================");
		System.out.println("Anti-DoS Collector: Testing Valve Endpoint");
		System.out.println("================================================================================");
		System.out.println("Target URL: " + url);
		System.out.println("Endpoint Name: " + name);
		System.out.println("Testing connection...");

		EndpointConfig config = new EndpointConfig(name, url, token, false, true);
		try {
			ValveOverviewDto overview = statusClient.fetchOverview(config);
			int count = overview.valves() != null ? overview.valves().size() : 0;
			System.out.println("\nSUCCESS: Connected to AntiDoSValve successfully!");
			System.out.println("Server Time: " + overview.serverTime());
			System.out.println("Detected Valves (" + count + "):");

			if (overview.valves() != null) {
				for (ValveOverviewDto.ValveSummaryDto v : overview.valves()) {
					System.out.printf("  - [%s] Order: #%d | Mode: %s | Slot Length: %ds | Slots: %d\n",
							v.monitorName(), v.pipelineOrder(), v.monitorMode(), v.slotLength(), v.numberOfSlots());
				}
			}

			System.out.println("\n--------------------------------------------------------------------------------");
			System.out.println("Ready-to-use YAML configuration snippet for 'collector-config.yaml':");
			System.out.println("--------------------------------------------------------------------------------");
			System.out.printf("""
					collector:
					  endpoints:
					    - name: "%s"
					      url: "%s"
					      token: "%s"
					      poll-intermediate-slots: false
					      enabled: true
					""", name, url, token != null ? token : "");

			if (overview.valves() != null && !overview.valves().isEmpty()) {
				System.out.println("      # Valves to poll (remove/comment out any you wish to ignore, or omit 'valves' to poll all):");
				System.out.println("      valves:");
				boolean first = true;
				for (ValveOverviewDto.ValveSummaryDto v : overview.valves()) {
					System.out.printf("        - \"%s\"\n", v.monitorName());
					if (first) {
						System.out.println("        # Optional override for active telemetry and threshold filtering:");
						System.out.printf("        # - name: \"%s\"\n", v.monitorName());
						System.out.println("        #   collect-active: true      # Fetch active client telemetry (default: false / activeLimit=0)");
						System.out.println("        #   active-min-count: 10      # Threshold (e.g. 1 for subnets, 15 for IP rate limiters)");
						System.out.println("        #   active-limit: 1000        # Max active entries per slot (or 'all')");
						first = false;
					}
				}
			}
			System.out.println("--------------------------------------------------------------------------------");
			return 0;

		} catch (java.io.IOException | InterruptedException | RuntimeException e) {
			System.err.println("\nFAILURE: Could not connect to endpoint: " + ValveStatusClient.formatErrorMessage(e));
			return 1;
		}
	}

	private static void printUsage() {
		System.out.println("""
				Anti-DoS Collector CLI Helper & Runner

				Commands:
				  java -jar anti-dos-collector-*.jar demo
				      Starts the collector with simulated AntiDoSValve endpoints (Edge EU, API Gateway US, Staging Node)
				      enabling an immediate out-of-the-box exploration experience.

				  java -jar anti-dos-collector-*.jar headless
				      Starts the collector in HEADLESS mode (background pollers, enrichment, mitigation, and rollups only,
				      with no embedded HTTP server or web dashboard exposed).

				  java -jar anti-dos-collector-*.jar operator [path/to/antidos-collector.db]
				      Starts the collector in OPERATOR mode (analyst & operator web UI: notes, daily report comments/regeneration,
				      and dynamic mitigation rules are enabled without background polling or system/admin maintenance).

				  java -jar anti-dos-collector-*.jar viewer [path/to/antidos-collector.db]
				      Starts the collector in strictly read-only VIEWER mode to inspect an existing SQLite snapshot or
				      configured database without performing any database writes or background polling.

				  java -jar anti-dos-collector-*.jar test-endpoint --url <url> [--token <token>] [--name <name>]
				      Tests connectivity to an AntiDoSValve endpoint and prints a ready-to-use YAML configuration block.

				  java -jar anti-dos-collector-*.jar generate-token [--name <name>] [--role <ADMIN|OPERATOR|AI_AGENT|VIEWER>] [--bytes <16..64>]
				      Generates a cryptographically secure random hex token (default: 32 bytes / 256-bit) and prints a YAML snippet
				      ready for collector.security.tokens.

				Options for test-endpoint:
				  --url     Full HTTP/HTTPS URL to the Valve status endpoint (e.g. http://localhost:8080/antidos-status)
				  --token   Bearer authentication token (optional, if statusToken is configured on the Valve)
				  --name    Friendly display name for the server (default: 'Monitored-Server')
				""");
	}

	private static Map<String, String> parseArgs(String[] args) {
		Map<String, String> map = new HashMap<>();
		for (int i = 1; i < args.length; i++) {
			String arg = args[i];
			if (arg.startsWith("--") && i + 1 < args.length) {
				String key = arg.substring(2);
				String val = args[i + 1];
				map.put(key, val);
				i++;
			}
		}
		return map;
	}

	private int executeGenerateToken(String[] args) {
		Map<String, String> params = parseArgs(args);
		String name = params.getOrDefault("name", "operator-1").trim();
		if (name.isEmpty()) {
			name = "operator-1";
		}

		CollectorTokenRole role;
		try {
			role = CollectorTokenRole.fromString(params.getOrDefault("role", "OPERATOR"));
		} catch (IllegalArgumentException e) {
			System.err.println("Error: " + e.getMessage());
			return 1;
		}

		int numBytes = 32;
		if (params.containsKey("bytes")) {
			try {
				int parsed = Integer.parseInt(params.get("bytes").trim());
				if (parsed < 16 || parsed > 64) {
					System.err.println("Error: --bytes must be between 16 and 64.");
					return 1;
				}
				numBytes = parsed;
			} catch (NumberFormatException e) {
				System.err.println("Error: Invalid --bytes value: " + params.get("bytes"));
				return 1;
			}
		}

		String token = generateSecureHexToken(numBytes);
		System.out.println("================================================================================");
		System.out.println("Anti-DoS Collector: Generated " + (numBytes * 8) + "-bit Authentication Token");
		System.out.println("================================================================================");
		System.out.println("Token: " + token);
		System.out.println();
		System.out.println("Add to collector-config.yaml:");
		System.out.println("collector:");
		System.out.println("  security:");
		System.out.println("    tokens:");
		System.out.println("      - name: \"" + name + "\"");
		System.out.println("        role: " + role.name());
		System.out.println("        token: \"" + token + "\"");
		System.out.println("================================================================================");
		return 0;
	}
}
