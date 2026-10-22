package org.henbru.antidos.collector.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;
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

	private final ValveStatusClient statusClient;

	public CollectorCliRunner(ValveStatusClient statusClient) {
		this.statusClient = statusClient;
	}

	public static boolean isCliCommand(String[] args) {
		if (args == null || args.length == 0) {
			return false;
		}
		String command = args[0].toLowerCase();
		return "test-endpoint".equals(command)
				|| "add-endpoint".equals(command)
				|| "--help".equals(command)
				|| "-h".equals(command)
				|| "help".equals(command);
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

		String command = args[0].toLowerCase();
		if ("--help".equals(command) || "-h".equals(command) || "help".equals(command)) {
			printUsage();
			return 0;
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

				  java -jar anti-dos-collector-*.jar test-endpoint --url <url> [--token <token>] [--name <name>]
				      Tests connectivity to an AntiDoSValve endpoint and prints a ready-to-use YAML configuration block.

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
}
