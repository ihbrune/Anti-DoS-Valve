package org.henbru.antidos.collector.notification;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.storage.SystemSettingsRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Dispatches alert notifications to generic HTTP Webhooks (compatible with Slack,
 * Microsoft Teams, Discord, Mattermost, and SIEM / automation receivers).
 *
 * Supports runtime configuration overrides via the system_settings table, allowing
 * administrators to configure and test webhooks live from the management dashboard.
 */
@Service
public class AlertNotificationService {

	private static final Logger log = LoggerFactory.getLogger(AlertNotificationService.class);

	private static final DateTimeFormatter TS_FMT =
			DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

	public static final String SETTING_ENABLED = "notification_enabled";
	public static final String SETTING_WEBHOOK_URL = "notification_webhook_url";
	public static final String SETTING_NOTIFY_DRY_RUN = "notification_notify_dry_run";
	public static final String SETTING_NOTIFY_AUTO_BLOCK = "notification_notify_auto_block";
	public static final String SETTING_NOTIFY_EMERGENCY_FLUSH = "notification_notify_emergency_flush";
	public static final String SETTING_NOTIFY_CIRCUIT_BREAKER = "notification_notify_circuit_breaker";

	private final CollectorProperties properties;
	private final SystemSettingsRepository systemSettings;
	private final ObjectMapper objectMapper;
	private final HttpClient httpClient;

	public record EffectiveNotificationSettings(
			boolean enabled,
			String webhookUrl,
			boolean notifyOnDryRun,
			boolean notifyOnAutoBlock,
			boolean notifyOnEmergencyFlush,
			boolean notifyOnCircuitBreaker,
			boolean hasDatabaseOverrides
	) {}

	public record TestResult(
			boolean success,
			int statusCode,
			String message
	) {}

	@Autowired
	public AlertNotificationService(
			CollectorProperties properties,
			SystemSettingsRepository systemSettings,
			ObjectMapper objectMapper) {
		this(properties, systemSettings, objectMapper, HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(5))
				.build());
	}

	public AlertNotificationService(
			CollectorProperties properties,
			SystemSettingsRepository systemSettings,
			ObjectMapper objectMapper,
			HttpClient httpClient) {
		this.properties = properties;
		this.systemSettings = systemSettings;
		this.objectMapper = objectMapper;
		this.httpClient = httpClient;
	}

	public EffectiveNotificationSettings getEffectiveSettings() {
		CollectorProperties.NotificationConfig def = properties.getNotification();

		var dbEnabled = systemSettings.getBoolean(SETTING_ENABLED);
		var dbUrl = systemSettings.getString(SETTING_WEBHOOK_URL);
		var dbDryRun = systemSettings.getBoolean(SETTING_NOTIFY_DRY_RUN);
		var dbAutoBlock = systemSettings.getBoolean(SETTING_NOTIFY_AUTO_BLOCK);
		var dbFlush = systemSettings.getBoolean(SETTING_NOTIFY_EMERGENCY_FLUSH);
		var dbBreaker = systemSettings.getBoolean(SETTING_NOTIFY_CIRCUIT_BREAKER);

		boolean hasDbOverrides = dbEnabled.isPresent() || dbUrl.isPresent() || dbDryRun.isPresent()
				|| dbAutoBlock.isPresent() || dbFlush.isPresent() || dbBreaker.isPresent();

		return new EffectiveNotificationSettings(
				dbEnabled.orElse(def.isEnabled()),
				dbUrl.orElse(def.getWebhookUrl()),
				dbDryRun.orElse(def.isNotifyOnDryRun()),
				dbAutoBlock.orElse(def.isNotifyOnAutoBlock()),
				dbFlush.orElse(def.isNotifyOnEmergencyFlush()),
				dbBreaker.orElse(def.isNotifyOnCircuitBreaker()),
				hasDbOverrides
		);
	}

	public void updateSettings(
			boolean enabled,
			String webhookUrl,
			boolean notifyOnDryRun,
			boolean notifyOnEmergencyFlush,
			String actor) {
		String safeActor = (actor != null && !actor.isBlank()) ? actor.trim() : "ADMIN";
		systemSettings.setSetting(SETTING_ENABLED, String.valueOf(enabled), "Master switch for webhook alert notifications", safeActor);
		systemSettings.setSetting(SETTING_WEBHOOK_URL, webhookUrl != null ? webhookUrl.trim() : "", "Webhook target URL (Slack, Teams, Discord, Generic)", safeActor);
		systemSettings.setSetting(SETTING_NOTIFY_DRY_RUN, String.valueOf(notifyOnDryRun), "Send notifications on simulation dry-run triggers", safeActor);
		systemSettings.setSetting(SETTING_NOTIFY_EMERGENCY_FLUSH, String.valueOf(notifyOnEmergencyFlush), "Send notifications on emergency flush events", safeActor);
		log.info("Notification settings updated by '{}': enabled={}, urlConfigured={}, notifyDryRun={}, notifyFlush={}",
				safeActor, enabled, (webhookUrl != null && !webhookUrl.isBlank()), notifyOnDryRun, notifyOnEmergencyFlush);
	}

	public void resetToDefaults(String actor) {
		systemSettings.deleteSetting(SETTING_ENABLED);
		systemSettings.deleteSetting(SETTING_WEBHOOK_URL);
		systemSettings.deleteSetting(SETTING_NOTIFY_DRY_RUN);
		systemSettings.deleteSetting(SETTING_NOTIFY_AUTO_BLOCK);
		systemSettings.deleteSetting(SETTING_NOTIFY_EMERGENCY_FLUSH);
		systemSettings.deleteSetting(SETTING_NOTIFY_CIRCUIT_BREAKER);
		log.info("Notification settings reset to application.yaml defaults by '{}'", actor);
	}

	public void sendAutoBlockAlert(long asn, String asOrg, List<String> subnets, String batchId, int ttlMinutes, String reason) {
		EffectiveNotificationSettings cfg = getEffectiveSettings();
		if (!cfg.enabled() || !cfg.notifyOnAutoBlock()) {
			return;
		}

		String safeOrg = (asOrg != null && !asOrg.isBlank()) ? asOrg.trim() : "Unknown Organization";
		int count = subnets != null ? subnets.size() : 0;
		String sampleSubnets = (subnets != null && !subnets.isEmpty())
				? String.join(", ", subnets.stream().limit(8).map(s -> "`" + s + "`").toList())
				: "`none`";
		if (count > 8) {
			sampleSubnets += " _(+" + (count - 8) + " more)_";
		}

		String text = """
				🚨 *[Anti-DoS Autonomous Defense]* Auto-blocked *%d* subnet(s) for *ASN %d (%s)*
				• *Subnets:* %s
				• *Batch ID:* `%s`
				• *TTL:* %d minutes
				• *Reason:* %s
				""".formatted(count, asn, safeOrg, sampleSubnets, batchId, ttlMinutes, reason);

		Map<String, Object> details = new LinkedHashMap<>();
		details.put("asn", asn);
		details.put("asnOrg", safeOrg);
		details.put("subnetsCount", count);
		details.put("subnets", subnets);
		details.put("batchId", batchId);
		details.put("ttlMinutes", ttlMinutes);
		details.put("reason", reason);

		sendAsync("AUTO_BLOCK", "Autonomous Mitigation Enforced", text, details);
	}

	public void sendDryRunAlert(long asn, String asOrg, List<String> subnets, String batchId, int ttlMinutes, String reason) {
		EffectiveNotificationSettings cfg = getEffectiveSettings();
		if (!cfg.enabled() || !cfg.notifyOnDryRun()) {
			return;
		}

		String safeOrg = (asOrg != null && !asOrg.isBlank()) ? asOrg.trim() : "Unknown Organization";
		int count = subnets != null ? subnets.size() : 0;
		String sampleSubnets = (subnets != null && !subnets.isEmpty())
				? String.join(", ", subnets.stream().limit(8).map(s -> "`" + s + "`").toList())
				: "`none`";
		if (count > 8) {
			sampleSubnets += " _(+" + (count - 8) + " more)_";
		}

		String text = """
				🧪 *[Anti-DoS Dry-Run Simulation]* Would block *%d* subnet(s) for *ASN %d (%s)*
				• *Subnets:* %s
				• *Reason:* %s
				• *Note:* No live blocks pushed to Valves (Simulation Mode active).
				""".formatted(count, asn, safeOrg, sampleSubnets, reason);

		Map<String, Object> details = new LinkedHashMap<>();
		details.put("asn", asn);
		details.put("asnOrg", safeOrg);
		details.put("subnetsCount", count);
		details.put("subnets", subnets);
		details.put("batchId", batchId);
		details.put("ttlMinutes", ttlMinutes);
		details.put("reason", reason);

		sendAsync("AUTO_DRY_RUN", "Dry-Run Simulation Triggered", text, details);
	}

	public void sendCircuitBreakerAlert(long currentAutoCount, int maxActiveRules, long asn, int subnetsCount) {
		EffectiveNotificationSettings cfg = getEffectiveSettings();
		if (!cfg.enabled() || !cfg.notifyOnCircuitBreaker()) {
			return;
		}

		String text = """
				⚠️ *[Anti-DoS Circuit Breaker]* Autonomous mitigation limit reached (*%d* / *%d* active rules)
				• *Action:* Skipped auto-blocking *ASN %d* (%d candidate subnets)
				• *Status:* Maximum concurrent autonomous rules reached across the fleet. Operator review recommended.
				""".formatted(currentAutoCount, maxActiveRules, asn, subnetsCount);

		Map<String, Object> details = new LinkedHashMap<>();
		details.put("currentAutoCount", currentAutoCount);
		details.put("maxActiveRules", maxActiveRules);
		details.put("skippedAsn", asn);
		details.put("skippedSubnetsCount", subnetsCount);

		sendAsync("CIRCUIT_BREAKER", "Circuit Breaker Limit Reached", text, details);
	}

	public void sendEmergencyFlushAlert(int revokedCount, String reason, String actor) {
		EffectiveNotificationSettings cfg = getEffectiveSettings();
		if (!cfg.enabled() || !cfg.notifyOnEmergencyFlush()) {
			return;
		}

		String text = """
				🚨 *[Anti-DoS Emergency Flush]* Fleet-wide panic flush executed
				• *Revoked Rules:* *%d* active dynamic CIDR blocks cleared
				• *Operator:* `%s`
				• *Reason:* %s
				• *Status:* All dynamic blocks immediately removed from all Tomcat Valves across the fleet.
				""".formatted(revokedCount, actor != null ? actor : "ADMIN", reason != null ? reason : "Emergency operator override");

		Map<String, Object> details = new LinkedHashMap<>();
		details.put("revokedCount", revokedCount);
		details.put("actor", actor);
		details.put("reason", reason);

		sendAsync("EMERGENCY_FLUSH", "Fleet Emergency Flush Executed", text, details);
	}

	public TestResult sendTestNotification() {
		EffectiveNotificationSettings cfg = getEffectiveSettings();
		if (cfg.webhookUrl() == null || cfg.webhookUrl().isBlank()) {
			return new TestResult(false, 0, "No Webhook URL configured. Please enter a valid Webhook URL first.");
		}

		String nowFormatted = TS_FMT.format(Instant.now());
		String text = """
				✅ *[Anti-DoS Collector]* Webhook test notification successful!
				• *Timestamp:* %s
				• *Status:* Integration with Slack / Webhook target is working properly.
				""".formatted(nowFormatted);

		Map<String, Object> details = new LinkedHashMap<>();
		details.put("test", true);
		details.put("timestamp", Instant.now().toString());

		try {
			HttpRequest request = buildHttpRequest(cfg.webhookUrl().trim(), "TEST", "Webhook Test Notification", text, details);
			HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
			if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
				return new TestResult(true, resp.statusCode(), "Test notification successfully delivered (HTTP " + resp.statusCode() + ").");
			} else {
				String body = resp.body() != null && !resp.body().isBlank() ? ": " + resp.body().trim() : "";
				return new TestResult(false, resp.statusCode(), "Webhook target returned HTTP " + resp.statusCode() + body);
			}
		} catch (Exception e) {
			log.warn("Test notification failed to {}: {}", maskUrl(cfg.webhookUrl()), e.getMessage());
			return new TestResult(false, 0, "Connection failed: " + e.getMessage());
		}
	}

	private void sendAsync(String eventType, String title, String markdownText, Map<String, Object> details) {
		EffectiveNotificationSettings cfg = getEffectiveSettings();
		if (!cfg.enabled() || cfg.webhookUrl() == null || cfg.webhookUrl().isBlank()) {
			return;
		}

		String url = cfg.webhookUrl().trim();
		try {
			HttpRequest request = buildHttpRequest(url, eventType, title, markdownText, details);
			httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
					.thenAccept(resp -> {
						if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
							log.debug("Alert notification '{}' delivered to webhook ({})", eventType, maskUrl(url));
						} else {
							log.warn("Alert notification '{}' to webhook ({}) returned HTTP {}: {}",
									eventType, maskUrl(url), resp.statusCode(), resp.body());
						}
					})
					.exceptionally(ex -> {
						log.warn("Failed to deliver alert notification '{}' to webhook ({}): {}",
								eventType, maskUrl(url), ex.getMessage());
						return null;
					});
		} catch (Exception e) {
			log.warn("Failed to construct notification '{}' for webhook ({}): {}",
					eventType, maskUrl(url), e.getMessage());
		}
	}

	private HttpRequest buildHttpRequest(
			String url,
			String eventType,
			String title,
			String markdownText,
			Map<String, Object> details) throws Exception {
		Map<String, Object> payload = new LinkedHashMap<>();
		payload.put("text", markdownText);
		payload.put("event", eventType);
		payload.put("title", title);
		payload.put("timestamp", Instant.now().toString());
		if (details != null && !details.isEmpty()) {
			payload.put("details", details);
		}

		String json = objectMapper.writeValueAsString(payload);

		return HttpRequest.newBuilder()
				.uri(URI.create(url))
				.timeout(Duration.ofSeconds(6))
				.header("Content-Type", "application/json; charset=UTF-8")
				.header("User-Agent", "Anti-DoS-Collector/1.9.0")
				.POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
				.build();
	}

	public static String maskUrl(String url) {
		if (url == null || url.isBlank()) {
			return "-";
		}
		try {
			URI uri = URI.create(url.trim());
			String host = uri.getHost() != null ? uri.getHost() : "webhook";
			String path = uri.getPath() != null ? uri.getPath() : "";
			if (path.length() > 14) {
				path = path.substring(0, 10) + "...";
			}
			return uri.getScheme() + "://" + host + path;
		} catch (Exception e) {
			return url.length() > 15 ? url.substring(0, 15) + "..." : url;
		}
	}
}
