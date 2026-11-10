package org.henbru.antidos.collector.notification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.storage.SystemSettingsRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

class AlertNotificationServiceTest {

	private CollectorProperties properties;
	private SystemSettingsRepository systemSettings;
	private ObjectMapper objectMapper;
	private HttpClient httpClient;
	private AlertNotificationService service;

	@BeforeEach
	void setUp() {
		properties = new CollectorProperties();
		systemSettings = mock(SystemSettingsRepository.class);
		objectMapper = new ObjectMapper();
		httpClient = mock(HttpClient.class);
		service = new AlertNotificationService(properties, systemSettings, objectMapper, httpClient);
	}

	@Test
	void testEffectiveSettingsFallbacksToPropertiesWhenNoDatabaseOverrides() {
		properties.getNotification().setEnabled(false);
		properties.getNotification().setWebhookUrl("https://hooks.slack.com/services/test");
		properties.getNotification().setNotifyOnDryRun(true);

		when(systemSettings.getBoolean(any())).thenReturn(Optional.empty());
		when(systemSettings.getString(any())).thenReturn(Optional.empty());

		var effective = service.getEffectiveSettings();
		assertFalse(effective.enabled());
		assertEquals("https://hooks.slack.com/services/test", effective.webhookUrl());
		assertTrue(effective.notifyOnDryRun());
		assertFalse(effective.hasDatabaseOverrides());
	}

	@Test
	void testEffectiveSettingsUsesDatabaseOverridesWhenPresent() {
		properties.getNotification().setEnabled(false);
		properties.getNotification().setWebhookUrl("https://static.example.com");

		when(systemSettings.getBoolean(AlertNotificationService.SETTING_ENABLED)).thenReturn(Optional.of(true));
		when(systemSettings.getString(AlertNotificationService.SETTING_WEBHOOK_URL)).thenReturn(Optional.of("https://hooks.slack.com/services/override"));
		when(systemSettings.getBoolean(AlertNotificationService.SETTING_NOTIFY_DRY_RUN)).thenReturn(Optional.of(false));

		var effective = service.getEffectiveSettings();
		assertTrue(effective.enabled());
		assertEquals("https://hooks.slack.com/services/override", effective.webhookUrl());
		assertFalse(effective.notifyOnDryRun());
		assertTrue(effective.hasDatabaseOverrides());
	}

	@Test
	void testUpdateSettingsSetsDatabaseEntries() {
		service.updateSettings(true, "https://hooks.slack.com/services/T123/B456/XYZ", true, true, "ADMIN");

		verify(systemSettings).setSetting(AlertNotificationService.SETTING_ENABLED, "true", "Master switch for webhook alert notifications", "ADMIN");
		verify(systemSettings).setSetting(AlertNotificationService.SETTING_WEBHOOK_URL, "https://hooks.slack.com/services/T123/B456/XYZ", "Webhook target URL (Slack, Teams, Discord, Generic)", "ADMIN");
		verify(systemSettings).setSetting(AlertNotificationService.SETTING_NOTIFY_DRY_RUN, "true", "Send notifications on simulation dry-run triggers", "ADMIN");
		verify(systemSettings).setSetting(AlertNotificationService.SETTING_NOTIFY_EMERGENCY_FLUSH, "true", "Send notifications on emergency flush events", "ADMIN");
	}

	@Test
	void testResetToDefaultsDeletesSettings() {
		service.resetToDefaults("ADMIN");

		verify(systemSettings).deleteSetting(AlertNotificationService.SETTING_ENABLED);
		verify(systemSettings).deleteSetting(AlertNotificationService.SETTING_WEBHOOK_URL);
		verify(systemSettings).deleteSetting(AlertNotificationService.SETTING_NOTIFY_DRY_RUN);
	}

	@Test
	void testMaskUrlHidesSensitiveTokens() {
		assertEquals("-", AlertNotificationService.maskUrl(null));
		assertEquals("-", AlertNotificationService.maskUrl(""));

		String slackUrl = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
		String masked = AlertNotificationService.maskUrl(slackUrl);
		assertTrue(masked.startsWith("https://hooks.slack.com/services/"));
		assertTrue(masked.contains("..."));
		assertFalse(masked.contains("XXXXXXXXXXXXXXXXXXXXXXXX"));
	}

	@Test
	@SuppressWarnings("unchecked")
	void testSendTestNotificationSuccess() throws IOException, InterruptedException {
		properties.getNotification().setWebhookUrl("https://hooks.slack.com/services/test");
		when(systemSettings.getString(any())).thenReturn(Optional.empty());

		HttpResponse<String> mockResponse = mock(HttpResponse.class);
		when(mockResponse.statusCode()).thenReturn(200);
		when(mockResponse.body()).thenReturn("ok");
		when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(mockResponse);

		AlertNotificationService.TestResult result = service.sendTestNotification();
		assertTrue(result.success());
		assertEquals(200, result.statusCode());
		assertTrue(result.message().contains("successfully delivered"));
	}

	@Test
	@SuppressWarnings("unchecked")
	void testSendTestNotificationMissingUrl() {
		properties.getNotification().setWebhookUrl("");
		when(systemSettings.getString(any())).thenReturn(Optional.empty());

		AlertNotificationService.TestResult result = service.sendTestNotification();
		assertFalse(result.success());
		assertTrue(result.message().contains("No Webhook URL configured"));
	}

	@Test
	@SuppressWarnings("unchecked")
	void testAlertMethodsTriggerAsyncHttpRequestsWhenEnabled() {
		properties.getNotification().setEnabled(true);
		properties.getNotification().setWebhookUrl("https://hooks.slack.com/services/test");
		when(systemSettings.getBoolean(any())).thenReturn(Optional.empty());
		when(systemSettings.getString(any())).thenReturn(Optional.empty());

		HttpResponse<String> mockResponse = mock(HttpResponse.class);
		when(mockResponse.statusCode()).thenReturn(200);
		when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
				.thenReturn(CompletableFuture.completedFuture(mockResponse));

		// Auto block
		service.sendAutoBlockAlert(64496L, "Example AS", List.of("198.51.100.0/24"), "BATCH-1", 60, "Carpet attack");
		// Dry run
		service.sendDryRunAlert(64496L, "Example AS", List.of("198.51.100.0/24"), "BATCH-1", 60, "Carpet attack");
		// Circuit breaker
		service.sendCircuitBreakerAlert(50, 50, 64496L, 5);
		// Emergency flush
		service.sendEmergencyFlushAlert(3, "Operator override", "ADMIN");

		verify(httpClient, org.mockito.Mockito.times(4))
				.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
	}
}

