package org.henbru.antidos.collector.config;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

import org.flywaydb.core.Flyway;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import org.henbru.antidos.collector.AntiDoSCollectorApplication;
import org.henbru.antidos.collector.demo.MockValveController;
import org.henbru.antidos.collector.poller.CollectorPollerService;
import org.henbru.antidos.collector.poller.CollectorScheduler;
import org.henbru.antidos.collector.web.ApiController;
import org.henbru.antidos.collector.web.CrawlerController;
import org.henbru.antidos.collector.web.DailyReportController;
import org.henbru.antidos.collector.web.DashboardController;
import org.henbru.antidos.collector.web.GlobalModelAdvice;
import org.henbru.antidos.collector.web.MitigationController;
import org.henbru.antidos.collector.web.NotesController;
import org.henbru.antidos.collector.web.SystemController;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.DefaultBootstrapContext;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SuppressWarnings("null")
class CollectorModeTest {

	@Nested
	class CollectorModeUnitTests {

		@Test
		void fromStringParsesCaseInsensitiveAndDefaultsBlankToFull() {
			assertEquals(CollectorMode.FULL, CollectorMode.fromString(null));
			assertEquals(CollectorMode.FULL, CollectorMode.fromString("   "));
			assertEquals(CollectorMode.FULL, CollectorMode.fromString("full"));
			assertEquals(CollectorMode.HEADLESS, CollectorMode.fromString(" headless "));
			assertEquals(CollectorMode.VIEWER, CollectorMode.fromString("Viewer"));
			assertEquals(CollectorMode.OPERATOR, CollectorMode.fromString(" OpErAtOr "));
			assertThrows(IllegalArgumentException.class, () -> CollectorMode.fromString("invalid"));
		}

		@Test
		void capabilityFlagsReflectModeSemantics() {
			assertTrue(CollectorMode.FULL.isWebEnabled());
			assertTrue(CollectorMode.FULL.isBackgroundProcessingEnabled());
			assertFalse(CollectorMode.FULL.isHeadless());
			assertFalse(CollectorMode.FULL.isViewer());
			assertFalse(CollectorMode.FULL.isOperator());
			assertTrue(CollectorMode.FULL.canModifyOperationalData());
			assertTrue(CollectorMode.FULL.canPerformSystemAdmin());

			assertFalse(CollectorMode.HEADLESS.isWebEnabled());
			assertTrue(CollectorMode.HEADLESS.isBackgroundProcessingEnabled());
			assertTrue(CollectorMode.HEADLESS.isHeadless());
			assertFalse(CollectorMode.HEADLESS.isViewer());
			assertFalse(CollectorMode.HEADLESS.isOperator());
			assertFalse(CollectorMode.HEADLESS.canModifyOperationalData());
			assertFalse(CollectorMode.HEADLESS.canPerformSystemAdmin());

			assertTrue(CollectorMode.VIEWER.isWebEnabled());
			assertFalse(CollectorMode.VIEWER.isBackgroundProcessingEnabled());
			assertFalse(CollectorMode.VIEWER.isHeadless());
			assertTrue(CollectorMode.VIEWER.isViewer());
			assertFalse(CollectorMode.VIEWER.isOperator());
			assertFalse(CollectorMode.VIEWER.canModifyOperationalData());
			assertFalse(CollectorMode.VIEWER.canPerformSystemAdmin());

			assertTrue(CollectorMode.OPERATOR.isWebEnabled());
			assertFalse(CollectorMode.OPERATOR.isBackgroundProcessingEnabled());
			assertFalse(CollectorMode.OPERATOR.isHeadless());
			assertFalse(CollectorMode.OPERATOR.isViewer());
			assertTrue(CollectorMode.OPERATOR.isOperator());
			assertTrue(CollectorMode.OPERATOR.canModifyOperationalData());
			assertFalse(CollectorMode.OPERATOR.canPerformSystemAdmin());
		}
	}

	@Nested
	class EnvironmentListenerTests {

		private final CollectorModeEnvironmentListener listener = new CollectorModeEnvironmentListener();

		private void fire(MockEnvironment env) {
			ApplicationEnvironmentPreparedEvent event = new ApplicationEnvironmentPreparedEvent(
					new DefaultBootstrapContext(),
					new SpringApplication(AntiDoSCollectorApplication.class),
					new String[0],
					env);
			listener.onApplicationEvent(event);
		}

		@Test
		void headlessDisablesWebServerAndEnablesKeepAlive() {
			MockEnvironment env = new MockEnvironment().withProperty("collector.mode", "HEADLESS");
			fire(env);

			assertEquals("none", env.getProperty("spring.main.web-application-type"));
			assertEquals("true", env.getProperty("spring.main.keep-alive"));
		}

		@Test
		void viewerDisablesFlywayAndAutoMitigationByDefault() {
			MockEnvironment env = new MockEnvironment().withProperty("collector.mode", "VIEWER");
			fire(env);

			assertEquals("false", env.getProperty("spring.flyway.enabled"));
			assertEquals("false", env.getProperty("collector.auto-mitigation.enabled"));
		}

		@Test
		void operatorDisablesFlywayAndAutoMitigationByDefault() {
			MockEnvironment env = new MockEnvironment().withProperty("collector.mode", "OPERATOR");
			fire(env);

			assertEquals("false", env.getProperty("spring.flyway.enabled"));
			assertEquals("false", env.getProperty("collector.auto-mitigation.enabled"));
		}

		@Test
		void viewerKeepsFlywayEnabledWhenMigrateOnStartupIsTrue() {
			MockEnvironment env = new MockEnvironment()
					.withProperty("collector.mode", "VIEWER")
					.withProperty("collector.viewer-migrate-on-startup", "true")
					.withProperty("spring.flyway.enabled", "true");
			fire(env);

			assertEquals("true", env.getProperty("spring.flyway.enabled"));
			assertEquals("false", env.getProperty("collector.auto-mitigation.enabled"));
		}

		@Test
		void operatorKeepsFlywayEnabledWhenMigrateOnStartupIsTrue() {
			MockEnvironment env = new MockEnvironment()
					.withProperty("collector.mode", "OPERATOR")
					.withProperty("collector.viewer-migrate-on-startup", "true")
					.withProperty("spring.flyway.enabled", "true");
			fire(env);

			assertEquals("true", env.getProperty("spring.flyway.enabled"));
			assertEquals("false", env.getProperty("collector.auto-mitigation.enabled"));
		}

		@Test
		void rejectsDemoModeCombinedWithHeadlessViewerOrOperator() {
			MockEnvironment headlessDemo = new MockEnvironment()
					.withProperty("collector.mode", "HEADLESS")
					.withProperty("collector.demo-mode", "true");
			assertThrows(IllegalStateException.class, () -> fire(headlessDemo));

			MockEnvironment viewerDemo = new MockEnvironment()
					.withProperty("collector.mode", "VIEWER")
					.withProperty("collector.demo-mode", "true");
			assertThrows(IllegalStateException.class, () -> fire(viewerDemo));

			MockEnvironment operatorDemo = new MockEnvironment()
					.withProperty("collector.mode", "OPERATOR")
					.withProperty("collector.demo-mode", "true");
			assertThrows(IllegalStateException.class, () -> fire(operatorDemo));
		}
	}

	@Nested
	class ModeRuntimeIntegrationTests {

		@Test
		void headlessModeStartsWithoutWebServerOrControllers(@TempDir Path tempDir) {
			Path dbPath = tempDir.resolve("headless.db");
			String jdbcUrl = "jdbc:sqlite:" + dbPath.toAbsolutePath() + "?busy_timeout=60000";

			try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(AntiDoSCollectorApplication.class)
					.run(
							"--collector.mode=HEADLESS",
							"--spring.datasource.url=" + jdbcUrl,
							"--collector.polling.enabled=false")) {
				assertFalse(ctx instanceof WebApplicationContext);

				CollectorProperties props = ctx.getBean(CollectorProperties.class);
				assertTrue(props.isHeadlessMode());
				assertFalse(props.isViewerMode());
				assertEquals(CollectorMode.HEADLESS, props.getMode());

				assertEquals(0, ctx.getBeanNamesForType(DashboardController.class).length);
				assertEquals(0, ctx.getBeanNamesForType(ApiController.class).length);
				assertEquals(0, ctx.getBeanNamesForType(SystemController.class).length);
				assertEquals(0, ctx.getBeanNamesForType(MitigationController.class).length);
				assertEquals(0, ctx.getBeanNamesForType(NotesController.class).length);
				assertEquals(0, ctx.getBeanNamesForType(CrawlerController.class).length);
				assertEquals(0, ctx.getBeanNamesForType(DailyReportController.class).length);
				assertEquals(0, ctx.getBeanNamesForType(MockValveController.class).length);
				assertEquals(0, ctx.getBeanNamesForType(GlobalModelAdvice.class).length);

				assertEquals(1, ctx.getBeanNamesForType(CollectorScheduler.class).length);
				assertEquals(1, ctx.getBeanNamesForType(CollectorPollerService.class).length);
			}
		}

		@Test
		void viewerModeFailsFastWhenSqliteFileDoesNotExist(@TempDir Path tempDir) {
			Path missingDir = tempDir.resolve("nonexistent-dir");
			Path missingDb = missingDir.resolve("missing.db");
			String jdbcUrl = "jdbc:sqlite:" + missingDb.toAbsolutePath() + "?busy_timeout=60000";

			assertThrows(RuntimeException.class, () -> {
				try (ConfigurableApplicationContext ignored = new SpringApplicationBuilder(
						AntiDoSCollectorApplication.class)
						.run(
								"--collector.mode=VIEWER",
								"--spring.datasource.url=" + jdbcUrl,
								"--server.port=0")) {
					// Expected to fail before opening or creating missing database file
				}
			});

			assertFalse(Files.exists(missingDir), "Viewer mode must not create missing parent directories");
			assertFalse(Files.exists(missingDb), "Viewer mode must not create missing SQLite files");
		}

		@Test
		void viewerModeIsStrictlyReadOnlyEndToEnd(@TempDir Path tempDir) throws Exception {
			Path dbPath = tempDir.resolve("viewer-snapshot.db");
			String jdbcUrl = "jdbc:sqlite:" + dbPath.toAbsolutePath() + "?busy_timeout=60000";

			Flyway.configure()
					.dataSource(jdbcUrl, "", "")
					.locations("classpath:db/migration/sqlite")
					.load()
					.migrate();

			try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(AntiDoSCollectorApplication.class)
					.run(
							"--collector.mode=VIEWER",
							"--spring.datasource.url=" + jdbcUrl,
							"--server.port=0")) {
				assertTrue(ctx instanceof WebApplicationContext);

				CollectorProperties props = ctx.getBean(CollectorProperties.class);
				assertTrue(props.isViewerMode());
				assertFalse(props.isHeadlessMode());
				assertEquals(CollectorMode.VIEWER, props.getMode());

				JdbcTemplate jdbc = ctx.getBean(JdbcTemplate.class);
				Integer queryOnly = jdbc.queryForObject("PRAGMA query_only", Integer.class);
				assertEquals(1, queryOnly);

				String journalMode = jdbc.queryForObject("PRAGMA journal_mode", String.class);
				assertNotNull(journalMode);
				assertNotEquals("wal", journalMode.toLowerCase(Locale.ROOT));

				assertThrows(DataAccessException.class,
						() -> jdbc.update("DELETE FROM flyway_schema_history WHERE installed_rank = -999"));

				int flywayCountBefore = jdbc.queryForObject("SELECT COUNT(*) FROM flyway_schema_history", Integer.class);
				int crawlerCountBefore = jdbc.queryForObject("SELECT COUNT(*) FROM crawler_feeds", Integer.class);
				int eventsCountBefore = jdbc.queryForObject("SELECT COUNT(*) FROM client_events", Integer.class);
				int annotationsCountBefore = jdbc.queryForObject(
						"SELECT COUNT(*) FROM network_annotations", Integer.class);
				int reportsCountBefore = jdbc.queryForObject("SELECT COUNT(*) FROM daily_reports", Integer.class);
				int rulesCountBefore = jdbc.queryForObject("SELECT COUNT(*) FROM mitigation_rules", Integer.class);
				int profilesCountBefore = jdbc.queryForObject("SELECT COUNT(*) FROM subnet_profiles", Integer.class);

				MockMvc mockMvc = MockMvcBuilders.webAppContextSetup((WebApplicationContext) ctx).build();

				List<String> htmlPages = List.of(
						"/", "/events", "/offenders", "/profiles", "/analytics",
						"/mitigation", "/notes", "/reports", "/crawlers", "/system", "/poll-log", "/help");
				for (String path : htmlPages) {
					mockMvc.perform(get(path))
							.andExpect(status().isOk())
							.andExpect(content().string(containsString("READ-ONLY VIEWER MODE")));
				}

				mockMvc.perform(get("/system"))
						.andExpect(status().isOk())
						.andExpect(content().string(containsString("VIEWER")));

				mockMvc.perform(get("/api/v1/fleet"))
						.andExpect(status().isOk());
				mockMvc.perform(get("/api/v1/mitigation/rules"))
						.andExpect(status().isOk());

				mockMvc.perform(post("/system/retention-cleanup")).andExpect(status().isForbidden());
				mockMvc.perform(post("/system/vacuum")).andExpect(status().isForbidden());
				mockMvc.perform(post("/system/rollup-catchup")).andExpect(status().isForbidden());
				mockMvc.perform(post("/system/clear-cache")).andExpect(status().isForbidden());
				mockMvc.perform(post("/crawlers/sync-all")).andExpect(status().isForbidden());
				mockMvc.perform(post("/notes")
								.param("targetType", "SUBNET")
								.param("targetKey", "203.0.113.0/24")
								.param("verdict", "SUSPICIOUS")
								.param("noteMarkdown", "test"))
						.andExpect(status().isForbidden());
				mockMvc.perform(delete("/notes/1")).andExpect(status().isForbidden());
				mockMvc.perform(post("/reports/generate")).andExpect(status().isForbidden());
				mockMvc.perform(post("/reports/2026-11-14/note")
								.param("noteMarkdown", "test"))
						.andExpect(status().isForbidden());
				mockMvc.perform(post("/profiles/refresh")).andExpect(status().isForbidden());
				mockMvc.perform(post("/mitigation/block")
								.param("cidrInput", "203.0.113.0/24"))
						.andExpect(status().isForbidden());
				mockMvc.perform(post("/mitigation/flush")).andExpect(status().isForbidden());
				mockMvc.perform(post("/api/v1/rollups/subnets/aggregate")).andExpect(status().isForbidden());

				assertEquals(flywayCountBefore,
						jdbc.queryForObject("SELECT COUNT(*) FROM flyway_schema_history", Integer.class));
				assertEquals(crawlerCountBefore,
						jdbc.queryForObject("SELECT COUNT(*) FROM crawler_feeds", Integer.class));
				assertEquals(eventsCountBefore,
						jdbc.queryForObject("SELECT COUNT(*) FROM client_events", Integer.class));
				assertEquals(annotationsCountBefore,
						jdbc.queryForObject("SELECT COUNT(*) FROM network_annotations", Integer.class));
				assertEquals(reportsCountBefore,
						jdbc.queryForObject("SELECT COUNT(*) FROM daily_reports", Integer.class));
				assertEquals(rulesCountBefore,
						jdbc.queryForObject("SELECT COUNT(*) FROM mitigation_rules", Integer.class));
				assertEquals(profilesCountBefore,
						jdbc.queryForObject("SELECT COUNT(*) FROM subnet_profiles", Integer.class));
			}
		}

		@Test
		void operatorModeFailsFastWhenSqliteFileDoesNotExist(@TempDir Path tempDir) {
			Path missingDir = tempDir.resolve("nonexistent-operator-dir");
			Path missingDb = missingDir.resolve("missing.db");
			String jdbcUrl = "jdbc:sqlite:" + missingDb.toAbsolutePath() + "?busy_timeout=60000";

			assertThrows(RuntimeException.class, () -> {
				try (ConfigurableApplicationContext ignored = new SpringApplicationBuilder(
						AntiDoSCollectorApplication.class)
						.run(
								"--collector.mode=OPERATOR",
								"--spring.datasource.url=" + jdbcUrl,
								"--server.port=0")) {
					// Expected to fail before opening or creating missing database file
				}
			});

			assertFalse(Files.exists(missingDir), "Operator mode must not create missing parent directories");
			assertFalse(Files.exists(missingDb), "Operator mode must not create missing SQLite files");
		}

		@Test
		void operatorModeAllowsNotesReportsAndMitigationsWhileBlockingSystemAdmin(@TempDir Path tempDir)
				throws Exception {
			Path dbPath = tempDir.resolve("operator-live.db");
			String jdbcUrl = "jdbc:sqlite:" + dbPath.toAbsolutePath() + "?busy_timeout=60000";

			Flyway.configure()
					.dataSource(jdbcUrl, "", "")
					.locations("classpath:db/migration/sqlite")
					.load()
					.migrate();

			try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(AntiDoSCollectorApplication.class)
					.run(
							"--collector.mode=OPERATOR",
							"--spring.datasource.url=" + jdbcUrl,
							"--server.port=0")) {
				assertTrue(ctx instanceof WebApplicationContext);

				CollectorProperties props = ctx.getBean(CollectorProperties.class);
				assertTrue(props.isOperatorMode());
				assertFalse(props.isViewerMode());
				assertFalse(props.isHeadlessMode());
				assertTrue(props.canModifyOperationalData());
				assertFalse(props.canPerformSystemAdmin());
				assertEquals(CollectorMode.OPERATOR, props.getMode());

				JdbcTemplate jdbc = ctx.getBean(JdbcTemplate.class);
				Integer queryOnly = jdbc.queryForObject("PRAGMA query_only", Integer.class);
				assertEquals(0, queryOnly);

				String journalMode = jdbc.queryForObject("PRAGMA journal_mode", String.class);
				assertNotNull(journalMode);
				assertEquals("wal", journalMode.toLowerCase(Locale.ROOT));

				MockMvc mockMvc = MockMvcBuilders.webAppContextSetup((WebApplicationContext) ctx).build();

				List<String> htmlPages = List.of(
						"/", "/events", "/offenders", "/profiles", "/analytics",
						"/mitigation", "/notes", "/reports", "/crawlers", "/system", "/poll-log", "/help");
				for (String path : htmlPages) {
					var result = mockMvc.perform(get(path))
							.andExpect(status().isOk())
							.andExpect(content().string(containsString("OPERATOR MODE")));
					if (!"/help".equals(path)) {
						result.andExpect(content().string(not(containsString("READ-ONLY VIEWER MODE"))));
					}
				}

				mockMvc.perform(get("/system"))
						.andExpect(status().isOk())
						.andExpect(content().string(containsString("OPERATOR")));

				mockMvc.perform(get("/api/v1/fleet"))
						.andExpect(status().isOk());
				mockMvc.perform(get("/api/v1/mitigation/rules"))
						.andExpect(status().isOk());

				// Allowed: Network notes create + delete
				mockMvc.perform(post("/notes")
								.param("targetType", "SUBNET")
								.param("targetKey", "203.0.113.0/24")
								.param("verdict", "SUSPICIOUS")
								.param("noteMarkdown", "Operator triage note"))
						.andExpect(status().isOk());
				assertEquals(1, jdbc.queryForObject(
						"SELECT COUNT(*) FROM network_annotations WHERE target_key = '203.0.113.0/24'",
						Integer.class));
				Long noteId = jdbc.queryForObject(
						"SELECT id FROM network_annotations WHERE target_key = '203.0.113.0/24'",
						Long.class);
				assertNotNull(noteId);

				mockMvc.perform(delete("/notes/" + noteId))
						.andExpect(status().isOk());
				assertEquals(0, jdbc.queryForObject(
						"SELECT COUNT(*) FROM network_annotations WHERE target_key = '203.0.113.0/24'",
						Integer.class));

				// Allowed: Daily report notes + report generation
				mockMvc.perform(post("/reports/2026-11-14/note")
								.header("HX-Request", "true")
								.param("noteMarkdown", "Operator shift handoff"))
						.andExpect(status().isOk());
				assertEquals(1, jdbc.queryForObject(
						"SELECT COUNT(*) FROM daily_report_notes WHERE report_date = '2026-11-14'",
						Integer.class));

				mockMvc.perform(post("/reports/generate")
								.param("date", "2026-11-14"))
						.andExpect(status().is3xxRedirection());
				assertEquals(1, jdbc.queryForObject(
						"SELECT COUNT(*) FROM daily_reports WHERE report_date = '2026-11-14'",
						Integer.class));

				// Allowed: Dynamic mitigation block -> extend -> revoke (persisted to DB without outbound Valve push)
				mockMvc.perform(post("/mitigation/block")
								.param("cidrInput", "203.0.113.0/24")
								.param("ttlMinutes", "30")
								.param("reason", "Operator manual block"))
						.andExpect(status().isOk());

				Long ruleId = jdbc.queryForObject(
						"SELECT id FROM mitigation_rules WHERE cidr = '203.0.113.0/24' AND status = 'ACTIVE'",
						Long.class);
				assertNotNull(ruleId);
				String initialExpiresAt = jdbc.queryForObject(
						"SELECT expires_at FROM mitigation_rules WHERE id = ?",
						String.class,
						ruleId);

				mockMvc.perform(post("/mitigation/" + ruleId + "/extend")
								.param("additionalMinutes", "60"))
						.andExpect(status().isOk());
				String extendedExpiresAt = jdbc.queryForObject(
						"SELECT expires_at FROM mitigation_rules WHERE id = ?",
						String.class,
						ruleId);
				assertNotEquals(initialExpiresAt, extendedExpiresAt);

				mockMvc.perform(post("/mitigation/" + ruleId + "/revoke")
								.param("reason", "Cleared by operator"))
						.andExpect(status().isOk());
				String statusAfterRevoke = jdbc.queryForObject(
						"SELECT status FROM mitigation_rules WHERE id = ?",
						String.class,
						ruleId);
				assertEquals("REVOKED", statusAfterRevoke);
				Integer auditCount = jdbc.queryForObject(
						"SELECT COUNT(*) FROM mitigation_audit_log WHERE rule_id = ?",
						Integer.class,
						ruleId);
				assertNotNull(auditCount);
				assertTrue(auditCount >= 3);

				// Blocked: System admin, maintenance, crawlers, profiles, valve deletion, fleet sync & auto-mitigation
				mockMvc.perform(post("/system/retention-cleanup")).andExpect(status().isForbidden());
				mockMvc.perform(post("/system/vacuum")).andExpect(status().isForbidden());
				mockMvc.perform(post("/system/rollup-catchup")).andExpect(status().isForbidden());
				mockMvc.perform(post("/system/clear-cache")).andExpect(status().isForbidden());
				mockMvc.perform(post("/crawlers/sync-all")).andExpect(status().isForbidden());
				mockMvc.perform(post("/crawlers/spamhaus-drop/sync")).andExpect(status().isForbidden());
				mockMvc.perform(post("/crawlers/sync-browser-feeds")).andExpect(status().isForbidden());
				mockMvc.perform(post("/profiles/refresh")).andExpect(status().isForbidden());
				mockMvc.perform(post("/server/srv-1/valves/valve-1/delete")).andExpect(status().isForbidden());
				mockMvc.perform(post("/api/v1/rollups/subnets/aggregate")).andExpect(status().isForbidden());
				mockMvc.perform(post("/api/v1/rollups/subnets/profiles/refresh")).andExpect(status().isForbidden());
				mockMvc.perform(post("/mitigation/sync")).andExpect(status().isForbidden());
				mockMvc.perform(post("/mitigation/auto/toggle")
								.param("property", "enabled"))
						.andExpect(status().isForbidden());
				mockMvc.perform(post("/mitigation/auto/reset")).andExpect(status().isForbidden());
				mockMvc.perform(post("/mitigation/auto/evaluate")).andExpect(status().isForbidden());
				mockMvc.perform(post("/mitigation/webhook/test")).andExpect(status().isForbidden());
			}
		}
	}
}
