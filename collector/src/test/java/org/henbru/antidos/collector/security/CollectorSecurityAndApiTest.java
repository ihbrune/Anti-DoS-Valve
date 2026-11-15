package org.henbru.antidos.collector.security;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Valve;
import org.henbru.antidos.AntiDoSValve;
import org.henbru.antidos.collector.config.CollectorMode;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.CollectorTokenRole;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.embedded.tomcat.TomcatWebServer;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest(
		webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = {
				"collector.mode=FULL",
				"collector.security.require-auth-for-read=true",
				"collector.security.api-enabled=true",
				"collector.security.max-auth-failures=3",
				"collector.security.auth-lockout-seconds=60",
				"collector.security.ai-guardrails.max-ttl-minutes=120",
				"collector.security.ai-guardrails.max-blocks-per-hour=20",
				"collector.security.ai-guardrails.min-reason-length=15",
				"collector.security.ai-guardrails.allow-asn-batch-block=false",
				"collector.security.ai-guardrails.min-ipv4-prefix=24",
				"collector.security.ai-guardrails.min-ipv6-prefix=48",
				"collector.self-protection.enabled=true"
		}
)
@AutoConfigureMockMvc
@SuppressWarnings("null")
class CollectorSecurityAndApiTest {

	private static final String ADMIN_TOKEN = "aa11".repeat(16);
	private static final String OPERATOR_TOKEN = "bb22".repeat(16);
	private static final String AI_TOKEN = "cc33".repeat(16);
	private static final String VIEWER_TOKEN = "dd44".repeat(16);
	private static final String DISABLED_TOKEN = "ee55".repeat(16);

	@TempDir
	static Path tempDir;

	@DynamicPropertySource
	static void registerDatasource(DynamicPropertyRegistry registry) {
		Path dbPath = tempDir.resolve("collector-security-test.db");
		registry.add("spring.datasource.url", () -> "jdbc:sqlite:" + dbPath.toAbsolutePath() + "?busy_timeout=60000");
	}

	@LocalServerPort
	private int port;

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private CollectorProperties properties;

	@Autowired
	private CollectorSecurityService securityService;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private ServletWebServerApplicationContext webServerContext;

	@BeforeEach
	void resetState() {
		properties.setMode(CollectorMode.FULL);
		properties.setDemoMode(false);
		properties.getSecurity().setRequireAuthForRead(true);
		properties.getSecurity().setApiEnabled(true);
		properties.getSecurity().setMaxAuthFailures(3);
		properties.getSecurity().getAiGuardrails().setMaxTtlMinutes(120);
		properties.getSecurity().getAiGuardrails().setMaxBlocksPerHour(20);
		properties.getSecurity().getAiGuardrails().setMinReasonLength(15);
		properties.getSecurity().getAiGuardrails().setAllowAsnBatchBlock(false);
		properties.getSecurity().setTokens(new java.util.ArrayList<>(List.of(
				new CollectorProperties.TokenEntry("soc-admin", CollectorTokenRole.ADMIN, ADMIN_TOKEN, true),
				new CollectorProperties.TokenEntry("soc-operator", CollectorTokenRole.OPERATOR, OPERATOR_TOKEN, true),
				new CollectorProperties.TokenEntry("triage-bot", CollectorTokenRole.AI_AGENT, AI_TOKEN, true),
				new CollectorProperties.TokenEntry("audit-viewer", CollectorTokenRole.VIEWER, VIEWER_TOKEN, true),
				new CollectorProperties.TokenEntry("disabled-user", CollectorTokenRole.ADMIN, DISABLED_TOKEN, false)
		)));

		securityService.clearAuthFailures("127.0.0.1");
		securityService.clearAuthFailures("198.51.100.77");
		securityService.clearAuthFailures("203.0.113.55");

		jdbcTemplate.update("DELETE FROM mitigation_audit_log");
		jdbcTemplate.update("DELETE FROM mitigation_rules");
		jdbcTemplate.update("DELETE FROM network_annotations");
		jdbcTemplate.update("DELETE FROM daily_report_notes");
		jdbcTemplate.update("DELETE FROM daily_reports");
	}

	@AfterEach
	void restoreMode() {
		properties.setMode(CollectorMode.FULL);
	}

	@Test
	void testEmbeddedSelfProtectionValveStartsCleanlyOnRealTomcat() throws Exception {
		assertTrue(port > 0);
		assertTrue(webServerContext.getWebServer() instanceof TomcatWebServer);
		TomcatWebServer tomcatWebServer = (TomcatWebServer) webServerContext.getWebServer();

		AntiDoSValve foundValve = null;
		for (Container child : tomcatWebServer.getTomcat().getHost().findChildren()) {
			if (child instanceof Context ctx) {
				for (Valve valve : ctx.getPipeline().getValves()) {
					if (valve instanceof AntiDoSValve adValve) {
						foundValve = adValve;
						break;
					}
				}
			}
		}

		assertNotNull(foundValve, "Embedded AntiDoSValve should be registered in Tomcat Context pipeline");
		assertEquals(LifecycleState.STARTED, foundValve.getState());
		assertEquals("Collector-Self-Protection", foundValve.getMonitorName());
		assertEquals(600, foundValve.getAllowedRequestsPerSlot());

		mockMvc.perform(get("/login"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Sign In")))
				.andExpect(content().string(containsString("autocomplete=\"current-password\"")));
	}

	@Test
	void testUnconfiguredTokensBehaviorAndFailClosedWriteApis() throws Exception {
		properties.getSecurity().getTokens().clear();

		// Loopback read succeeds and Web UI auto-issues a local cookie
		mockMvc.perform(get("/api/v1/fleet").with(req -> {
			req.setRemoteAddr("127.0.0.1");
			return req;
		}))
				.andExpect(status().isOk());

		MvcResult uiResult = mockMvc.perform(get("/").with(req -> {
			req.setRemoteAddr("127.0.0.1");
			return req;
		}))
				.andExpect(status().isOk())
				.andExpect(header().string(HttpHeaders.SET_COOKIE, containsString(CollectorSecurityService.SESSION_COOKIE_NAME + "=")))
				.andReturn();
		assertNotNull(uiResult.getResponse().getCookie(CollectorSecurityService.SESSION_COOKIE_NAME));

		// Non-loopback read is rejected when require-auth-for-read=true
		mockMvc.perform(get("/api/v1/fleet").with(req -> {
			req.setRemoteAddr("203.0.113.55");
			return req;
		}))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.status").value("UNAUTHORIZED"));

		// Operational write APIs are strictly fail-closed even on loopback when no tokens exist
		mockMvc.perform(post("/api/v1/notes")
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"targetType\":\"ASN\",\"targetKey\":\"AS64512\",\"verdict\":\"MALICIOUS\",\"noteMarkdown\":\"Test operational note\"}")
				.with(req -> {
					req.setRemoteAddr("127.0.0.1");
					return req;
				}))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.status").value("UNAUTHORIZED"));

		mockMvc.perform(post("/api/v1/mitigation/block")
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"198.51.100.0/24\",\"ttlMinutes\":60,\"reason\":\"Fail-closed test block\"}")
				.with(req -> {
					req.setRemoteAddr("127.0.0.1");
					return req;
				}))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void testMultiTokenAuthSessionCookieLogoutAndBruteForceLockout() throws Exception {
		// Unauthenticated API read fails when tokens are configured
		mockMvc.perform(get("/api/v1/fleet"))
				.andExpect(status().isUnauthorized());

		// Unauthenticated Web UI redirects to /login (and HX-Redirect for HTMX)
		mockMvc.perform(get("/"))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string(HttpHeaders.LOCATION, "/login"));

		mockMvc.perform(get("/").header("HX-Request", "true"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("HX-Redirect", "/login"));

		// Read access works with Bearer, X-AntiDoS-Token, or ?token=, while disabled tokens are rejected
		mockMvc.perform(get("/api/v1/fleet").header(HttpHeaders.AUTHORIZATION, "Bearer " + VIEWER_TOKEN))
				.andExpect(status().isOk());
		mockMvc.perform(get("/api/v1/fleet").header(CollectorSecurityInterceptor.TOKEN_HEADER, OPERATOR_TOKEN))
				.andExpect(status().isOk());
		mockMvc.perform(get("/api/v1/fleet").param("token", ADMIN_TOKEN))
				.andExpect(status().isOk());
		mockMvc.perform(get("/api/v1/fleet").header(HttpHeaders.AUTHORIZATION, "Bearer " + DISABLED_TOKEN))
				.andExpect(status().isUnauthorized());

		// Opt-out check for require-auth-for-read=false
		properties.getSecurity().setRequireAuthForRead(false);
		mockMvc.perform(get("/api/v1/fleet"))
				.andExpect(status().isOk());
		properties.getSecurity().setRequireAuthForRead(true);

		// Web-UI /login sets _adc_session cookie and unlocks Web-UI + API read; /logout clears it
		MvcResult loginResult = mockMvc.perform(post("/login").param("token", OPERATOR_TOKEN))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/"))
				.andReturn();
		Cookie sessionCookie = loginResult.getResponse().getCookie(CollectorSecurityService.SESSION_COOKIE_NAME);
		assertNotNull(sessionCookie);

		mockMvc.perform(get("/").cookie(sessionCookie))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("soc-operator")));

		MvcResult logoutResult = mockMvc.perform(post("/logout").cookie(sessionCookie))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/login?loggedOut=true"))
				.andReturn();
		Cookie clearedCookie = logoutResult.getResponse().getCookie(CollectorSecurityService.SESSION_COOKIE_NAME);
		assertNotNull(clearedCookie);
		assertEquals(0, clearedCookie.getMaxAge());

		// Brute-force lockout after max-auth-failures=3 from the same remote IP
		for (int i = 0; i < 2; i++) {
			mockMvc.perform(post("/login")
					.param("token", "wrong-token-" + i)
					.with(req -> {
						req.setRemoteAddr("198.51.100.77");
						return req;
					}))
					.andExpect(status().isUnauthorized());
		}
		// 3rd failure hits maxAuthFailures=3 -> locks out with 429
		mockMvc.perform(post("/login")
				.param("token", "wrong-token-final")
				.with(req -> {
					req.setRemoteAddr("198.51.100.77");
					return req;
				}))
				.andExpect(status().isTooManyRequests());

		// Even a valid token from the locked-out IP gets 429 until lockout expires/cleared
		mockMvc.perform(get("/api/v1/fleet")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + ADMIN_TOKEN)
				.with(req -> {
					req.setRemoteAddr("198.51.100.77");
					return req;
				}))
				.andExpect(status().isTooManyRequests())
				.andExpect(jsonPath("$.status").value("TOO_MANY_REQUESTS"));
	}

	@Test
	void testRoleModeIntersectionAndStage2OperationalApi() throws Exception {
		// VIEWER token cannot modify operational data
		mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + VIEWER_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"198.51.100.0/24\",\"ttlMinutes\":60,\"reason\":\"Viewer attempt\"}"))
				.andExpect(status().isForbidden());

		// OPERATOR token cannot execute system admin maintenance endpoints in FULL mode
		mockMvc.perform(post("/api/v1/rollups/subnets/profiles/refresh")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN))
				.andExpect(status().isForbidden());

		// ADMIN token succeeds on system admin endpoints in FULL mode
		mockMvc.perform(post("/api/v1/rollups/subnets/profiles/refresh")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + ADMIN_TOKEN))
				.andExpect(status().isOk());

		// VIEWER collector mode overrides even an ADMIN token (intersection)
		properties.setMode(CollectorMode.VIEWER);
		mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + ADMIN_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"198.51.100.0/24\",\"ttlMinutes\":60,\"reason\":\"Admin in viewer mode\"}"))
				.andExpect(status().isForbidden());
		properties.setMode(CollectorMode.FULL);

		// Stage 2: OPERATOR notes CRUD via JSON API
		MvcResult noteCreateRes = mockMvc.perform(post("/api/v1/notes")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"targetType\":\"SUBNET\",\"targetKey\":\"198.51.100.0/24\",\"verdict\":\"SUSPICIOUS\",\"noteMarkdown\":\"Verified UDP/HTTPS flood cluster\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.actor").value("OPERATOR:soc-operator"))
				.andExpect(jsonPath("$.note.targetKey").value("198.51.100.0/24"))
				.andReturn();
		long noteId = objectMapper.readTree(noteCreateRes.getResponse().getContentAsString())
				.path("note").path("id").asLong();

		mockMvc.perform(get("/api/v1/notes/" + noteId)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + VIEWER_TOKEN))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.note.verdict").value("SUSPICIOUS"));

		// Stage 2: OPERATOR daily report note & read
		jdbcTemplate.update("""
				INSERT INTO daily_reports (report_date, status, total_requests, total_blocked, total_marked,
				    peak_requests_per_sec, peak_blocked_per_sec, peak_marked_per_sec,
				    peak_valve_name, peak_server_id, server_count, incident_count, report_markdown, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				""",
				"2026-10-18", "NORMAL", 1000L, 10L, 0L, 12.5, 1.0, 0.0,
				"Edge-1", "Node-A", 1, 1, "# Daily Report 2026-10-18\n\nSummary",
				Timestamp.from(Instant.now()), Timestamp.from(Instant.now()));

		mockMvc.perform(post("/api/v1/reports/2026-10-18/note")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"noteMarkdown\":\"Confirmed legitimate batch job spike.\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.actor").value("OPERATOR:soc-operator"));

		mockMvc.perform(get("/api/v1/reports/2026-10-18")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + VIEWER_TOKEN))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.report.reportDate").value("2026-10-18"))
				.andExpect(jsonPath("$.operatorNote.noteMarkdown").value("Confirmed legitimate batch job spike."));

		// Stage 2: OPERATOR mitigation lifecycle + critical preflight override flow
		mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"10.20.30.0/24\",\"ttlMinutes\":30,\"reason\":\"Private subnet test without override\"}"))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.status").value("PREFLIGHT_CONFIRMATION_REQUIRED"));

		MvcResult blockRes = mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"198.51.100.0/24\",\"ttlMinutes\":60,\"reason\":\"Manual operator flood mitigation\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.actor").value("OPERATOR:soc-operator"))
				.andExpect(jsonPath("$.rule.source").value("MANUAL"))
				.andReturn();
		long ruleId = objectMapper.readTree(blockRes.getResponse().getContentAsString())
				.path("rule").path("id").asLong();

		mockMvc.perform(post("/api/v1/mitigation/" + ruleId + "/extend")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"additionalMinutes\":30}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.actor").value("OPERATOR:soc-operator"));

		mockMvc.perform(post("/api/v1/mitigation/" + ruleId + "/revoke")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"reason\":\"Mitigation verified complete\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.rule.status").value("REVOKED"));

		// Verify audit trail attributes OPERATOR:<tokenName>
		List<String> actors = jdbcTemplate.queryForList(
				"SELECT actor FROM mitigation_audit_log WHERE rule_id = ?", String.class, ruleId);
		assertEquals(3, actors.size());
		assertTrue(actors.stream().allMatch(a -> a.equals("OPERATOR:soc-operator")));

		// Human delete succeeds
		mockMvc.perform(delete("/api/v1/notes/" + noteId)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN))
				.andExpect(status().isOk());
	}

	@Test
	void testStage3AiAgentGuardrailsOwnershipAndWebUiBypassBlocking() throws Exception {
		// 1. Web-UI mutation bypass attempts by AI_AGENT are strictly rejected (403)
		mockMvc.perform(post("/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.param("cidrInput", "203.0.113.0/24")
				.param("ttlMinutes", "30")
				.param("reason", "Attempt Web UI mitigation bypass"))
				.andExpect(status().isForbidden());

		mockMvc.perform(post("/notes")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.param("targetType", "ASN")
				.param("targetKey", "AS64512")
				.param("verdict", "MALICIOUS")
				.param("noteMarkdown", "Attempt Web UI notes bypass"))
				.andExpect(status().isForbidden());

		mockMvc.perform(post("/reports/2026-10-18/note")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.param("noteMarkdown", "Attempt Web UI report note bypass"))
				.andExpect(status().isForbidden());

		// 2. AI_AGENT guardrail checks on /api/v1/mitigation/block
		mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"203.0.113.0/24\",\"ttlMinutes\":60,\"reason\":\"short\"}"))
				.andExpect(status().isUnprocessableEntity())
				.andExpect(jsonPath("$.status").value("REASON_TOO_SHORT"));

		mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"203.0.113.0/24\",\"ttlMinutes\":300,\"reason\":\"Automated AI analysis detected HTTP flood\"}"))
				.andExpect(status().isUnprocessableEntity())
				.andExpect(jsonPath("$.status").value("TTL_EXCEEDS_AI_LIMIT"));

		mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"203.0.0.0/16\",\"ttlMinutes\":60,\"reason\":\"Automated AI analysis detected broad range\"}"))
				.andExpect(status().isUnprocessableEntity())
				.andExpect(jsonPath("$.status").value("PREFIX_TOO_BROAD"));

		// Collateral damage risk cannot be bypassed by forceOverride=true
		mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"10.20.30.0/24\",\"ttlMinutes\":60,\"forceOverride\":true,\"reason\":\"Trying to force-override private range\"}"))
				.andExpect(status().isUnprocessableEntity())
				.andExpect(jsonPath("$.status").value("COLLATERAL_DAMAGE_RISK"));

		// ASN batch blocking disabled for AI_AGENT by default
		mockMvc.perform(post("/api/v1/mitigation/asn-block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"asn\":64512,\"hours\":24,\"ttlMinutes\":60,\"reason\":\"Automated ASN carpet-bomb block\"}"))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.status").value("AI_ASN_BATCH_DISABLED"));

		// Valid AI block succeeds with source=AI_AGENT and actor=AI_AGENT:triage-bot
		MvcResult aiBlockRes = mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"203.0.113.0/24\",\"ttlMinutes\":60,\"reason\":\"Spike of 500k 429 hits with 0 authenticated users\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.actor").value("AI_AGENT:triage-bot"))
				.andExpect(jsonPath("$.rule.source").value("AI_AGENT"))
				.andReturn();
		long aiRuleId = objectMapper.readTree(aiBlockRes.getResponse().getContentAsString())
				.path("rule").path("id").asLong();

		// Human creates a MANUAL rule; AI_AGENT must NOT extend or revoke it
		MvcResult manualRes = mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"192.0.2.0/24\",\"ttlMinutes\":60,\"reason\":\"Human manual rule\"}"))
				.andExpect(status().isOk())
				.andReturn();
		long manualRuleId = objectMapper.readTree(manualRes.getResponse().getContentAsString())
				.path("rule").path("id").asLong();

		mockMvc.perform(post("/api/v1/mitigation/" + manualRuleId + "/extend")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"additionalMinutes\":30}"))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.status").value("OWNERSHIP_VIOLATION"));

		mockMvc.perform(post("/api/v1/mitigation/" + manualRuleId + "/revoke")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"reason\":\"AI trying to revoke human rule\"}"))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.status").value("OWNERSHIP_VIOLATION"));

		// AI cannot extend its own rule beyond maxTtlMinutes (currently ~60m left + 90m = 150m > 120m)
		mockMvc.perform(post("/api/v1/mitigation/" + aiRuleId + "/extend")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"additionalMinutes\":90}"))
				.andExpect(status().isUnprocessableEntity())
				.andExpect(jsonPath("$.status").value("TTL_EXCEEDS_AI_LIMIT"));

		// AI can extend within maxTtlMinutes and revoke its own AI rule
		mockMvc.perform(post("/api/v1/mitigation/" + aiRuleId + "/extend")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"additionalMinutes\":30}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.actor").value("AI_AGENT:triage-bot"));

		// Rate limiting check (set ceiling to 2; we already have 2 AI CREATE+EXTEND actions in last hour)
		properties.getSecurity().getAiGuardrails().setMaxBlocksPerHour(2);
		mockMvc.perform(post("/api/v1/mitigation/block")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"cidr\":\"203.0.114.0/24\",\"ttlMinutes\":30,\"reason\":\"Quota test block against hourly AI ceiling\"}"))
				.andExpect(status().isTooManyRequests())
				.andExpect(jsonPath("$.status").value("AI_RATE_LIMIT_EXCEEDED"));
		properties.getSecurity().getAiGuardrails().setMaxBlocksPerHour(20);

		mockMvc.perform(post("/api/v1/mitigation/" + aiRuleId + "/revoke")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"reason\":\"Attack subsided according to latest telemetry\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.rule.status").value("REVOKED"));

		// 3. Human note protection & AI append-only semantics
		MvcResult humanNoteRes = mockMvc.perform(post("/api/v1/notes")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"targetType\":\"SUBNET\",\"targetKey\":\"203.0.113.0/24\",\"verdict\":\"LEGITIMATE\",\"noteMarkdown\":\"Partner webhook egress range\"}"))
				.andExpect(status().isOk())
				.andReturn();
		long humanNoteId = objectMapper.readTree(humanNoteRes.getResponse().getContentAsString())
				.path("note").path("id").asLong();

		// Overwrite attempt (even targeting a single IP inside /24) must fail with 409 HUMAN_NOTE_PROTECTED
		mockMvc.perform(post("/api/v1/notes")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"targetType\":\"SUBNET\",\"targetKey\":\"203.0.113.42\",\"verdict\":\"MALICIOUS\",\"noteMarkdown\":\"Trying to overwrite human partner note\"}"))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.status").value("HUMAN_NOTE_PROTECTED"));

		// Append=true preserves human content and verdict while adding attributed AI addendum
		MvcResult appendedRes = mockMvc.perform(post("/api/v1/notes")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"targetType\":\"SUBNET\",\"targetKey\":\"203.0.113.0/24\",\"verdict\":\"MALICIOUS\",\"append\":true,\"noteMarkdown\":\"Observed temporary burst from partner worker #3\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.note.verdict").value("LEGITIMATE"))
				.andReturn();
		String mergedMarkdown = objectMapper.readTree(appendedRes.getResponse().getContentAsString())
				.path("note").path("noteMarkdown").asText();
		assertTrue(mergedMarkdown.contains("Partner webhook egress range"));
		assertTrue(mergedMarkdown.contains("[AI_AGENT: triage-bot"));
		assertTrue(mergedMarkdown.contains("Observed temporary burst from partner worker #3"));

		// AI_AGENT cannot delete annotations or daily report notes
		mockMvc.perform(delete("/api/v1/notes/" + humanNoteId)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.status").value("AI_DELETE_FORBIDDEN"));

		// AI_AGENT appends cleanly to an existing human report note rather than overwriting
		mockMvc.perform(post("/api/v1/reports/2026-10-18/note")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + OPERATOR_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"noteMarkdown\":\"Human analyst initial triage.\"}"))
				.andExpect(status().isOk());

		MvcResult aiReportNoteRes = mockMvc.perform(post("/api/v1/reports/2026-10-18/note")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"noteMarkdown\":\"AI follow-up confirms packet signature matches botnet X.\"}"))
				.andExpect(status().isOk())
				.andReturn();
		JsonNode reportNoteJson = objectMapper.readTree(aiReportNoteRes.getResponse().getContentAsString());
		String reportMd = reportNoteJson.path("operatorNote").path("noteMarkdown").asText();
		assertTrue(reportMd.contains("Human analyst initial triage."));
		assertTrue(reportMd.contains("[AI_AGENT: triage-bot"));

		mockMvc.perform(delete("/api/v1/reports/2026-10-18/note")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + AI_TOKEN))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.status").value("AI_DELETE_FORBIDDEN"));
	}
}
