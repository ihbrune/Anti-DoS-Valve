package org.henbru.antidos.collector.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.henbru.antidos.collector.config.CollectorMode;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.config.CollectorTokenRole;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Enforces multi-token API authentication, fail-closed write protection, optional read protection,
 * browser session cookies, and brute-force lockout protection across all Collector endpoints.
 */
@Component
@ConditionalOnWebApplication
public class CollectorSecurityInterceptor implements HandlerInterceptor {

	public static final String TOKEN_HEADER = "X-AntiDoS-Token";

	private final CollectorProperties properties;
	private final CollectorSecurityService securityService;
	private final ObjectMapper objectMapper;

	public CollectorSecurityInterceptor(
			CollectorProperties properties,
			CollectorSecurityService securityService,
			ObjectMapper objectMapper) {
		this.properties = properties;
		this.securityService = securityService;
		this.objectMapper = objectMapper;
	}

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
		CollectorAuthContext.clear();

		String uri = request.getRequestURI();
		if (isPublicAssetOrAuthPath(uri)) {
			return true;
		}

		String clientIp = request.getRemoteAddr();
		if (securityService.isIpLockedOut(clientIp)) {
			writeJsonError(response, HttpStatus.TOO_MANY_REQUESTS,
					"TOO_MANY_REQUESTS",
					"Too many failed authentication attempts. Please try again later.");
			return false;
		}

		boolean isApiRequest = isApiPath(uri);
		String providedToken = extractToken(request, isApiRequest);
		boolean hasTokensConfigured = securityService.hasConfiguredTokens();

		if (providedToken != null) {
			Optional<CollectorAuthContext.AuthPrincipal> tokenPrincipal = securityService.authenticateToken(providedToken);
			if (tokenPrincipal.isEmpty()) {
				boolean lockedNow = securityService.recordAuthFailure(clientIp);
				if (lockedNow) {
					writeJsonError(response, HttpStatus.TOO_MANY_REQUESTS,
							"TOO_MANY_REQUESTS",
							"Too many failed authentication attempts. IP temporarily locked out.");
				} else {
					writeJsonError(response, HttpStatus.UNAUTHORIZED,
							"UNAUTHORIZED",
							"Invalid authentication token.");
				}
				return false;
			}
			securityService.clearAuthFailures(clientIp);
			CollectorAuthContext.set(tokenPrincipal.get());
		} else {
			String cookieVal = extractCookie(request, CollectorSecurityService.SESSION_COOKIE_NAME);
			if (cookieVal != null) {
				Optional<CollectorAuthContext.AuthPrincipal> cookiePrincipal =
						securityService.authenticateSessionCookie(cookieVal);
				cookiePrincipal.ifPresent(CollectorAuthContext::set);
			}
		}

		CollectorAuthContext.AuthPrincipal principal = CollectorAuthContext.get();

		if (isApiRequest) {
			return authorizeApiRequest(request, response, uri, clientIp, hasTokensConfigured, principal);
		}
		return authorizeWebRequest(request, response, clientIp, hasTokensConfigured, principal);
	}

	@Override
	public void afterCompletion(
			HttpServletRequest request,
			HttpServletResponse response,
			Object handler,
			Exception ex) {
		CollectorAuthContext.clear();
	}

	private boolean authorizeApiRequest(
			HttpServletRequest request,
			HttpServletResponse response,
			String uri,
			String clientIp,
			boolean hasTokensConfigured,
			CollectorAuthContext.AuthPrincipal principal) throws IOException {

		if (!properties.getSecurity().isApiEnabled()
				&& (principal == null || !principal.authenticatedViaSession())) {
			writeJsonError(response, HttpStatus.FORBIDDEN,
					"FORBIDDEN",
					"Collector REST API is disabled via configuration.");
			return false;
		}

		String method = request.getMethod();
		boolean isMutatingMethod = !"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method);

		if (isMutatingMethod && isOperationalApiPath(uri)) {
			if (!hasTokensConfigured) {
				writeJsonError(response, HttpStatus.UNAUTHORIZED,
						"UNAUTHORIZED",
						"Active API write endpoints require configured collector.security.tokens (fail-closed by default).");
				return false;
			}
			if (principal == null) {
				writeJsonError(response, HttpStatus.UNAUTHORIZED,
						"UNAUTHORIZED",
						"Authentication token or active login session required.");
				return false;
			}
			if (!properties.canModifyOperationalData()) {
				writeJsonError(response, HttpStatus.FORBIDDEN,
						"FORBIDDEN",
						"Active role/mode (" + properties.getEffectiveMode() + ") does not permit operational writes.");
				return false;
			}
			return true;
		}

		if (isMutatingMethod) {
			if (principal == null && (hasTokensConfigured || !CollectorSecurityService.isLoopbackAddress(clientIp))) {
				writeJsonError(response, HttpStatus.UNAUTHORIZED,
						"UNAUTHORIZED",
						"Authentication token or active login session required.");
				return false;
			}
			return true;
		}

		// Read-only /api/v1/** GET requests
		if (properties.getSecurity().isRequireAuthForRead() && principal == null) {
			if (hasTokensConfigured
					|| (!CollectorSecurityService.isLoopbackAddress(clientIp) && !properties.isDemoMode())) {
				writeJsonError(response, HttpStatus.UNAUTHORIZED,
						"UNAUTHORIZED",
						"Authentication required to access Collector read API (collector.security.require-auth-for-read=true).");
				return false;
			}
		}
		return true;
	}

	private boolean authorizeWebRequest(
			HttpServletRequest request,
			HttpServletResponse response,
			String clientIp,
			boolean hasTokensConfigured,
			CollectorAuthContext.AuthPrincipal principal) throws IOException {

		if (hasTokensConfigured && principal == null) {
			if ("true".equalsIgnoreCase(request.getHeader("HX-Request"))) {
				response.setStatus(HttpStatus.UNAUTHORIZED.value());
				response.setHeader("HX-Redirect", "/login");
			} else {
				response.sendRedirect("/login");
			}
			return false;
		}

		String method = request.getMethod();
		boolean isMutatingMethod = !"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method);
		if (isMutatingMethod && principal != null && principal.role().isAiAgent()) {
			writeJsonError(response, HttpStatus.FORBIDDEN,
					"AI_WEB_MUTATION_FORBIDDEN",
					"AI_AGENT callers must use guarded /api/v1/** endpoints instead of Web-UI mutation routes.");
			return false;
		}

		// On local machines without configured tokens, auto-issue a loopback session cookie on HTML page loads
		if (!hasTokensConfigured
				&& principal == null
				&& CollectorSecurityService.isLoopbackAddress(clientIp)
				&& "GET".equalsIgnoreCase(request.getMethod())) {
			CollectorTokenRole defaultLocalRole = properties.getMode() == CollectorMode.VIEWER
					? CollectorTokenRole.VIEWER
					: (properties.getMode() == CollectorMode.OPERATOR ? CollectorTokenRole.OPERATOR : CollectorTokenRole.ADMIN);
			String cookieVal = securityService.createSessionCookieValue("local", defaultLocalRole);
			ResponseCookie cookie = ResponseCookie.from(CollectorSecurityService.SESSION_COOKIE_NAME, cookieVal)
					.httpOnly(true)
					.sameSite("Lax")
					.path("/")
					.maxAge(properties.getSecurity().getSessionTtlSeconds())
					.build();
			response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
		}
		return true;
	}

	private static boolean isPublicAssetOrAuthPath(String uri) {
		if (uri == null) {
			return false;
		}
		return uri.startsWith("/css/")
				|| uri.startsWith("/js/")
				|| uri.equals("/favicon.ico")
				|| uri.equals("/login")
				|| uri.equals("/logout")
				|| uri.equals("/error")
				|| uri.startsWith("/mock-valve/");
	}

	private static boolean isApiPath(String uri) {
		return uri != null && (uri.equals("/api/v1") || uri.startsWith("/api/v1/"));
	}

	private static boolean isOperationalApiPath(String uri) {
		return uri.startsWith("/api/v1/notes")
				|| uri.startsWith("/api/v1/reports")
				|| uri.startsWith("/api/v1/mitigation");
	}

	private static String extractToken(HttpServletRequest request, boolean allowQueryParam) {
		String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
			String token = authHeader.substring(7).trim();
			if (!token.isEmpty()) {
				return token;
			}
		}
		String customHeader = request.getHeader(TOKEN_HEADER);
		if (customHeader != null && !customHeader.isBlank()) {
			return customHeader.trim();
		}
		if (allowQueryParam) {
			String param = request.getParameter("token");
			if (param != null && !param.isBlank()) {
				return param.trim();
			}
		}
		return null;
	}

	private static String extractCookie(HttpServletRequest request, String cookieName) {
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			return null;
		}
		for (Cookie c : cookies) {
			if (cookieName.equals(c.getName()) && c.getValue() != null && !c.getValue().isBlank()) {
				return c.getValue();
			}
		}
		return null;
	}

	private void writeJsonError(HttpServletResponse response, HttpStatus status, String code, String message)
			throws IOException {
		response.setStatus(status.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding("UTF-8");
		Map<String, Object> body = new LinkedHashMap<>();
		body.put("status", code);
		body.put("message", message);
		objectMapper.writeValue(response.getWriter(), body);
	}
}
