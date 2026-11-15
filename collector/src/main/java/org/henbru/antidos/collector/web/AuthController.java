package org.henbru.antidos.collector.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import org.henbru.antidos.collector.config.CollectorProperties;
import org.henbru.antidos.collector.security.CollectorAuthContext;
import org.henbru.antidos.collector.security.CollectorSecurityService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Web controller handling token-based browser login and session cookie management (/login, /logout).
 */
@Controller
@ConditionalOnWebApplication
public class AuthController {

	private final CollectorProperties properties;
	private final CollectorSecurityService securityService;

	public AuthController(CollectorProperties properties, CollectorSecurityService securityService) {
		this.properties = properties;
		this.securityService = securityService;
	}

	@GetMapping("/login")
	public String loginPage(
			@RequestParam(value = "loggedOut", required = false) String loggedOut,
			Model model) {
		model.addAttribute("authConfigured", securityService.hasConfiguredTokens());
		model.addAttribute("collectorMode", properties.getMode().name());
		if ("true".equalsIgnoreCase(loggedOut)) {
			model.addAttribute("logoutMessage", "You have been signed out.");
		}
		return "login";
	}

	@PostMapping("/login")
	public String submitLogin(
			@RequestParam(value = "token", required = false) String token,
			HttpServletRequest request,
			HttpServletResponse response,
			Model model) {
		model.addAttribute("authConfigured", securityService.hasConfiguredTokens());
		model.addAttribute("collectorMode", properties.getMode().name());

		String clientIp = request.getRemoteAddr();
		if (securityService.isIpLockedOut(clientIp)) {
			response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
			model.addAttribute("errorMessage",
					"Too many failed authentication attempts. Your IP address is temporarily locked out.");
			return "login";
		}

		if (!securityService.hasConfiguredTokens()) {
			model.addAttribute("errorMessage",
					"No authentication tokens are configured in collector.security.tokens.");
			return "login";
		}

		Optional<CollectorAuthContext.AuthPrincipal> matched = securityService.authenticateToken(token);
		if (matched.isEmpty()) {
			boolean lockedNow = securityService.recordAuthFailure(clientIp);
			response.setStatus(lockedNow ? HttpStatus.TOO_MANY_REQUESTS.value() : HttpStatus.UNAUTHORIZED.value());
			model.addAttribute("errorMessage", lockedNow
					? "Too many failed authentication attempts. Your IP address has been temporarily locked out."
					: "Invalid authentication token.");
			return "login";
		}

		securityService.clearAuthFailures(clientIp);
		CollectorAuthContext.AuthPrincipal principal = matched.get();
		String cookieValue = securityService.createSessionCookieValue(principal.name(), principal.role());
		ResponseCookie cookie = ResponseCookie.from(CollectorSecurityService.SESSION_COOKIE_NAME, cookieValue)
				.httpOnly(true)
				.sameSite("Lax")
				.secure(request.isSecure())
				.path("/")
				.maxAge(properties.getSecurity().getSessionTtlSeconds())
				.build();
		response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
		return "redirect:/";
	}

	@PostMapping("/logout")
	public String logoutPost(HttpServletRequest request, HttpServletResponse response) {
		return clearSessionAndRedirect(request, response);
	}

	@GetMapping("/logout")
	public String logoutGet(HttpServletRequest request, HttpServletResponse response) {
		return clearSessionAndRedirect(request, response);
	}

	private String clearSessionAndRedirect(HttpServletRequest request, HttpServletResponse response) {
		ResponseCookie cleared = ResponseCookie.from(CollectorSecurityService.SESSION_COOKIE_NAME, "")
				.httpOnly(true)
				.sameSite("Lax")
				.secure(request.isSecure())
				.path("/")
				.maxAge(0)
				.build();
		response.addHeader(HttpHeaders.SET_COOKIE, cleared.toString());
		return securityService.hasConfiguredTokens() ? "redirect:/login?loggedOut=true" : "redirect:/";
	}
}
