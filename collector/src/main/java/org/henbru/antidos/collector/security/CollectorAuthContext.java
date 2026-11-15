package org.henbru.antidos.collector.security;

import org.henbru.antidos.collector.config.CollectorTokenRole;

/**
 * Request-scoped holder tracking the authenticated token or browser session principal.
 * Cleared in {@link CollectorSecurityInterceptor#afterCompletion} after every request.
 */
public final class CollectorAuthContext {

	public record AuthPrincipal(
			String name,
			CollectorTokenRole role,
			boolean authenticatedViaToken,
			boolean authenticatedViaSession
	) {
		public String auditActor() {
			if (role == null) {
				return (name != null && !name.isBlank()) ? name : "ANONYMOUS";
			}
			String safeName = (name != null && !name.isBlank()) ? name.trim() : "default";
			return role.name() + ":" + safeName;
		}
	}

	private static final ThreadLocal<AuthPrincipal> CURRENT = new ThreadLocal<>();

	private CollectorAuthContext() {
	}

	public static void set(AuthPrincipal principal) {
		if (principal == null) {
			CURRENT.remove();
		} else {
			CURRENT.set(principal);
		}
	}

	public static AuthPrincipal get() {
		return CURRENT.get();
	}

	public static void clear() {
		CURRENT.remove();
	}

	public static String getEffectiveActor(String fallback) {
		AuthPrincipal principal = CURRENT.get();
		if (principal != null) {
			return principal.auditActor();
		}
		return (fallback != null && !fallback.isBlank()) ? fallback : "ADMIN";
	}

	public static boolean isAiAgent() {
		AuthPrincipal principal = CURRENT.get();
		return principal != null && principal.role() != null && principal.role().isAiAgent();
	}
}
