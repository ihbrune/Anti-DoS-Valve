package org.henbru.antidos.collector.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Registers {@link CollectorSecurityInterceptor} across all Spring MVC endpoints.
 */
@Configuration
@ConditionalOnWebApplication
public class CollectorSecurityWebConfig implements WebMvcConfigurer {

	private final CollectorSecurityInterceptor securityInterceptor;

	public CollectorSecurityWebConfig(CollectorSecurityInterceptor securityInterceptor) {
		this.securityInterceptor = securityInterceptor;
	}

	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(securityInterceptor).addPathPatterns("/**");
	}
}
