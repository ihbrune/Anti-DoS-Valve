package org.henbru.antidos.collector.config;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.lang.NonNull;

/**
 * Ensures that parent directories for file-based databases (such as SQLite)
 * exist before the DataSource and Flyway attempt to connect.
 */
@Configuration
public class DatabaseDirectoryInitializer implements BeanFactoryPostProcessor {

	private static final Logger log = LoggerFactory.getLogger(DatabaseDirectoryInitializer.class);
	private static final String SQLITE_PREFIX = "jdbc:sqlite:";

	@Override
	public void postProcessBeanFactory(@NonNull ConfigurableListableBeanFactory beanFactory) throws BeansException {
		Environment env = beanFactory.getBean(Environment.class);
		String url = env.getProperty("spring.datasource.url");
		if (url != null && url.startsWith(SQLITE_PREFIX)) {
			ensureDirectoryExists(url);
		}
	}

	private void ensureDirectoryExists(String url) {
		String rawPath = url.substring(SQLITE_PREFIX.length()).trim();
		int queryIdx = rawPath.indexOf('?');
		if (queryIdx >= 0) {
			rawPath = rawPath.substring(0, queryIdx).trim();
		}

		if (rawPath.isEmpty() || ":memory:".equalsIgnoreCase(rawPath)) {
			return;
		}

		try {
			Path dbPath = Paths.get(rawPath);
			Path parent = dbPath.getParent();
			if (parent != null && !Files.exists(parent)) {
				Files.createDirectories(parent);
				log.info("Created missing database directory: {}", parent.toAbsolutePath());
			}
		} catch (java.io.IOException | java.nio.file.InvalidPathException e) {
			log.warn("Could not inspect or create directory for SQLite database URL '{}': {}", url, e.getMessage());
		}
	}

	@org.springframework.context.annotation.Bean
	public static org.springframework.beans.factory.config.BeanPostProcessor sqliteHikariCustomizer() {
		return new org.springframework.beans.factory.config.BeanPostProcessor() {
			@Override
			public Object postProcessBeforeInitialization(@NonNull Object bean, @NonNull String beanName) throws BeansException {
				if (bean instanceof com.zaxxer.hikari.HikariDataSource hikari) {
					String url = hikari.getJdbcUrl();
					if (url != null && url.startsWith(SQLITE_PREFIX)) {
						hikari.setConnectionInitSql("PRAGMA journal_mode=WAL;");
						String updatedUrl = url;
						if (!updatedUrl.contains("busy_timeout")) {
							String separator = updatedUrl.contains("?") ? "&" : "?";
							updatedUrl = updatedUrl + separator + "busy_timeout=60000";
						} else if (updatedUrl.contains("busy_timeout=10000")) {
							updatedUrl = updatedUrl.replace("busy_timeout=10000", "busy_timeout=60000");
						}
						if (!updatedUrl.contains("synchronous")) {
							String separator = updatedUrl.contains("?") ? "&" : "?";
							updatedUrl = updatedUrl + separator + "synchronous=NORMAL";
						}
						hikari.setJdbcUrl(updatedUrl);
						log.info("Configured SQLite WAL mode, synchronous=NORMAL, and busy_timeout=60000 on HikariDataSource");
					}
				}
				return bean;
			}
		};
	}

	@org.springframework.context.annotation.Bean
	public org.springframework.boot.autoconfigure.flyway.FlywayConfigurationCustomizer flywayVendorCustomizer(
			@org.springframework.beans.factory.annotation.Value("${spring.datasource.url:}") String url) {
		return configuration -> {
			if (url != null && url.startsWith("jdbc:postgresql")) {
				configuration.locations("classpath:db/migration/postgresql");
			} else {
				configuration.locations("classpath:db/migration/sqlite");
			}
		};
	}
}
