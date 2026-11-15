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
		CollectorMode mode = CollectorMode.fromString(env.getProperty("collector.mode", "FULL"));
		String url = env.getProperty("spring.datasource.url");
		if (url != null && url.startsWith(SQLITE_PREFIX)) {
			if (mode.isViewer() || mode.isOperator()) {
				verifyExistingDatabaseFile(url, mode);
			} else {
				ensureDirectoryExists(url);
			}
		}
	}

	private void verifyExistingDatabaseFile(String url, CollectorMode mode) {
		Path dbPath = resolveSqlitePath(url);
		if (dbPath == null) {
			return;
		}
		if (!Files.exists(dbPath)) {
			throw new IllegalStateException(
					mode + " mode requires an existing SQLite database file, but none was found at: "
							+ dbPath.toAbsolutePath());
		}
		log.info("Verified existing SQLite database for {} mode: {}", mode, dbPath.toAbsolutePath());
	}

	private Path resolveSqlitePath(String url) {
		String rawPath = url.substring(SQLITE_PREFIX.length()).trim();
		int queryIdx = rawPath.indexOf('?');
		if (queryIdx >= 0) {
			rawPath = rawPath.substring(0, queryIdx).trim();
		}
		if (rawPath.startsWith("file:")) {
			rawPath = rawPath.substring("file:".length()).trim();
		}
		if (rawPath.isEmpty() || ":memory:".equalsIgnoreCase(rawPath) || url.contains("mode=memory")) {
			return null;
		}
		try {
			return Paths.get(rawPath);
		} catch (java.nio.file.InvalidPathException e) {
			log.warn("Could not parse SQLite database path from URL '{}': {}", url, e.getMessage());
			return null;
		}
	}

	private void ensureDirectoryExists(String url) {
		Path dbPath = resolveSqlitePath(url);
		if (dbPath == null) {
			return;
		}

		try {
			Path parent = dbPath.getParent();
			if (parent != null && !Files.exists(parent)) {
				Files.createDirectories(parent);
				log.info("Created missing database directory: {}", parent.toAbsolutePath());
			}
		} catch (java.io.IOException e) {
			log.warn("Could not inspect or create directory for SQLite database URL '{}': {}", url, e.getMessage());
		}
	}

	public static org.springframework.beans.factory.config.BeanPostProcessor sqliteHikariCustomizer() {
		return sqliteHikariCustomizer(null);
	}

	@org.springframework.context.annotation.Bean
	public static org.springframework.beans.factory.config.BeanPostProcessor sqliteHikariCustomizer(
			Environment env) {
		boolean viewerMode = env != null
				&& CollectorMode.fromString(env.getProperty("collector.mode", "FULL")).isViewer();
		return new org.springframework.beans.factory.config.BeanPostProcessor() {
			@Override
			public Object postProcessBeforeInitialization(@NonNull Object bean, @NonNull String beanName) throws BeansException {
				if (bean instanceof com.zaxxer.hikari.HikariDataSource hikari) {
					String url = hikari.getJdbcUrl();
					if (url != null && url.startsWith(SQLITE_PREFIX)) {
						String updatedUrl = url;
						if (!updatedUrl.contains("busy_timeout")) {
							String separator = updatedUrl.contains("?") ? "&" : "?";
							updatedUrl = updatedUrl + separator + "busy_timeout=60000";
						} else if (updatedUrl.contains("busy_timeout=10000")) {
							updatedUrl = updatedUrl.replace("busy_timeout=10000", "busy_timeout=60000");
						}
						if (viewerMode) {
							hikari.setConnectionInitSql("PRAGMA query_only=ON;");
							hikari.setJdbcUrl(updatedUrl);
							log.info("Configured SQLite read-only PRAGMA query_only=ON and busy_timeout=60000 on HikariDataSource (VIEWER mode)");
						} else {
							hikari.setConnectionInitSql("PRAGMA journal_mode=WAL;");
							if (!updatedUrl.contains("synchronous")) {
								String separator = updatedUrl.contains("?") ? "&" : "?";
								updatedUrl = updatedUrl + separator + "synchronous=NORMAL";
							}
							hikari.setJdbcUrl(updatedUrl);
							log.info("Configured SQLite WAL mode, synchronous=NORMAL, and busy_timeout=60000 on HikariDataSource");
						}
					} else if (viewerMode) {
						hikari.setReadOnly(true);
						log.info("Configured HikariDataSource read-only mode on JDBC datasource (VIEWER mode)");
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
