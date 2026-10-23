package org.henbru.antidos.collector.config;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.mock.env.MockEnvironment;

class DatabaseDirectoryInitializerTest {

	@Test
	void testCreatesParentDirectoryWhenMissing(@TempDir Path tempDir) {
		Path nestedDb = tempDir.resolve("subfolder/data/test.db");
		MockEnvironment env = new MockEnvironment();
		env.setProperty("spring.datasource.url", "jdbc:sqlite:" + nestedDb.toString());

		ConfigurableListableBeanFactory beanFactory = mock(ConfigurableListableBeanFactory.class);
		when(beanFactory.getBean(org.springframework.core.env.Environment.class)).thenReturn(env);

		DatabaseDirectoryInitializer initializer = new DatabaseDirectoryInitializer();
		initializer.postProcessBeanFactory(beanFactory);

		assertTrue(Files.exists(nestedDb.getParent()), "Parent directories must be created");
	}

	@Test
	void testSqliteHikariCustomizerConfiguresPragmas(@TempDir Path tempDir) throws Exception {
		Path dbPath = tempDir.resolve("pragma-test.db");
		com.zaxxer.hikari.HikariDataSource ds = new com.zaxxer.hikari.HikariDataSource();
		// URL without busy_timeout - customizer should automatically append busy_timeout=10000
		ds.setJdbcUrl("jdbc:sqlite:" + dbPath.toString());

		org.springframework.beans.factory.config.BeanPostProcessor bpp = DatabaseDirectoryInitializer.sqliteHikariCustomizer();
		bpp.postProcessBeforeInitialization(ds, "dataSource");

		try (java.sql.Connection conn = ds.getConnection();
		     java.sql.Statement stmt = conn.createStatement()) {
			java.sql.ResultSet rs1 = stmt.executeQuery("PRAGMA journal_mode;");
			assertTrue(rs1.next());
			org.junit.jupiter.api.Assertions.assertEquals("wal", rs1.getString(1).toLowerCase());

			java.sql.ResultSet rs2 = stmt.executeQuery("PRAGMA busy_timeout;");
			assertTrue(rs2.next());
			org.junit.jupiter.api.Assertions.assertEquals(10000, rs2.getInt(1));
		} finally {
			ds.close();
		}
	}
}
