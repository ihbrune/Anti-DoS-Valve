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
}
