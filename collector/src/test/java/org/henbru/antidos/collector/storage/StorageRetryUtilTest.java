package org.henbru.antidos.collector.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.TransientDataAccessResourceException;

class StorageRetryUtilTest {

	@Test
	void testIsBusyOrLockedIdentification() {
		assertTrue(StorageRetryUtil.isBusyOrLocked(new SQLException("[SQLITE_BUSY] The database file is locked", "null", 5)));
		assertTrue(StorageRetryUtil.isBusyOrLocked(new RuntimeException(new SQLException("database is locked"))));
		assertTrue(StorageRetryUtil.isBusyOrLocked(new TransientDataAccessResourceException("database table is locked")));
		assertFalse(StorageRetryUtil.isBusyOrLocked(new SQLException("table client_events not found", "42S02", 1)));
		assertFalse(StorageRetryUtil.isBusyOrLocked(new NullPointerException("NPE")));
	}

	@Test
	void testExecuteWithRetryRecoversAfterLock() {
		AtomicInteger attempts = new AtomicInteger(0);
		String result = StorageRetryUtil.executeWithRetry("test-recovery", () -> {
			if (attempts.incrementAndGet() < 3) {
				throw new TransientDataAccessResourceException("[SQLITE_BUSY] The database file is locked");
			}
			return "success";
		});

		assertEquals(3, attempts.get());
		assertEquals("success", result);
	}

	@Test
	void testExecuteWithRetryDoesNotRetryNonBusyErrors() {
		AtomicInteger attempts = new AtomicInteger(0);
		assertThrows(DataAccessException.class, () -> {
			StorageRetryUtil.executeWithRetry("test-fatal", () -> {
				attempts.incrementAndGet();
				throw new org.springframework.dao.DataIntegrityViolationException("unique constraint violated");
			});
		});

		assertEquals(1, attempts.get());
	}
}
