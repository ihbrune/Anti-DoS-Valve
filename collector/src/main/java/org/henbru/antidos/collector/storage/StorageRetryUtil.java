package org.henbru.antidos.collector.storage;

import java.sql.SQLException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;

/**
 * Utility executing database write operations with automated retry and backoff
 * when transient SQLite file/table locks (SQLITE_BUSY / error code 5) are encountered.
 */
public final class StorageRetryUtil {

	private static final Logger log = LoggerFactory.getLogger(StorageRetryUtil.class);
	public static final int DEFAULT_MAX_RETRIES = 5;
	public static final long INITIAL_BACKOFF_MS = 100;

	private StorageRetryUtil() {}

	/**
	 * Determines whether a throwable (or any of its nested causes) indicates an SQLite file or table lock.
	 */
	public static boolean isBusyOrLocked(Throwable t) {
		Throwable curr = t;
		while (curr != null) {
			String msg = curr.getMessage();
			if (msg != null) {
				String lower = msg.toLowerCase();
				if (lower.contains("sqlite_busy") || lower.contains("database is locked") || lower.contains("database table is locked")) {
					return true;
				}
			}
			if (curr instanceof SQLException se && se.getErrorCode() == 5) {
				return true;
			}
			curr = curr.getCause();
		}
		return false;
	}

	/**
	 * Executes an action with retry on transient lock conflicts.
	 */
	public static void executeWithRetry(String operationName, Runnable action) {
		executeWithRetry(operationName, () -> {
			action.run();
			return null;
		});
	}

	/**
	 * Executes a supplier with retry on transient lock conflicts.
	 */
	public static <T> T executeWithRetry(String operationName, Supplier<T> action) {
		int attempt = 0;
		while (true) {
			attempt++;
			try {
				return action.get();
			} catch (DataAccessException e) {
				if (isBusyOrLocked(e) && attempt <= DEFAULT_MAX_RETRIES) {
					long backoff = (long) (INITIAL_BACKOFF_MS * Math.pow(1.5, attempt - 1)
							+ ThreadLocalRandom.current().nextInt(50));
					log.warn("Database busy/locked during '{}' (attempt {}/{}); retrying in {}ms: {}",
							operationName, attempt, DEFAULT_MAX_RETRIES, backoff, e.getMessage());
					try {
						sleepBackoff(backoff);
					} catch (InterruptedException ie) {
						Thread.currentThread().interrupt();
						throw e;
					}
				} else {
					throw e;
				}
			}
		}
	}

	private static void sleepBackoff(long backoffMs) throws InterruptedException {
		Thread.sleep(backoffMs);
	}
}
