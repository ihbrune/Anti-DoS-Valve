package org.henbru.antidos;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

/**
 * Concurrency tests to ensure thread-safety under heavy multi-threaded access.
 */
class AntiDoSConcurrencyTest {

	@Test
	void testConcurrentRequestsAndStatusCalls() throws InterruptedException, ExecutionException {
		AntiDoSValve valve = new AntiDoSValve();
		valve.setMonitorName("CONCURRENCY_TEST");
		valve.setMaxIPCacheSize(200);
		valve.setNumberOfSlots(5);
		valve.setSlotLength(1);
		valve.setAllowedRequestsPerSlot(50);
		valve.setShareOfRetainedFormerRequests("0.5");
		valve.setRelevantPaths("/api/.*");
		valve.reloadMonitor();

		int threadCount = 16;
		int iterationsPerThread = 500;
		ExecutorService executor = Executors.newFixedThreadPool(threadCount);
		CountDownLatch startLatch = new CountDownLatch(1);

		List<Future<Void>> futures = new ArrayList<>();
		AtomicInteger blockedRequests = new AtomicInteger(0);
		AtomicInteger allowedRequests = new AtomicInteger(0);

		for (int t = 0; t < threadCount; t++) {
			final int threadId = t;
			futures.add(executor.submit(() -> {
				startLatch.await(); // ensure all threads start simultaneously

				for (int i = 0; i < iterationsPerThread; i++) {
					// Alternate between shared IPs and thread-local IPs
					String ip = (i % 2 == 0) ? "192.168.1.1" : "10.0.0." + (threadId % 8);
					boolean allowed = valve.isRequestAllowed(ip, "/api/resource");
					if (allowed) {
						allowedRequests.incrementAndGet();
					} else {
						blockedRequests.incrementAndGet();
					}

					// Concurrently query status and toString without throwing ConcurrentModificationException
					if (i % 20 == 0) {
						assertNotNull(valve.getIPAddressStatus(ip));
						assertNotNull(valve.getMonitorStatus());
					}
				}
				return null;
			}));
		}

		// Fire all threads
		startLatch.countDown();

		// Await completion
		for (Future<Void> future : futures) {
			future.get();
		}

		executor.shutdown();
		assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

		int totalExpected = threadCount * iterationsPerThread;
		assertEquals(totalExpected, allowedRequests.get() + blockedRequests.get());
		assertTrue(blockedRequests.get() > 0, "Rate limit should have blocked requests for heavily accessed IP");
	}

	@Test
	void testConcurrentSlotRollovers() throws InterruptedException, ExecutionException {
		// Mock monitor with dynamic time for controlled fast slot rollover
		class DynamicTimeMonitor extends AntiDoSMonitor {
			private final AtomicInteger timeOffsetSeconds = new AtomicInteger(0);

			DynamicTimeMonitor() {
				super("CONCURRENT_SLOTS", 50, 4, 1, 10, 0.5f);
			}

			void advanceSeconds(int seconds) {
				timeOffsetSeconds.addAndGet(seconds);
			}

			@Override
			protected long getTimeInMillis() {
				return 1000000L + timeOffsetSeconds.get() * 1000L;
			}
		}

		DynamicTimeMonitor monitor = new DynamicTimeMonitor();
		int threadCount = 12;
		int operationsPerThread = 400;
		ExecutorService executor = Executors.newFixedThreadPool(threadCount);
		CountDownLatch startLatch = new CountDownLatch(1);

		List<Future<Void>> futures = new ArrayList<>();

		for (int t = 0; t < threadCount; t++) {
			final int threadId = t;
			futures.add(executor.submit(() -> {
				startLatch.await();
				for (int i = 0; i < operationsPerThread; i++) {
					if (threadId == 0 && i % 50 == 0) {
						// Thread 0 periodically rolls slots forward
						monitor.advanceSeconds(1);
					}

					String ip = "172.16.0." + (i % 25);
					monitor.registerAndCheckRequest(ip);

					if (i % 25 == 0) {
						assertNotNull(monitor.toString());
					}
				}
				return null;
			}));
		}

		startLatch.countDown();

		for (Future<Void> future : futures) {
			future.get();
		}

		executor.shutdown();
		assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
		assertEquals(threadCount * operationsPerThread, monitor.getTotalrequests());
	}
}
