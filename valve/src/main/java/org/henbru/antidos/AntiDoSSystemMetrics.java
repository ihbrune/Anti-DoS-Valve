package org.henbru.antidos;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.OperatingSystemMXBean;
import java.util.List;
import java.util.Set;
import javax.management.MBeanServer;
import javax.management.ObjectName;

/**
 * Lightweight, zero-runtime-dependency collector for JVM and Tomcat host resource telemetry
 * (CPU load, Heap memory utilization, GC pause times, and Tomcat connector worker threads).
 */
public record AntiDoSSystemMetrics(
		Double processCpuLoad,
		Double systemCpuLoad,
		Double systemLoadAverage,
		Long heapUsedBytes,
		Long heapMaxBytes,
		Double heapUsedPercent,
		Long gcCollectionCount,
		Long gcCollectionTimeMs,
		Integer tomcatBusyThreads,
		Integer tomcatMaxThreads
) {

	public static final long CACHE_TTL_MS = 1000L;

	private record CachedSnapshot(long timestampMs, AntiDoSSystemMetrics metrics) {}

	private static volatile CachedSnapshot cachedSnapshot = null;

	/**
	 * Gathers current system, JVM, and Tomcat container metrics with zero external dependencies
	 * and safe exception isolation, cached briefly to avoid repeated JMX scans across multi-valve polls.
	 */
	public static AntiDoSSystemMetrics collect() {
		long now = System.currentTimeMillis();
		CachedSnapshot snap = cachedSnapshot;
		if (snap != null) {
			long age = now - snap.timestampMs();
			if (age >= 0 && age < CACHE_TTL_MS) {
				return snap.metrics();
			}
		}
		AntiDoSSystemMetrics fresh = collectFresh();
		cachedSnapshot = new CachedSnapshot(now, fresh);
		return fresh;
	}

	/**
	 * Uncached collection of current system, JVM, and Tomcat container metrics.
	 */
	public static AntiDoSSystemMetrics collectFresh() {
		Double processCpu = null;
		Double systemCpu = null;
		Double loadAvg = null;

		try {
			OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
			if (osBean != null) {
				double la = osBean.getSystemLoadAverage();
				if (la >= 0) {
					loadAvg = Math.round(la * 100.0) / 100.0;
				}
				if (osBean instanceof com.sun.management.OperatingSystemMXBean sunOs) {
					double pc = sunOs.getProcessCpuLoad();
					if (pc >= 0) {
						processCpu = Math.round(pc * 10000.0) / 10000.0;
					}
					double sc = sunOs.getCpuLoad();
					if (sc >= 0) {
						systemCpu = Math.round(sc * 10000.0) / 10000.0;
					}
				}
			}
		} catch (Throwable ignored) {
		}

		Long heapUsed = null;
		Long heapMax = null;
		Double heapPct = null;

		try {
			MemoryMXBean memBean = ManagementFactory.getMemoryMXBean();
			if (memBean != null) {
				MemoryUsage heap = memBean.getHeapMemoryUsage();
				if (heap != null) {
					heapUsed = heap.getUsed();
					heapMax = heap.getMax();
					if (heapMax > 0 && heapUsed >= 0) {
						heapPct = Math.round(((double) heapUsed / (double) heapMax * 100.0) * 10.0) / 10.0;
					}
				}
			}
		} catch (Throwable ignored) {
		}

		Long gcCount = null;
		Long gcTimeMs = null;

		try {
			List<GarbageCollectorMXBean> gcBeans = ManagementFactory.getGarbageCollectorMXBeans();
			if (gcBeans != null && !gcBeans.isEmpty()) {
				long totalCount = 0;
				long totalTime = 0;
				boolean any = false;
				for (GarbageCollectorMXBean gc : gcBeans) {
					long c = gc.getCollectionCount();
					long t = gc.getCollectionTime();
					if (c >= 0) {
						totalCount += c;
						any = true;
					}
					if (t >= 0) {
						totalTime += t;
						any = true;
					}
				}
				if (any) {
					gcCount = totalCount;
					gcTimeMs = totalTime;
				}
			}
		} catch (Throwable ignored) {
		}

		Integer busyThreads = null;
		Integer maxThreads = null;

		try {
			MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
			if (mbs != null) {
				Set<ObjectName> names = mbs.queryNames(new ObjectName("*:type=ThreadPool,*"), null);
				if (names != null && !names.isEmpty()) {
					int busySum = 0;
					int maxSum = 0;
					boolean found = false;
					for (ObjectName name : names) {
						try {
							Object busyObj = mbs.getAttribute(name, "currentThreadsBusy");
							Object maxObj = mbs.getAttribute(name, "maxThreads");
							if (busyObj instanceof Number bNum) {
								busySum += bNum.intValue();
								found = true;
							}
							if (maxObj instanceof Number mNum) {
								maxSum += mNum.intValue();
								found = true;
							}
						} catch (Throwable ignored) {
						}
					}
					if (found) {
						busyThreads = busySum;
						maxThreads = maxSum;
					}
				}
			}
		} catch (Throwable ignored) {
		}

		return new AntiDoSSystemMetrics(
				processCpu,
				systemCpu,
				loadAvg,
				heapUsed,
				heapMax,
				heapPct,
				gcCount,
				gcTimeMs,
				busyThreads,
				maxThreads
		);
	}

	/**
	 * Appends formatted JSON fragment for this system metrics block.
	 */
	public void appendJson(StringBuilder sb) {
		sb.append("  \"system\": {\n")
				.append("    \"processCpuLoad\": ").append(processCpuLoad != null ? processCpuLoad : "null").append(",\n")
				.append("    \"systemCpuLoad\": ").append(systemCpuLoad != null ? systemCpuLoad : "null").append(",\n")
				.append("    \"systemLoadAverage\": ").append(systemLoadAverage != null ? systemLoadAverage : "null").append(",\n")
				.append("    \"heapUsedBytes\": ").append(heapUsedBytes != null ? heapUsedBytes : "null").append(",\n")
				.append("    \"heapMaxBytes\": ").append(heapMaxBytes != null ? heapMaxBytes : "null").append(",\n")
				.append("    \"heapUsedPercent\": ").append(heapUsedPercent != null ? heapUsedPercent : "null").append(",\n")
				.append("    \"gcCollectionCount\": ").append(gcCollectionCount != null ? gcCollectionCount : "null").append(",\n")
				.append("    \"gcCollectionTimeMs\": ").append(gcCollectionTimeMs != null ? gcCollectionTimeMs : "null").append(",\n")
				.append("    \"tomcatBusyThreads\": ").append(tomcatBusyThreads != null ? tomcatBusyThreads : "null").append(",\n")
				.append("    \"tomcatMaxThreads\": ").append(tomcatMaxThreads != null ? tomcatMaxThreads : "null").append("\n")
				.append("  }");
	}
}
