package org.henbru.antidos;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.regex.Pattern;

import org.apache.catalina.Container;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Pipeline;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.crypto.SecretKey;
import org.henbru.antidos.AntiDoSVisitorTokenService.TokenData;

/**
 * Copyright 2026 Henning Brune
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 * 
 *************************
 *
 * This is an implementation of a Tomcat Valve to accomplish an access rate
 * limitation for individual IP addresses. For this purpose, you can define how
 * many requests per time unit per IP are allowed. Any additional requests are
 * rejected.
 * <p>
 * The valve can be defined by several parameters, see for example these
 * methods:
 * 
 * <ul>
 * <li>{@link #setMonitorName(String)}
 * <li>{@link #setAlwaysAllowedIPs(String)}
 * <li>{@link #setAlwaysForbiddenIPs(String)}
 * <li>{@link #setRelevantPaths(String)}
 * <li>{@link #setNonRelevantPaths(String)}
 * <li>{@link #setServerWideBlocking(boolean)}
 * <li>{@link #setMaxIPCacheSize(int)}
 * <li>{@link #setMaxBlockedIPCacheSize(int)}
 * <li>{@link #setIpv4SubnetMask(int)}
 * <li>{@link #setIpv6SubnetMask(int)}
 * <li>{@link #setNumberOfSlots(int)}
 * <li>{@link #setSlotLength(int)}
 * <li>{@link #setShareOfRetainedFormerRequests(String)}
 * <li>{@link #setSimulationMode(boolean)}
 * <li>{@link #setHttpStatusCode(int)}
 * </ul>
 * 
 * @author Henning
 *
 */
public class AntiDoSValve extends ValveBase {

	private static final Log log = LogFactory.getLog(AntiDoSValve.ANTIDOS_LOGGER_NAME);

	/**
	 * This logger name is used by the valve to log events that are relevant for
	 * normal operation to INFO level.
	 */
	public static final String ANTIDOS_LOGGER_NAME = "org.henbru.antidos.AntiDoS";

	/**
	 * Default HTTP response status code that is set during a rejection due to too many
	 * accesses (RFC 6585 - Too Many Requests).
	 */
	public static final int DEFAULT_HTTP_STATUS_CODE = 429;

	/**
	 * Legacy HTTP response status code used in versions prior to 1.4.1 (403 Forbidden).
	 */
	public static final int LEGACY_HTTP_STATUS_CODE = HttpServletResponse.SC_FORBIDDEN;

	/**
	 * The HTTP response status code that is set during a rejection due to too many
	 * accesses in {@link #DEFAULT_MONITOR_MODE}.
	 * Kept for backward compatibility.
	 */
	public static final int BLOCKING_HTTP_STATUS = DEFAULT_HTTP_STATUS_CODE;

	/**
	 * This name of the request attribute that is set by the valve to mark requests
	 * due to too many accesses in {@link #MARKING_MONITOR_MODE}
	 */
	public static final String MARKING_ATTRIBUTE_NAME = "org.henbru.antidos.AntiDoS";

	/**
	 * Request attribute indicating whether a request carried a valid returning visitor cookie (Boolean).
	 */
	public static final String RETURNING_VISITOR_ATTRIBUTE_NAME = "org.henbru.antidos.RETURNING_VISITOR";

	/**
	 * Request attribute indicating whether a request was a first contact without a valid visitor cookie (Boolean).
	 */
	public static final String FIRST_CONTACT_ATTRIBUTE_NAME = "org.henbru.antidos.FIRST_CONTACT";

	/**
	 * Request attribute containing the visit counter from the validated visitor cookie (Integer).
	 */
	public static final String VISITOR_COUNTER_ATTRIBUTE_NAME = "org.henbru.antidos.VISITOR_COUNTER";

	/**
	 * Request attribute containing the immutable {@link AntiDoSVisitorContext} shared across upstream and downstream valves.
	 */
	public static final String VISITOR_CONTEXT_ATTRIBUTE_NAME = "org.henbru.antidos.VISITOR_CONTEXT";

	/**
	 * Request attribute indicating whether a request carried a valid authenticated login session cookie (Boolean),
	 * shared across upstream and downstream valves in the pipeline.
	 */
	public static final String AUTHENTICATED_ATTRIBUTE_NAME = "org.henbru.antidos.AUTHENTICATED";

	/**
	 * Auth tracking mode constant: disables authentication session tracking (default).
	 */
	public static final String AUTH_TRACKING_MODE_OFF = "OFF";

	/**
	 * Auth tracking mode constant: tracks authenticated sessions via login cookies issued on configured login endpoints.
	 */
	public static final String AUTH_TRACKING_MODE_COOKIE = "COOKIE";

	public AntiDoSValve() {
		super(true);
	}

	/**
	 * Monitor mode constant: This is the default value and sets to mode to
	 * 'blocking'. In this mode requests which exceed the limits of the valve are
	 * answered with {@link #BLOCKING_HTTP_STATUS}
	 */
	public static final String DEFAULT_MONITOR_MODE = "BLOCKING";

	/**
	 * Monitor mode constant: This is the value for setting the mode to 'marking'.
	 * In this mode requests which exceed the limits of the valve are still passed
	 * to the application, but the request object contains an information about this
	 * situation in die attribute named {@link #MARKING_ATTRIBUTE_NAME}
	 */
	public static final String MARKING_MONITOR_MODE = "MARKING";

	private static final String DEFAULT_MONITOR_NAME = "DEFAULT";

	/**
	 * Map of monitor objects for different valve instances
	 */
	private static final Map<String, AntiDoSMonitor> monitors = new ConcurrentHashMap<>();

	/**
	 * Set of all currently active valve instances in the JVM, preserving registration/startup order.
	 */
	private static final Set<AntiDoSValve> activeValves = new CopyOnWriteArraySet<>();

	/**
	 * Global sequence counter for assigning unique, sequential startup/registration indices to valve instances.
	 */
	private static final AtomicInteger registrationSequence = new AtomicInteger(0);

	/**
	 * 1-based sequential index assigned to this valve instance during startup or registration.
	 */
	private volatile int registrationIndex = 0;
	private volatile boolean stopped = false;

	public boolean isStopped() {
		return stopped;
	}

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	private static volatile String generatedStatusToken = null;

	private volatile String statusUri = null;
	private volatile String statusAllowedIPsConfigValue = null;
	private volatile Pattern statusAllowedIPs = null;
	private volatile boolean statusAllowedIPsValid = true;
	private volatile String statusPassword = null;
	private final AntiDoSStatusRenderer statusRenderer = new AntiDoSStatusRenderer(this);

	public AntiDoSStatusRenderer getStatusRenderer() {
		return this.statusRenderer;
	}

	public static final String DEFAULT_COLLECTOR_INTEGRATION = "auto";
	public static final long COLLECTOR_LEASE_MILLIS = 120_000L;

	private volatile int maxIPCacheSize = -1;
	private volatile int maxBlockedIPCacheSize = -1;
	private volatile int ipv4SubnetMask = 32;
	private volatile int ipv6SubnetMask = 128;
	private volatile String collectorIntegration = DEFAULT_COLLECTOR_INTEGRATION;
	private final AtomicLong lastCollectorScrapeTime = new AtomicLong(0);
	private volatile int numberOfSlots = -1;
	private volatile int slotLength = -1;
	private volatile int allowedRequestsPerSlot = -1;
	private volatile float shareOfRetainedFormerRequests = 0;
	private volatile boolean simulationMode = false;
	private volatile boolean serverWideBlocking = false;
	private volatile int httpStatusCode = DEFAULT_HTTP_STATUS_CODE;
	private volatile Boolean asyncEviction = null;
	private volatile int maxBlockLogsPerSecond = AntiDoSLogThrottler.DEFAULT_MAX_LOGS_PER_SECOND;

	private volatile boolean visitorCookieEnabled = false;
	private volatile String visitorCookieName = "_adv";
	private volatile String visitorCookieSecret = null;
	private volatile int visitorCookieTtlSeconds = 900;
	private volatile float visitorCookieRefreshRatio = 0.5f;
	private volatile int visitorCookieSubnetMaskV4 = 24;
	private volatile int visitorCookieSubnetMaskV6 = 64;
	private volatile String visitorCookiePath = "/";
	private volatile String visitorCookieSameSite = "Lax";
	private volatile String visitorCookieSecure = "auto";
	private volatile String visitorCookieDomain = null;
	private volatile AntiDoSVisitorTokenService visitorTokenService = null;

	private static final AntiDoSAuthSessionCache sharedAuthSessionCache = new AntiDoSAuthSessionCache();
	private volatile String authTrackingMode = AUTH_TRACKING_MODE_OFF;
	private volatile String authCookieName = null;
	private volatile Pattern authLoginPaths = null;
	private volatile String authLoginPathsConfigValue = null;
	private volatile boolean authLoginPathsValid = true;
	private volatile int authSessionTtlSeconds = AntiDoSAuthSessionCache.DEFAULT_SESSION_TTL_SECONDS;
	private volatile int maxAuthCacheSize = AntiDoSAuthSessionCache.DEFAULT_MAX_CAPACITY;

	/**
	 * Monitor operation mode. If not set the default mode is used
	 */
	private volatile String monitorMode = DEFAULT_MONITOR_MODE;

	/**
	 * Internal monitor name. If not set a default name is used
	 */
	private volatile String monitorName = DEFAULT_MONITOR_NAME;

	/**
	 * Optional description text for this valve instance, displayed in the monitoring status.
	 */
	private volatile String description = null;

	/**
	 * Monitor name for logging
	 */
	private volatile String name4logging = provideName4logging(DEFAULT_MONITOR_NAME);

	private static String provideName4logging(String monitorName) {
		return "AntiDoSValve [" + monitorName + "]";
	}

	/**
	 * Regular expression with IP addresses that are always blocked
	 */
	private volatile Pattern alwaysForbiddenIPs = null;

	/**
	 * Configuration value for the regular expression with IP addresses that are
	 * always blocked. Probably not a valid {@link Pattern}.
	 */
	private volatile String alwaysForbiddenIPsConfigValue = null;

	/**
	 * Variable for testing for configuration errors. <code>true</code> by default,
	 * is set to <code>false</code> if {@link #setAlwaysForbiddenIPs(String)}
	 * receives an invalid value
	 */
	private volatile boolean alwaysForbiddenIPsValid = true;
	private final LongAdder alwaysForbiddenBlockedRequests = new LongAdder();

	/**
	 * Regular expression with IP addresses that are never blocked
	 */
	private volatile Pattern alwaysAllowedIPs = null;

	/**
	 * Configuration value for the regular expression with IP addresses that are
	 * never blocked. Probably not a valid {@link Pattern}.
	 */
	private volatile String alwaysAllowedIPsConfigValue = null;

	/**
	 * Variable for testing for configuration errors. <code>true</code> by default,
	 * is set to <code>false</code> if {@link #setAlwaysAllowedIPs(String)} receives
	 * an invalid value
	 */
	private volatile boolean alwaysAllowedIPsValid = true;

	/**
	 * Regular expression with the paths for which the valve becomes active
	 */
	private volatile Pattern relevantPaths = null;

	/**
	 * Configuration value for the regular expression with the paths for which the
	 * valve becomes active. Probably not a valid {@link Pattern}.
	 */
	private volatile String relevantPathsConfigValue = null;

	/**
	 * Variable for testing for configuration errors. <code>true</code> by default,
	 * is set to <code>false</code> if {@link #setRelevantPaths(String)} receives an
	 * invalid value
	 */
	private volatile boolean relevantPathsValid = true;

	/**
	 * Regular expression with the paths for which the valve never becomes active
	 */
	private volatile Pattern nonRelevantPaths	= null;

	/**
	 * Configuration value for the regular expression with the paths for which the
	 * valve never becomes active. Probably not a valid {@link Pattern}.
	 */
	private volatile String nonRelevantPathsConfigValue = null;

	/**
	 * Variable for testing for configuration errors. <code>true</code> by default,
	 * is set to <code>false</code> if {@link #setNonRelevantPaths(String)} receives an
	 * invalid value
	 */
	private volatile boolean nonRelevantPathsValid = true;

	/**
	 * The monitor object for the monitorName in this instance. Calls
	 * {@link #reloadMonitor()} to create monitor instance, if necessary
	 * 
	 * @return might be <code>null</code> if configuration is incomplete
	 */
	AntiDoSMonitor provideMonitor() {
		AntiDoSMonitor monitor = monitors.get(monitorName);
		if (monitor != null) {
			return monitor;
		}

		synchronized (monitors) {
			monitor = monitors.get(monitorName);
			if (monitor == null) {
				reloadMonitor();
				monitor = monitors.get(monitorName);
			}
			return monitor;
		}
	}


	/**
	 * Monitor mode used by this valve instance
	 */
	public String getMonitorMode() {
		return monitorMode;
	}

	/**
	 *
	 * @param monitorMode The operation mode of the monitor object used by this
	 *                    valve instance. Might be empty and is then set to default,
	 *                    which is blocking mode. Use {@link #isMonitorModeValid()}
	 *                    to check if the parameter is valid
	 * @see #DEFAULT_MONITOR_MODE
	 * @see #MARKING_MONITOR_MODE
	 */
	public void setMonitorMode(String monitorMode) {
		if (monitorMode == null || monitorMode.length() == 0) {
			this.monitorMode = DEFAULT_MONITOR_MODE;
		} else {
			this.monitorMode = monitorMode.trim().toUpperCase();
		}
	}

	/**
	 * 
	 * @return returns <code>true</code> if monitorMode equals
	 *         {@link #DEFAULT_MONITOR_MODE}
	 * @see #setMonitorMode(String)
	 */
	public boolean isMonitorModeDefault() {
		return DEFAULT_MONITOR_MODE.equals(monitorMode);
	}

	/**
	 * 
	 * @return returns <code>true</code> if monitorMode equals
	 *         {@link #MARKING_MONITOR_MODE}
	 * @see #setMonitorMode(String)
	 */
	public boolean isMonitorModeMarking() {
		return MARKING_MONITOR_MODE.equals(monitorMode);
	}

	/**
	 * @return <code>true</code> is either {@link #isMonitorModeDefault()} or
	 *         {@link #isMonitorModeMarking()} is <code>true</code>
	 */
	public boolean isMonitorModeValid() {
		return isMonitorModeDefault() || isMonitorModeMarking();
	}

	/**
	 * Monitor name used by this valve instance
	 */
	public String getMonitorName() {
		return monitorName;
	}

	/**
	 *
	 * @param monitorName The name of the monitor object used by this valve
	 *                    instance. Might be empty and is then set to a default.
	 */
	public void setMonitorName(String monitorName) {
		if (monitorName == null || monitorName.length() == 0) {
			this.monitorName = DEFAULT_MONITOR_NAME;
		} else {
			this.monitorName = monitorName;
		}
		name4logging = provideName4logging(this.monitorName);
	}

	/**
	 * @return The optional description text for this valve instance, or <code>null</code> if not configured.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Sets an optional description text for this valve instance.
	 *
	 * @param description Description text, or <code>null</code> / empty to clear.
	 */
	public void setDescription(String description) {
		if (description == null || description.trim().isEmpty()) {
			this.description = null;
		} else {
			this.description = description.trim();
		}
	}

	/**
	 * Regular expression with IP addresses that are always blocked
	 */
	public String getAlwaysForbiddenIPsConfigValue() {
		return alwaysForbiddenIPsConfigValue;
	}

	/**
	 * Setting of the regular expression with IP addresses that are always blocked.
	 * Example for blocking all requests from <code>localhost</code>:
	 * <p>
	 * <code>"127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1"</code>
	 *
	 * @param alwaysForbiddenIPs The regular expression. Might be empty. Whether the
	 *                           parameter was valid can be checked via the result
	 *                           of the method {@link #isAlwaysForbiddenIPsValid()}
	 */
	public void setAlwaysForbiddenIPs(String alwaysForbiddenIPs) {
		if (alwaysForbiddenIPs == null || alwaysForbiddenIPs.length() == 0) {
			this.alwaysForbiddenIPs = null;
			alwaysForbiddenIPsConfigValue = null;
			alwaysForbiddenIPsValid = true;
		} else {
			boolean valid = false;
			try {
				alwaysForbiddenIPsConfigValue = alwaysForbiddenIPs;
				this.alwaysForbiddenIPs = Pattern.compile(alwaysForbiddenIPs);
				valid = true;
			} catch (Exception ex) {
			} finally {
				alwaysForbiddenIPsValid = valid;
			}
		}
	}

	/**
	 * @see {@link #setAlwaysForbiddenIPs(String)}
	 */
	public boolean isAlwaysForbiddenIPsValid() {
		return alwaysForbiddenIPsValid;
	}

	/**
	 * @return The total number of requests blocked by alwaysForbiddenIPs during the lifetime of this valve
	 */
	public long getAlwaysForbiddenBlockedRequests() {
		return alwaysForbiddenBlockedRequests.sum();
	}

	/**
	 * Regular expression with IP addresses that are never blocked
	 */
	public String getAlwaysAllowedIPsConfigValue() {
		return alwaysAllowedIPsConfigValue;
	}

	/**
	 * Setting of the regular expression with IP addresses that are never blocked.
	 * Example for allowing all requests from <code>localhost</code>:
	 * <p>
	 * <code>"127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1"</code>
	 *
	 * @param alwaysAllowedIPs The regular expression. Might be empty. Whether the
	 *                         parameter was valid can be checked via the result of
	 *                         the method {@link #isAlwaysAllowedIPsValid()}
	 */
	public void setAlwaysAllowedIPs(String alwaysAllowedIPs) {
		if (alwaysAllowedIPs == null || alwaysAllowedIPs.length() == 0) {
			this.alwaysAllowedIPs = null;
			alwaysAllowedIPsConfigValue = null;
			alwaysAllowedIPsValid = true;
		} else {
			boolean valid = false;
			try {
				alwaysAllowedIPsConfigValue = alwaysAllowedIPs;
				this.alwaysAllowedIPs = Pattern.compile(alwaysAllowedIPs);
				valid = true;
			} catch (Exception ex) {
			} finally {
				alwaysAllowedIPsValid = valid;
			}
		}
	}

	/**
	 * @see #setAlwaysAllowedIPs(String)
	 */
	public boolean isAlwaysAllowedIPsValid() {
		return alwaysAllowedIPsValid;
	}

	/**
	 * 
	 * @return Regular expression with the paths for which the valve becomes active
	 */
	public String getRelevantPathsConfigValue() {
		return relevantPathsConfigValue;
	}

	/**
	 * Setting of the regular expression with the paths for which the valve becomes
	 * active. Example for activating the valve on all requests:
	 * <p>
	 * <code>".*"</code>
	 * 
	 * @param relevantPaths The regular expression. Might be empty. Whether the
	 *                      parameter was valid can be checked via the result of the
	 *                      method {@link #isRelevantPathsValid()}
	 */
	public void setRelevantPaths(String relevantPaths) {
		if (relevantPaths == null || relevantPaths.length() == 0) {
			this.relevantPaths = null;
			relevantPathsConfigValue = null;
			relevantPathsValid = true;
		} else {
			boolean valid = false;
			try {
				relevantPathsConfigValue = relevantPaths;
				this.relevantPaths = Pattern.compile(relevantPaths);
				valid = true;
			} catch (Exception ex) {
			} finally {
				relevantPathsValid = valid;
			}
		}
	}

	/**
	 * @see #setRelevantPaths(String)
	 */
	public boolean isRelevantPathsValid() {
		return relevantPathsValid;
	}
	/**
	 * 
	 * @return Regular expression with the paths for which the valve never becomes active
	 */
	public String getNonRelevantPathsConfigValue() {
		return nonRelevantPathsConfigValue;
	}

	/**
	 * Setting of the regular expression with the paths for which the valve never becomes
	 * active. Example for activating the valve on all requests:
	 * <p>
	 * <code>".*"</code>
	 * 
	 * @param nonRelevantPaths The regular expression. Might be empty. Whether the
	 *                      parameter was valid can be checked via the result of the
	 *                      method {@link #isNonRelevantPathsValid()}
	 */
	public void setNonRelevantPaths(String nonRelevantPaths) {
		if (nonRelevantPaths == null || nonRelevantPaths.length() == 0) {
			this.nonRelevantPaths = null;
			nonRelevantPathsConfigValue = null;
			nonRelevantPathsValid = true;
		} else {
			boolean valid = false;
			try {
				nonRelevantPathsConfigValue = nonRelevantPaths;
				this.nonRelevantPaths = Pattern.compile(nonRelevantPaths);
				valid = true;
			} catch (Exception ex) {
			} finally {
				nonRelevantPathsValid = valid;
			}
		}
	}

	/**
	 * @see #setNonRelevantPaths(String)
	 */
	public boolean isNonRelevantPathsValid() {
		return nonRelevantPathsValid;
	}

	/**
	 * 
	 * @param maxIPCacheSize The number of IP addresses that can be monitored within
	 *                       a time slot. Used to prevent the memory requirement
	 *                       from growing indefinitely. This value is used as
	 *                       <code>maxCountersPerSlot</code> in
	 *                       {@link AntiDoSMonitor#AntiDoSMonitor(int, int, int, int, float)}
	 */
	public int getMaxIPCacheSize() {
		return maxIPCacheSize;
	}

	public void setMaxIPCacheSize(int maxIPCacheSize) {
		this.maxIPCacheSize = maxIPCacheSize;
	}

	/**
	 * @return The number of blocked IP addresses that can be monitored within a
	 *         time slot, or -1 if not set (falls back to {@link #getMaxIPCacheSize()})
	 */
	public int getMaxBlockedIPCacheSize() {
		return maxBlockedIPCacheSize;
	}

	/**
	 * Sets the number of blocked IP addresses that can be monitored within a time
	 * slot. If not set or non-positive, defaults to the value of
	 * {@link #setMaxIPCacheSize(int)}.
	 * 
	 * @param maxBlockedIPCacheSize The number of blocked IP addresses that can be
	 *                              monitored within a time slot
	 */
	public void setMaxBlockedIPCacheSize(int maxBlockedIPCacheSize) {
		this.maxBlockedIPCacheSize = maxBlockedIPCacheSize;
	}

	/**
	 * Sets the number of blocked IP addresses that can be monitored within a time
	 * slot from a string. If null or empty, falls back to -1 (default, which falls
	 * back to {@link #getMaxIPCacheSize()}).
	 * 
	 * @param maxBlockedIPCacheSize The number of blocked IP addresses as string
	 */
	public void setMaxBlockedIPCacheSize(String maxBlockedIPCacheSize) {
		if (maxBlockedIPCacheSize == null || maxBlockedIPCacheSize.trim().isEmpty()) {
			this.maxBlockedIPCacheSize = -1;
		} else {
			this.maxBlockedIPCacheSize = Integer.parseInt(maxBlockedIPCacheSize.trim());
		}
	}

	/**
	 * @return The IPv4 subnet mask prefix length (e.g. 24 for /24, 32 for no aggregation)
	 */
	public int getIpv4SubnetMask() {
		return ipv4SubnetMask;
	}

	/**
	 * Sets the IPv4 subnet prefix length (1 to 32). A value of 32 or -1 disables
	 * aggregation (default: 32).
	 * 
	 * @param ipv4SubnetMask The prefix length
	 */
	public void setIpv4SubnetMask(int ipv4SubnetMask) {
		this.ipv4SubnetMask = ipv4SubnetMask;
	}

	/**
	 * Sets the IPv4 subnet mask from a string (e.g. "24", "/24", or "255.255.255.0").
	 * 
	 * @param mask The subnet mask string
	 */
	public void setIpv4SubnetMask(String mask) {
		this.ipv4SubnetMask = parseSubnetMask(mask, 32);
	}

	/**
	 * @return <code>true</code> if the IPv4 subnet mask is valid (between 1 and 32, or -1)
	 */
	public boolean isIpv4SubnetMaskValid() {
		return ipv4SubnetMask == -1 || (ipv4SubnetMask >= 1 && ipv4SubnetMask <= 32);
	}

	/**
	 * @return The IPv6 subnet mask prefix length (e.g. 64 for /64, 128 for no aggregation)
	 */
	public int getIpv6SubnetMask() {
		return ipv6SubnetMask;
	}

	/**
	 * Sets the IPv6 subnet prefix length (1 to 128). A value of 128 or -1 disables
	 * aggregation (default: 128).
	 * 
	 * @param ipv6SubnetMask The prefix length
	 */
	public void setIpv6SubnetMask(int ipv6SubnetMask) {
		this.ipv6SubnetMask = ipv6SubnetMask;
	}

	/**
	 * Sets the IPv6 subnet mask from a string (e.g. "64" or "/64").
	 * 
	 * @param mask The subnet mask string
	 */
	public void setIpv6SubnetMask(String mask) {
		this.ipv6SubnetMask = parseSubnetMask(mask, 128);
	}

	/**
	 * @return <code>true</code> if the IPv6 subnet mask is valid (between 1 and 128, or -1)
	 */
	public boolean isIpv6SubnetMaskValid() {
		return ipv6SubnetMask == -1 || (ipv6SubnetMask >= 1 && ipv6SubnetMask <= 128);
	}

	/**
	 * @return <code>true</code> if subnet aggregation / monitoring is active (IPv4 prefix &lt; 32 or IPv6 prefix &lt; 128)
	 */
	public boolean isSubnetAggregationActive() {
		return (ipv4SubnetMask > 0 && ipv4SubnetMask < 32) || (ipv6SubnetMask > 0 && ipv6SubnetMask < 128);
	}

	/**
	 * @return The collector integration mode ("auto", "true", or "false"). Default is "auto".
	 */
	public String getCollectorIntegration() {
		return collectorIntegration;
	}

	/**
	 * Configures collector integration mode.
	 * <ul>
	 * <li><code>auto</code>: Automatically enables extended telemetry (distinct client tracking, etc.)
	 *     for 2 minutes whenever a collector queries the status endpoint. Falls back to minimal zero-overhead
	 *     mode when no collector is active.</li>
	 * <li><code>true</code>: Forces extended telemetry on permanently.</li>
	 * <li><code>false</code>: Explicitly disables extended telemetry (even if polled).</li>
	 * </ul>
	 * 
	 * @param collectorIntegration "auto", "true", or "false"
	 */
	public void setCollectorIntegration(String collectorIntegration) {
		if (collectorIntegration == null || collectorIntegration.trim().isEmpty()) {
			this.collectorIntegration = DEFAULT_COLLECTOR_INTEGRATION;
		} else {
			this.collectorIntegration = collectorIntegration.trim();
		}
	}

	public boolean isCollectorIntegrationValid() {
		if (collectorIntegration == null) {
			return true;
		}
		String trimmed = collectorIntegration.trim().toLowerCase();
		return "auto".equals(trimmed) || "true".equals(trimmed) || "false".equals(trimmed);
	}

	/**
	 * Renews the collector activity lease for {@link #COLLECTOR_LEASE_MILLIS} (2 minutes).
	 */
	public void touchCollectorLease() {
		lastCollectorScrapeTime.set(getTimeInMillis());
	}

	public long getLastCollectorScrapeTime() {
		return lastCollectorScrapeTime.get();
	}

	public void setLastCollectorScrapeTime(long time) {
		lastCollectorScrapeTime.set(time);
	}

	/**
	 * @return true if a collector has queried the status endpoint within the last 2 minutes
	 */
	public boolean isCollectorLeaseActive() {
		return (getTimeInMillis() - lastCollectorScrapeTime.get()) < COLLECTOR_LEASE_MILLIS;
	}

	/**
	 * @return true if extended metrics collection (distinct client tracking, etc.) is currently active
	 */
	public boolean isExtendedMetricsActive() {
		String mode = this.collectorIntegration;
		if ("true".equalsIgnoreCase(mode)) {
			return true;
		}
		if ("false".equalsIgnoreCase(mode)) {
			return false;
		}
		return isCollectorLeaseActive();
	}

	public boolean isVisitorCookieEnabled() {
		return visitorCookieEnabled;
	}

	/**
	 * Returns true if this valve actively validates visitor cookies itself, OR if another active valve
	 * in the Tomcat JVM has visitor cookie tracking enabled (allowing this valve to inherit validated visitor state).
	 *
	 * @return true if visitor tracking is active or inherited from an upstream valve
	 */
	public boolean isVisitorTrackingActive() {
		if (this.visitorCookieEnabled) {
			return true;
		}
		for (AntiDoSValve v : activeValves) {
			if (v != this && v.isVisitorCookieEnabled()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns the upstream valve from which visitor cookie tracking is inherited, or null if this valve
	 * manages its own cookies or no active valve has cookies enabled.
	 *
	 * @return upstream AntiDoSValve or null
	 */
	public AntiDoSValve getInheritedVisitorCookieValve() {
		if (this.visitorCookieEnabled) {
			return null;
		}
		for (AntiDoSValve v : activeValves) {
			if (v != this && v.isVisitorCookieEnabled()) {
				return v;
			}
		}
		return null;
	}

	/**
	 * Returns the effective cookie name used for visitor tracking (either this valve's configured name
	 * or the inherited name from an active upstream valve).
	 *
	 * @return effective visitor cookie name
	 */
	public String getEffectiveVisitorCookieName() {
		if (this.visitorCookieEnabled) {
			return this.visitorCookieName;
		}
		AntiDoSValve upstream = getInheritedVisitorCookieValve();
		return upstream != null ? upstream.getVisitorCookieName() : this.visitorCookieName;
	}

	/**
	 * Returns the effective cookie domain used for visitor tracking (either this valve's configured domain
	 * or the inherited domain from an active upstream valve).
	 *
	 * @return effective visitor cookie domain or null
	 */
	public String getEffectiveVisitorCookieDomain() {
		if (this.visitorCookieEnabled) {
			return this.visitorCookieDomain;
		}
		AntiDoSValve upstream = getInheritedVisitorCookieValve();
		return upstream != null ? upstream.getVisitorCookieDomain() : this.visitorCookieDomain;
	}

	public void setVisitorCookieEnabled(boolean visitorCookieEnabled) {
		this.visitorCookieEnabled = visitorCookieEnabled;
	}

	public void setVisitorCookieEnabled(String visitorCookieEnabled) {
		if (visitorCookieEnabled != null) {
			this.visitorCookieEnabled = Boolean.parseBoolean(visitorCookieEnabled.trim());
		}
	}

	public String getVisitorCookieName() {
		return visitorCookieName;
	}

	public void setVisitorCookieName(String visitorCookieName) {
		if (visitorCookieName != null && !visitorCookieName.trim().isEmpty()) {
			this.visitorCookieName = visitorCookieName.trim();
		}
	}

	public String getVisitorCookieSecret() {
		return visitorCookieSecret;
	}

	public void setVisitorCookieSecret(String visitorCookieSecret) {
		if (visitorCookieSecret == null || visitorCookieSecret.trim().isEmpty()) {
			this.visitorCookieSecret = null;
		} else {
			this.visitorCookieSecret = visitorCookieSecret.trim();
		}
	}

	public int getVisitorCookieTtlSeconds() {
		return visitorCookieTtlSeconds;
	}

	public void setVisitorCookieTtlSeconds(int visitorCookieTtlSeconds) {
		this.visitorCookieTtlSeconds = visitorCookieTtlSeconds;
	}

	public void setVisitorCookieTtlSeconds(String visitorCookieTtlSeconds) {
		if (visitorCookieTtlSeconds != null && !visitorCookieTtlSeconds.trim().isEmpty()) {
			this.visitorCookieTtlSeconds = Integer.parseInt(visitorCookieTtlSeconds.trim());
		}
	}

	public float getVisitorCookieRefreshRatio() {
		return visitorCookieRefreshRatio;
	}

	public void setVisitorCookieRefreshRatio(float visitorCookieRefreshRatio) {
		this.visitorCookieRefreshRatio = visitorCookieRefreshRatio;
	}

	public void setVisitorCookieRefreshRatio(String visitorCookieRefreshRatio) {
		if (visitorCookieRefreshRatio != null && !visitorCookieRefreshRatio.trim().isEmpty()) {
			this.visitorCookieRefreshRatio = Float.parseFloat(visitorCookieRefreshRatio.trim());
		}
	}

	public int getVisitorCookieSubnetMaskV4() {
		return visitorCookieSubnetMaskV4;
	}

	public void setVisitorCookieSubnetMaskV4(int visitorCookieSubnetMaskV4) {
		this.visitorCookieSubnetMaskV4 = visitorCookieSubnetMaskV4;
	}

	public void setVisitorCookieSubnetMaskV4(String mask) {
		this.visitorCookieSubnetMaskV4 = parseSubnetMask(mask, 32);
	}

	public int getVisitorCookieSubnetMaskV6() {
		return visitorCookieSubnetMaskV6;
	}

	public void setVisitorCookieSubnetMaskV6(int visitorCookieSubnetMaskV6) {
		this.visitorCookieSubnetMaskV6 = visitorCookieSubnetMaskV6;
	}

	public void setVisitorCookieSubnetMaskV6(String mask) {
		this.visitorCookieSubnetMaskV6 = parseSubnetMask(mask, 128);
	}

	public String getVisitorCookiePath() {
		return visitorCookiePath;
	}

	public void setVisitorCookiePath(String visitorCookiePath) {
		this.visitorCookiePath = (visitorCookiePath != null && !visitorCookiePath.trim().isEmpty())
				? visitorCookiePath.trim() : "/";
	}

	public String getVisitorCookieSameSite() {
		return visitorCookieSameSite;
	}

	public void setVisitorCookieSameSite(String visitorCookieSameSite) {
		this.visitorCookieSameSite = (visitorCookieSameSite != null && !visitorCookieSameSite.trim().isEmpty())
				? visitorCookieSameSite.trim() : "Lax";
	}

	public String getVisitorCookieSecure() {
		return visitorCookieSecure;
	}

	public void setVisitorCookieSecure(String visitorCookieSecure) {
		this.visitorCookieSecure = (visitorCookieSecure != null && !visitorCookieSecure.trim().isEmpty())
				? visitorCookieSecure.trim() : "auto";
	}

	public String getVisitorCookieDomain() {
		return visitorCookieDomain;
	}

	public void setVisitorCookieDomain(String visitorCookieDomain) {
		if (visitorCookieDomain == null || visitorCookieDomain.trim().isEmpty()) {
			this.visitorCookieDomain = null;
		} else {
			this.visitorCookieDomain = visitorCookieDomain.trim();
		}
	}

	public AntiDoSVisitorTokenService getVisitorTokenService() {
		return visitorTokenService;
	}

	public void setVisitorTokenService(AntiDoSVisitorTokenService visitorTokenService) {
		this.visitorTokenService = visitorTokenService;
	}

	public void initVisitorTokenService() {
		SecretKey key = AntiDoSVisitorTokenService.parseOrGenerateKey(this.visitorCookieSecret);
		this.visitorTokenService = new AntiDoSVisitorTokenService(key);
	}

	/**
	 * @return The shared server-wide authentication session cache
	 */
	public static AntiDoSAuthSessionCache getSharedAuthSessionCache() {
		return sharedAuthSessionCache;
	}

	/**
	 * Clears the shared server-wide authentication session cache. Primarily used in unit tests.
	 */
	public static void clearAuthSessionCache() {
		sharedAuthSessionCache.clear();
		sharedAuthSessionCache.setMaxCapacity(AntiDoSAuthSessionCache.DEFAULT_MAX_CAPACITY);
	}

	/**
	 * @return Configured authentication tracking mode ("OFF" or "COOKIE"). Defaults to "OFF".
	 */
	public String getAuthTrackingMode() {
		return authTrackingMode;
	}

	/**
	 * Sets the authentication tracking mode. Supported values: "OFF" (or "NONE", "FALSE", empty) and "COOKIE".
	 *
	 * @param authTrackingMode The authentication tracking mode
	 */
	public void setAuthTrackingMode(String authTrackingMode) {
		if (authTrackingMode == null || authTrackingMode.trim().isEmpty()) {
			this.authTrackingMode = AUTH_TRACKING_MODE_OFF;
		} else {
			String normalized = authTrackingMode.trim().toUpperCase();
			if ("NONE".equals(normalized) || "FALSE".equals(normalized) || "OFF".equals(normalized)) {
				this.authTrackingMode = AUTH_TRACKING_MODE_OFF;
			} else {
				this.authTrackingMode = normalized;
			}
		}
	}

	/**
	 * @return {@code true} if {@link #getAuthTrackingMode()} is a valid supported mode ("OFF" or "COOKIE")
	 */
	public boolean isAuthTrackingModeValid() {
		return AUTH_TRACKING_MODE_OFF.equals(authTrackingMode) || AUTH_TRACKING_MODE_COOKIE.equals(authTrackingMode);
	}

	/**
	 * @return {@code true} if authentication session tracking is explicitly enabled on this valve instance
	 */
	public boolean isAuthTrackingEnabled() {
		return AUTH_TRACKING_MODE_COOKIE.equals(authTrackingMode);
	}

	/**
	 * Returns {@code true} if this valve actively tracks authentication sessions itself, OR if another
	 * active valve in the Tomcat JVM has authentication tracking enabled (allowing this valve to share
	 * the session cache and inherit authenticated request state).
	 *
	 * @return {@code true} if authentication tracking is active on this valve or inherited from an active valve
	 */
	public boolean isAuthTrackingActive() {
		if (this.isAuthTrackingEnabled()) {
			return true;
		}
		for (AntiDoSValve v : activeValves) {
			if (v != this && v.isAuthTrackingEnabled()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns the active valve from which authentication tracking configuration is inherited,
	 * or {@code null} if this valve manages authentication tracking itself or no active valve has it enabled.
	 *
	 * @return inherited {@link AntiDoSValve} or {@code null}
	 */
	public AntiDoSValve getInheritedAuthTrackingValve() {
		if (this.isAuthTrackingEnabled()) {
			return null;
		}
		for (AntiDoSValve v : activeValves) {
			if (v != this && v.isAuthTrackingEnabled()) {
				return v;
			}
		}
		return null;
	}

	/**
	 * @return The effective authentication tracking mode (either configured on this valve or inherited)
	 */
	public String getEffectiveAuthTrackingMode() {
		if (this.isAuthTrackingEnabled()) {
			return this.authTrackingMode;
		}
		AntiDoSValve inherited = getInheritedAuthTrackingValve();
		return inherited != null ? inherited.getAuthTrackingMode() : this.authTrackingMode;
	}

	/**
	 * @return The effective authentication cookie name (either configured on this valve or inherited)
	 */
	public String getEffectiveAuthCookieName() {
		if (this.isAuthTrackingEnabled()) {
			return this.authCookieName;
		}
		AntiDoSValve inherited = getInheritedAuthTrackingValve();
		return inherited != null ? inherited.getAuthCookieName() : this.authCookieName;
	}

	/**
	 * @return The effective login paths regex pattern string (either configured on this valve or inherited)
	 */
	public String getEffectiveAuthLoginPathsConfigValue() {
		if (this.isAuthTrackingEnabled()) {
			return this.authLoginPathsConfigValue;
		}
		AntiDoSValve inherited = getInheritedAuthTrackingValve();
		return inherited != null ? inherited.getAuthLoginPathsConfigValue() : this.authLoginPathsConfigValue;
	}

	/**
	 * @return The effective fallback session TTL in seconds (either configured on this valve or inherited)
	 */
	public int getEffectiveAuthSessionTtlSeconds() {
		if (this.isAuthTrackingEnabled()) {
			return this.authSessionTtlSeconds;
		}
		AntiDoSValve inherited = getInheritedAuthTrackingValve();
		return inherited != null ? inherited.getAuthSessionTtlSeconds() : this.authSessionTtlSeconds;
	}

	/**
	 * @return The effective maximum authentication session cache size (either configured on this valve or inherited)
	 */
	public int getEffectiveMaxAuthCacheSize() {
		if (this.isAuthTrackingEnabled()) {
			return this.maxAuthCacheSize;
		}
		AntiDoSValve inherited = getInheritedAuthTrackingValve();
		return inherited != null ? inherited.getMaxAuthCacheSize() : this.maxAuthCacheSize;
	}

	/**
	 * @return The current number of non-expired authenticated sessions in the shared server cache
	 */
	public int getActiveAuthSessionCount() {
		return isAuthTrackingActive() ? sharedAuthSessionCache.getActiveSessionCount(getTimeInMillis()) : 0;
	}

	public String getAuthCookieName() {
		return authCookieName;
	}

	public void setAuthCookieName(String authCookieName) {
		if (authCookieName == null || authCookieName.trim().isEmpty()) {
			this.authCookieName = null;
		} else {
			this.authCookieName = authCookieName.trim();
		}
	}

	public String getAuthLoginPathsConfigValue() {
		return authLoginPathsConfigValue;
	}

	public void setAuthLoginPaths(String authLoginPaths) {
		if (authLoginPaths == null || authLoginPaths.trim().isEmpty()) {
			this.authLoginPaths = null;
			this.authLoginPathsConfigValue = null;
			this.authLoginPathsValid = true;
		} else {
			boolean valid = false;
			try {
				this.authLoginPathsConfigValue = authLoginPaths.trim();
				this.authLoginPaths = Pattern.compile(this.authLoginPathsConfigValue);
				valid = true;
			} catch (Exception ex) {
			} finally {
				this.authLoginPathsValid = valid;
			}
		}
	}

	public boolean isAuthLoginPathsValid() {
		return authLoginPathsValid;
	}

	public boolean isRequestURIInAuthLoginPaths(String requestURI) {
		Pattern loginPattern = this.authLoginPaths;
		return loginPattern != null && requestURI != null && loginPattern.matcher(requestURI).matches();
	}

	public int getAuthSessionTtlSeconds() {
		return authSessionTtlSeconds;
	}

	public void setAuthSessionTtlSeconds(int authSessionTtlSeconds) {
		this.authSessionTtlSeconds = authSessionTtlSeconds;
	}

	public void setAuthSessionTtlSeconds(String authSessionTtlSeconds) {
		if (authSessionTtlSeconds == null || authSessionTtlSeconds.trim().isEmpty()) {
			this.authSessionTtlSeconds = AntiDoSAuthSessionCache.DEFAULT_SESSION_TTL_SECONDS;
		} else {
			this.authSessionTtlSeconds = Integer.parseInt(authSessionTtlSeconds.trim());
		}
	}

	public int getMaxAuthCacheSize() {
		return maxAuthCacheSize;
	}

	public void setMaxAuthCacheSize(int maxAuthCacheSize) {
		this.maxAuthCacheSize = maxAuthCacheSize;
		if (maxAuthCacheSize > 0) {
			sharedAuthSessionCache.setMaxCapacity(maxAuthCacheSize);
		}
	}

	public void setMaxAuthCacheSize(String maxAuthCacheSize) {
		if (maxAuthCacheSize == null || maxAuthCacheSize.trim().isEmpty()) {
			setMaxAuthCacheSize(AntiDoSAuthSessionCache.DEFAULT_MAX_CAPACITY);
		} else {
			setMaxAuthCacheSize(Integer.parseInt(maxAuthCacheSize.trim()));
		}
	}

	/**
	 * 
	 * @param numberOfSlots The number of slots to be held. More slots allow a
	 *                      further look into the past, but increase the memory
	 *                      requirements and slow down the execution to a certain
	 *                      degree
	 */
	public void setNumberOfSlots(int numberOfSlots) {
		this.numberOfSlots = numberOfSlots;
	}

	public int getNumberOfSlots() {
		return numberOfSlots;
	}

	/**
	 * 
	 * @param slotLength The length of the individual slots in seconds
	 */
	public void setSlotLength(int slotLength) {
		this.slotLength = slotLength;
	}

	public int getSlotLength() {
		return slotLength;
	}

	/**
	 * 
	 * @param allowedRequestsPerSlot The number of requests from one IP address
	 *                               allowed within a slot until it is blocked (>= 0;
	 *                               set to 0 for zero-tolerance honeypot traps)
	 */
	public void setAllowedRequestsPerSlot(int allowedRequestsPerSlot) {
		this.allowedRequestsPerSlot = allowedRequestsPerSlot;
	}

	/**
	 * Sets the number of allowed requests per slot from a string.
	 * 
	 * @param allowedRequestsPerSlot The number of requests as string (>= 0)
	 */
	public void setAllowedRequestsPerSlot(String allowedRequestsPerSlot) {
		if (allowedRequestsPerSlot == null || allowedRequestsPerSlot.trim().isEmpty()) {
			this.allowedRequestsPerSlot = -1;
		} else {
			this.allowedRequestsPerSlot = Integer.parseInt(allowedRequestsPerSlot.trim());
		}
	}

	public int getAllowedRequestsPerSlot() {
		return allowedRequestsPerSlot;
	}

	/**
	 * 
	 * @param shareOfRetainedFormerRequests This parameter defines which portion of
	 *                                      the requests from an IP address from
	 *                                      previous slots is retained in a new
	 *                                      slot. The higher this share, the longer
	 *                                      it takes for an IP address to recover
	 *                                      from a blocking. The value 1 would mean
	 *                                      that the average number of requests for
	 *                                      an IP address in the past slots is
	 *                                      retained completely. A value of 0.5
	 *                                      would retain half, the value of 0 would
	 *                                      completely ignore the past (is this case
	 *                                      the retention of older slots would make
	 *                                      no sense). A value greater than 1 would
	 *                                      eventually lead to a block in the case
	 *                                      of an IP address which remains below the
	 *                                      <code>allowedRequestsPerSlot</code> per
	 *                                      slot on average.
	 */
	public void setShareOfRetainedFormerRequests(float shareOfRetainedFormerRequests) {
		this.shareOfRetainedFormerRequests = shareOfRetainedFormerRequests;
	}

	public void setShareOfRetainedFormerRequests(String shareOfRetainedFormerRequests) {
		if (shareOfRetainedFormerRequests == null || shareOfRetainedFormerRequests.trim().isEmpty()) {
			this.shareOfRetainedFormerRequests = 0;
			return;
		}
		try {
			this.shareOfRetainedFormerRequests = Float.parseFloat(shareOfRetainedFormerRequests.trim());
		} catch (NumberFormatException ex) {
			this.shareOfRetainedFormerRequests = -1;
		}
	}

	public float getShareOfRetainedFormerRequests() {
		return shareOfRetainedFormerRequests;
	}

	/**
	 * 
	 * @return if <code>true</code> the valve operates in simulation mode and will
	 *         not perform actual blockings. Default is <code>false</code>
	 */
	public boolean isSimulationMode() {
		return simulationMode;
	}

	/**
	 * Turn simulation mode on or off
	 * 
	 * @param simulationMode if <code>true</code> the valve will operate in
	 *                       simulation mode and not perform actual blockings
	 */
	public void setSimulationMode(boolean simulationMode) {
		this.simulationMode = simulationMode;
	}

	/**
	 * @return <code>true</code> if server-wide blocking is active
	 */
	public boolean isServerWideBlocking() {
		return serverWideBlocking;
	}

	/**
	 * Controls whether an IP blocked on {@link #getRelevantPathsConfigValue()} is
	 * blocked across all server paths.
	 * 
	 * @param serverWideBlocking <code>true</code> to block all server paths when limit is exceeded
	 */
	public void setServerWideBlocking(boolean serverWideBlocking) {
		this.serverWideBlocking = serverWideBlocking;
	}

	/**
	 * @return The HTTP response status code used when blocking requests
	 */
	public int getHttpStatusCode() {
		return httpStatusCode;
	}

	/**
	 * Sets the HTTP response status code used when blocking requests in
	 * {@link #DEFAULT_MONITOR_MODE}. Defaults to {@link #DEFAULT_HTTP_STATUS_CODE} (429).
	 * To restore the legacy behavior of previous versions, set this to
	 * {@link #LEGACY_HTTP_STATUS_CODE} (403).
	 *
	 * @param httpStatusCode The HTTP status code (must be between 100 and 599)
	 */
	public void setHttpStatusCode(int httpStatusCode) {
		this.httpStatusCode = httpStatusCode;
	}

	/**
	 * Sets the HTTP response status code used when blocking requests from a string.
	 * If null or empty, defaults to {@link #DEFAULT_HTTP_STATUS_CODE} (429).
	 *
	 * @param httpStatusCode The HTTP status code as string
	 */
	public void setHttpStatusCode(String httpStatusCode) {
		if (httpStatusCode == null || httpStatusCode.trim().isEmpty()) {
			this.httpStatusCode = DEFAULT_HTTP_STATUS_CODE;
		} else {
			this.httpStatusCode = Integer.parseInt(httpStatusCode.trim());
		}
	}

	/**
	 * @return <code>true</code> if {@link #getHttpStatusCode()} is a valid HTTP status code
	 */
	public boolean isHttpStatusCodeValid() {
		return httpStatusCode >= 100 && httpStatusCode <= 599;
	}

	public String getName4logging() {
		return name4logging;
	}

	/**
	 * @return Set of all active AntiDoSValve instances currently running in the JVM
	 */
	public static Set<AntiDoSValve> getActiveValves() {
		return Collections.unmodifiableSet(activeValves);
	}

	/**
	 * Clears the set of active valves. Primarily used in unit tests.
	 */
	public static void clearActiveValves() {
		for (AntiDoSValve v : activeValves) {
			v.registrationIndex = 0;
			v.stopped = false;
		}
		activeValves.clear();
		registrationSequence.set(0);
		clearAuthSessionCache();
	}

	/**
	 * Returns the shared randomly generated status access token, generating one if not already created.
	 * The token is generated using {@link SecureRandom} and consists of 16 to 20 hexadecimal characters (0-9a-f),
	 * which allows easy double-click copying in console windows without special characters.
	 *
	 * @return The random HEX access token
	 */
	public static synchronized String getOrGenerateStatusToken() {
		if (generatedStatusToken == null) {
			int byteLength = 8 + SECURE_RANDOM.nextInt(3); // 8, 9, or 10 bytes -> 16, 18, or 20 hex chars
			byte[] bytes = new byte[byteLength];
			SECURE_RANDOM.nextBytes(bytes);
			StringBuilder sb = new StringBuilder(byteLength * 2);
			for (byte b : bytes) {
				sb.append(String.format("%02x", b));
			}
			generatedStatusToken = sb.toString();
		}
		return generatedStatusToken;
	}

	/**
	 * Resets the shared random status access token. Primarily used in unit tests.
	 */
	public static synchronized void resetGeneratedStatusToken() {
		generatedStatusToken = null;
	}

	/**
	 * @return The URI path at which the status dashboard is exposed, or <code>null</code> if disabled
	 */
	public String getStatusUri() {
		return statusUri;
	}

	/**
	 * Sets the URI path at which the internal status dashboard is exposed (e.g. "/antidos-status").
	 * If null or empty, the status dashboard is disabled (default).
	 *
	 * @param statusUri The status URI path
	 */
	public void setStatusUri(String statusUri) {
		if (statusUri == null || statusUri.trim().isEmpty()) {
			this.statusUri = null;
		} else {
			String uri = statusUri.trim();
			if (!uri.startsWith("/")) {
				uri = "/" + uri;
			}
			this.statusUri = uri;
		}
	}

	/**
	 * @return The regular expression matching IP addresses allowed to access the status dashboard
	 */
	public String getStatusAllowedIPs() {
		return statusAllowedIPsConfigValue;
	}

	/**
	 * Sets a regular expression matching client IP addresses allowed to access the status dashboard.
	 * If null or empty, all client IPs are allowed (subject to password and rate limiting).
	 *
	 * @param statusAllowedIPs Regular expression for allowed client IPs
	 */
	public void setStatusAllowedIPs(String statusAllowedIPs) {
		this.statusAllowedIPsConfigValue = statusAllowedIPs;
		if (statusAllowedIPs == null || statusAllowedIPs.trim().isEmpty()) {
			this.statusAllowedIPs = null;
			this.statusAllowedIPsValid = true;
			return;
		}
		try {
			this.statusAllowedIPs = Pattern.compile(statusAllowedIPs.trim());
			this.statusAllowedIPsValid = true;
		} catch (Exception e) {
			this.statusAllowedIPsValid = false;
		}
	}

	/**
	 * @return <code>true</code> if {@link #getStatusAllowedIPs()} contains a valid regular expression
	 */
	public boolean isStatusAllowedIPsValid() {
		return statusAllowedIPsValid;
	}

	/**
	 * @return The configured password for the status dashboard, or <code>null</code> if unconfigured
	 */
	public String getStatusPassword() {
		return statusPassword;
	}

	/**
	 * Sets the access password for the status dashboard. If null or empty, a secure random HEX token
	 * is automatically generated on startup and logged to the server console.
	 *
	 * @param statusPassword The access password
	 */
	public void setStatusPassword(String statusPassword) {
		if (statusPassword == null || statusPassword.trim().isEmpty()) {
			this.statusPassword = null;
		} else {
			this.statusPassword = statusPassword.trim();
		}
	}

	/**
	 * @return The effective password used to protect the status dashboard (configured password or generated HEX token)
	 */
	public String getEffectiveStatusPassword() {
		if (statusPassword != null && !statusPassword.trim().isEmpty()) {
			return statusPassword.trim();
		}
		return getOrGenerateStatusToken();
	}

	/**
	 * This method is called on every request. It uses
	 * {@link #isRequestAllowed(String, String)} for its checks. If a request is
	 * blocked the reaction of the valve depends on its mode:
	 * <ul>
	 * <li>{@link #DEFAULT_MONITOR_MODE}: the value of {@link #getHttpStatusCode()} is set as error code
	 * <li>{@link #MARKING_MONITOR_MODE}: an information is added to the request
	 * </ul>
	 * When simulationMode is on only logging information is generated
	 */
	@Override
	public void invoke(Request request, Response response) throws IOException, ServletException {

		String ip = request.getRemoteAddr();
		String path = request.getRequestURI();

		if (statusUri != null && statusUri.equals(path)) {
			handleStatusRequest(request, response, ip);
			return;
		}

		if (log.isDebugEnabled()) {
			log.debug(name4logging + ", ip: " + ip);
			log.debug(name4logging + ", path: " + path);
		}

		boolean isReturningVisitor = false;
		int visitorCounter = 0;
		boolean issueNewCookie = false;
		byte[] clientSubnetBytes = null;
		long now = getTimeInMillis();

		Object upstreamCtxObj = request.getAttribute(VISITOR_CONTEXT_ATTRIBUTE_NAME);
		if (upstreamCtxObj instanceof AntiDoSVisitorContext upstreamCtx) {
			isReturningVisitor = upstreamCtx.valid();
			visitorCounter = upstreamCtx.counter();
			clientSubnetBytes = upstreamCtx.subnetBytes();
		} else if (visitorCookieEnabled && visitorTokenService != null) {
			clientSubnetBytes = extractVisitorSubnetBytes(ip);
			String cookieVal = extractCookieValue(request, visitorCookieName);
			if (cookieVal != null && clientSubnetBytes != null) {
				TokenData tokenData = visitorTokenService.validateToken(cookieVal, clientSubnetBytes, now);
				if (tokenData.isValid()) {
					isReturningVisitor = true;
					visitorCounter = tokenData.counter();
					long remainingTtl = tokenData.expiresAtMillis() - now;
					long fullTtl = (long) visitorCookieTtlSeconds * 1000L;
					if (remainingTtl < (long) (fullTtl * visitorCookieRefreshRatio)) {
						issueNewCookie = true;
					}
				} else {
					issueNewCookie = true;
				}
			} else {
				issueNewCookie = true;
			}

			request.setAttribute(VISITOR_CONTEXT_ATTRIBUTE_NAME, new AntiDoSVisitorContext(
					isReturningVisitor,
					visitorCounter,
					visitorCookieSubnetMaskV4,
					visitorCookieSubnetMaskV6,
					clientSubnetBytes));
			request.setAttribute(RETURNING_VISITOR_ATTRIBUTE_NAME, isReturningVisitor);
			request.setAttribute(FIRST_CONTACT_ATTRIBUTE_NAME, !isReturningVisitor);
			request.setAttribute(VISITOR_COUNTER_ATTRIBUTE_NAME, visitorCounter);
		}

		boolean isAuthenticated = false;
		String incomingAuthCookieVal = null;
		Object upstreamAuthObj = request.getAttribute(AUTHENTICATED_ATTRIBUTE_NAME);
		if (upstreamAuthObj instanceof Boolean b) {
			isAuthenticated = b.booleanValue();
		} else if (isAuthTrackingActive()) {
			String effAuthCookieName = getEffectiveAuthCookieName();
			if (effAuthCookieName != null && !effAuthCookieName.isEmpty()) {
				incomingAuthCookieVal = extractCookieValue(request, effAuthCookieName);
				if (incomingAuthCookieVal != null) {
					isAuthenticated = sharedAuthSessionCache.isValidSession(incomingAuthCookieVal, now);
				}
			}
			request.setAttribute(AUTHENTICATED_ATTRIBUTE_NAME, Boolean.valueOf(isAuthenticated));
		}

		boolean allowed = isRequestAllowed(ip, path, isReturningVisitor, isAuthenticated);
		if (!allowed) {
			recordBlockedSampleIfAbsent(ip, request, path);
		}
		if (allowed || simulationMode) {
			if (visitorCookieEnabled && visitorTokenService != null && issueNewCookie && clientSubnetBytes != null) {
				String newCookieVal = visitorTokenService.createToken(clientSubnetBytes, visitorCounter,
						(long) visitorCookieTtlSeconds * 1000L, now);
				String headerVal = buildSetCookieHeader(request, newCookieVal, visitorCookieTtlSeconds);
				response.addHeader("Set-Cookie", headerVal);
			}
			if (getNext() != null) {
				getNext().invoke(request, response);
			}
			inspectAuthLoginResponse(request, response, path, incomingAuthCookieVal);
			return;
		}

		if (isMonitorModeDefault()) {
			// block request:
			if (httpStatusCode == DEFAULT_HTTP_STATUS_CODE) {
				int retryAfter = provideRetryAfterSeconds();
				response.setHeader("Retry-After", Integer.toString(retryAfter));
			}
			response.sendError(httpStatusCode);
		} else {
			// mark request:
			response.getRequest().setAttribute(MARKING_ATTRIBUTE_NAME, name4logging);
			if (getNext() != null) {
				getNext().invoke(request, response);
			}
			inspectAuthLoginResponse(request, response, path, incomingAuthCookieVal);
		}
	}

	void inspectAuthLoginResponse(Request request, Response response, String path, String incomingAuthCookieVal) {
		if (!isAuthTrackingEnabled() || !isRequestURIInAuthLoginPaths(path) || response == null) {
			return;
		}
		int status = response.getStatus();
		if (status < 200 || status >= 400) {
			return;
		}
		java.util.Collection<String> setCookieHeaders = response.getHeaders("Set-Cookie");
		if (setCookieHeaders == null || setCookieHeaders.isEmpty()) {
			return;
		}
		String reqCookie = incomingAuthCookieVal != null
				? incomingAuthCookieVal
				: extractCookieValue(request, authCookieName);
		sharedAuthSessionCache.processSetCookieHeaders(
				setCookieHeaders, authCookieName, authSessionTtlSeconds, reqCookie, getTimeInMillis());
	}

	void recordBlockedSampleIfAbsent(String ip, Request request, String path) {
		AntiDoSMonitor monitor = provideMonitor();
		if (monitor == null || request == null) {
			return;
		}
		String counterName = resolveCounterName(ip);
		AntiDoSCounter counter = monitor.provideCurrentCounter(counterName);
		if (counter != null && counter.getSample() == null) {
			String method = request.getMethod();
			String ua = request.getHeader("User-Agent");
			counter.recordSampleIfAbsent(method, path, ua);
		}
	}

	byte[] extractVisitorSubnetBytes(String ip) {
		if (ip == null || ip.isEmpty()) {
			return null;
		}
		byte[] v4 = parseIPv4Literal(ip);
		if (v4 != null) {
			int mask = this.visitorCookieSubnetMaskV4 > 0 ? this.visitorCookieSubnetMaskV4 : 32;
			maskBytes(v4, mask);
			return v4;
		}
		if (ip.indexOf(':') >= 0) {
			try {
				InetAddress addr = InetAddress.getByName(ip);
				if (addr instanceof Inet6Address) {
					byte[] bytes = addr.getAddress();
					int mask = this.visitorCookieSubnetMaskV6 > 0 ? this.visitorCookieSubnetMaskV6 : 128;
					maskBytes(bytes, mask);
					return bytes;
				}
			} catch (UnknownHostException ignored) {
			}
		}
		return null;
	}

	String extractCookieValue(Request request, String name) {
		if (request == null || name == null) {
			return null;
		}
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie c : cookies) {
				if (name.equals(c.getName())) {
					return c.getValue();
				}
			}
		}
		return null;
	}

	String buildSetCookieHeader(Request request, String cookieValue, int ttlSeconds) {
		StringBuilder sb = new StringBuilder(128);
		sb.append(visitorCookieName).append('=').append(cookieValue);
		if (visitorCookieDomain != null && !visitorCookieDomain.isEmpty()) {
			sb.append("; Domain=").append(visitorCookieDomain);
		}
		sb.append("; Path=").append(visitorCookiePath != null ? visitorCookiePath : "/");
		sb.append("; Max-Age=").append(ttlSeconds);
		sb.append("; SameSite=").append(visitorCookieSameSite != null ? visitorCookieSameSite : "Lax");
		sb.append("; HttpOnly");

		boolean secure;
		if ("true".equalsIgnoreCase(visitorCookieSecure)) {
			secure = true;
		} else if ("false".equalsIgnoreCase(visitorCookieSecure)) {
			secure = false;
		} else {
			secure = (request != null && request.isSecure())
					|| (request != null && "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto")));
		}
		if (secure) {
			sb.append("; Secure");
		}
		return sb.toString();
	}

	/**
	 * Handles status dashboard requests.
	 *
	 * @param request  The incoming request
	 * @param response The response to send
	 * @param ip       The client IP address
	 * @throws IOException
	 */
	void handleStatusRequest(Request request, Response response, String ip) throws IOException {
		// 1. Check IP whitelist if configured
		if (statusAllowedIPs != null && !statusAllowedIPs.matcher(ip).matches()) {
			if (log.isDebugEnabled()) {
				log.debug(name4logging + " Status request rejected (IP not allowed): " + ip);
			}
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}

		// 2. Check password/token
		if (!isStatusTokenValid(request)) {
			// If the IP is already blocked, reject with httpStatusCode (e.g. 429) before counting
			if (isIPAddressCurrentlyBlocked(ip)) {
				if (log.isDebugEnabled()) {
					log.debug(name4logging + " Status request rejected (IP currently blocked and invalid token): " + ip);
				}
				if (httpStatusCode == DEFAULT_HTTP_STATUS_CODE) {
					response.setHeader("Retry-After", Integer.toString(provideRetryAfterSeconds()));
				}
				response.sendError(httpStatusCode);
				return;
			}

			if (log.isDebugEnabled()) {
				log.debug(name4logging + " Status request unauthorized (invalid or missing token): " + ip);
			}
			// Asymmetric counting: record failed authentication attempt in the monitor!
			isIPAddressBlocked(ip);
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		// 3. Authorized (valid token): Render dashboard (NOT blocked, NOT counted in monitor)
		String token = request.getParameter("token");
		if (token == null || token.isEmpty()) {
			String authHeader = request.getHeader("Authorization");
			if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
				token = authHeader.substring(7).trim();
			}
		}

		String format = request.getParameter("format");
		boolean isJson = "json".equalsIgnoreCase(format) ||
				(request.getHeader("Accept") != null && request.getHeader("Accept").contains("application/json"));

		String filterValve = request.getParameter("valve");
		String view = request.getParameter("view");
		if (view == null && "true".equalsIgnoreCase(request.getParameter("details"))) {
			view = "details";
		}
		String slot = request.getParameter("slot");
		String limit = request.getParameter("limit");
		String blockedLimit = request.getParameter("blockedLimit");
		String activeLimit = request.getParameter("activeLimit");
		String sinceBlockedOrder = request.getParameter("sinceBlockedOrder");
		String sinceActiveOrder = request.getParameter("sinceActiveOrder");
		String activeMinCount = request.getParameter("activeMinCount");

		if (isJson) {
			touchCollectorLease();
			for (AntiDoSValve v : getValvesToRender()) {
				if (filterValve == null || filterValve.trim().isEmpty() || v.getMonitorName().equalsIgnoreCase(filterValve.trim())) {
					v.touchCollectorLease();
				}
			}
			statusRenderer.renderStatusJson(response, filterValve, view, slot, limit, blockedLimit, activeLimit,
					sinceBlockedOrder, sinceActiveOrder, activeMinCount);
		} else {
			statusRenderer.renderStatusHtml(response, filterValve, view, token, slot, limit, blockedLimit, activeLimit);
		}
	}

	boolean isStatusTokenValid(Request request) {
		String expected = getEffectiveStatusPassword();
		if (expected == null || expected.isEmpty()) {
			return false;
		}

		String provided = request.getParameter("token");
		if (provided == null || provided.isEmpty()) {
			String authHeader = request.getHeader("Authorization");
			if (authHeader != null && authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
				provided = authHeader.substring(7).trim();
			}
		}

		if (provided == null) {
			return false;
		}

		return MessageDigest.isEqual(provided.trim().getBytes(StandardCharsets.UTF_8),
				expected.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Returns the 1-based sequential registration index of this valve instance, assigned during startup
	 * or first access. Used as a fallback ordering key if container pipeline information is unavailable.
	 *
	 * @return The registration index of this valve
	 */
	public int getRegistrationIndex() {
		if (registrationIndex == 0) {
			registrationIndex = registrationSequence.incrementAndGet();
		}
		return registrationIndex;
	}

	/**
	 * Determines the hierarchy tier of the Tomcat container to which this valve is attached.
	 * In Tomcat, request processing flows down the container hierarchy from Engine (tier 1)
	 * to Host (tier 2) to Context (tier 3).
	 *
	 * @return Numerical tier representing the container hierarchy level (1 for Engine, 2 for Host, 3 for Context)
	 */
	private int getContainerTier() {
		try {
			Container c = getContainer();
			if (c instanceof org.apache.catalina.Engine) {
				return 1;
			}
			if (c instanceof org.apache.catalina.Host) {
				return 2;
			}
			if (c instanceof org.apache.catalina.Context) {
				return 3;
			}
		} catch (Exception e) {
			// Ignore
		}
		return 2;
	}

	/**
	 * Returns a {@link Comparator} that orders {@link AntiDoSValve} instances according to their
	 * actual Tomcat pipeline execution order:
	 * <ol>
	 *   <li>Container tier hierarchy ({@code Engine} before {@code Host} before {@code Context})</li>
	 *   <li>Pipeline index within the same container (from {@link Pipeline#getValves()})</li>
	 *   <li>Registration/startup sequence index as fallback</li>
	 * </ol>
	 *
	 * @return Comparator ordering valves by execution sequence
	 */
	public static Comparator<AntiDoSValve> getPipelineOrderComparator() {
		return (v1, v2) -> {
			if (v1 == v2) {
				return 0;
			}
			// 1. Container tier (Engine < Host < Context)
			int t1 = v1.getContainerTier();
			int t2 = v2.getContainerTier();
			if (t1 != t2) {
				return Integer.compare(t1, t2);
			}
			// 2. If same container and pipeline is available
			if (v1.getContainer() != null && v1.getContainer() == v2.getContainer()) {
				try {
					Pipeline p = v1.getContainer().getPipeline();
					if (p != null) {
						Valve[] valves = p.getValves();
						int idx1 = -1;
						int idx2 = -1;
						for (int i = 0; i < valves.length; i++) {
							if (valves[i] == v1) idx1 = i;
							if (valves[i] == v2) idx2 = i;
						}
						if (idx1 != -1 && idx2 != -1) {
							return Integer.compare(idx1, idx2);
						}
					}
				} catch (Exception e) {
					// Fallback
				}
			}
			// 3. Fallback to registrationIndex (order of addition/start)
			return Integer.compare(v1.getRegistrationIndex(), v2.getRegistrationIndex());
		};
	}

	/**
	 * Returns the 1-based execution order index of this valve among all currently active
	 * {@link AntiDoSValve} instances in the JVM.
	 *
	 * @return 1-based pipeline position (1 for the first valve to execute, 2 for the second, etc.),
	 * -1 if not running.
	 */
	public int getPipelineOrder() {
		if (stopped) {
			return -1;
		}
		Set<AntiDoSValve> valves = getValvesToRender();
		int order = 1;
		for (AntiDoSValve v : valves) {
			if (v == this) {
				return order;
			}
			order++;
		}
		return -1;
	}

	/**
	 * Returns the set of all active {@link AntiDoSValve} instances ordered by their Tomcat pipeline
	 * execution order, suitable for deterministic rendering in HTML status dashboards and JSON APIs.
	 *
	 * @return A {@link LinkedHashSet} of active valves sorted by execution order
	 */
	Set<AntiDoSValve> getValvesToRender() {
		if (stopped) {
			return Collections.emptySet();
		}
		getRegistrationIndex();
		if (activeValves.isEmpty()) {
			Set<AntiDoSValve> fallback = new LinkedHashSet<>();
			fallback.add(this);
			return fallback;
		}
		List<AntiDoSValve> list = new ArrayList<>(activeValves);
		list.sort(getPipelineOrderComparator());
		return new LinkedHashSet<>(list);
	}

	public String buildStatusHtml(String filterValve) {
		return statusRenderer.buildStatusHtml(filterValve);
	}

	public String buildStatusHtml(String filterValve, String token) {
		return statusRenderer.buildStatusHtml(filterValve, token);
	}

	public String buildStatusHtmlDetails(String valveName, String token) {
		return statusRenderer.buildStatusHtmlDetails(valveName, token);
	}

	public String buildStatusHtmlDetails(String valveName, String token, String slotParam, Integer limit) {
		return statusRenderer.buildStatusHtmlDetails(valveName, token, slotParam, limit);
	}

	public String buildStatusHtmlDetails(String valveName, String token, String slotParam, Integer blockedLimit, Integer activeLimit) {
		return statusRenderer.buildStatusHtmlDetails(valveName, token, slotParam, blockedLimit, activeLimit);
	}

	public String buildStatusJson(String filterValve) {
		return statusRenderer.buildStatusJson(filterValve);
	}

	public String buildStatusJsonDetails(String filterValve) {
		return statusRenderer.buildStatusJsonDetails(filterValve);
	}

	public String buildStatusJsonDetails(String filterValve, String slotParam, Integer limit) {
		return statusRenderer.buildStatusJsonDetails(filterValve, slotParam, limit);
	}

	public String buildStatusJsonDetails(String filterValve, String slotParam, Integer blockedLimit, Integer activeLimit) {
		return statusRenderer.buildStatusJsonDetails(filterValve, slotParam, blockedLimit, activeLimit);
	}

	public String buildStatusJsonDetails(String filterValve, String slotParam, Integer blockedLimit, Integer activeLimit,
			Long sinceBlockedOrder, Long sinceActiveOrder, Integer activeMinCount) {
		return statusRenderer.buildStatusJsonDetails(filterValve, slotParam, blockedLimit, activeLimit,
				sinceBlockedOrder, sinceActiveOrder, activeMinCount);
	}

	public static String buildDashboardUrl(String token, String valve, String view, String format) {
		return AntiDoSStatusRenderer.buildDashboardUrl(token, valve, view, format);
	}

	public static String buildDashboardUrl(String token, String valve, String view, String format, boolean forHtml) {
		return AntiDoSStatusRenderer.buildDashboardUrl(token, valve, view, format, forHtml);
	}

	public static String buildDashboardUrl(String token, String valve, String view, String format, String slot, String limit, boolean forHtml) {
		return AntiDoSStatusRenderer.buildDashboardUrl(token, valve, view, format, slot, limit, forHtml);
	}

	public static String buildDashboardUrl(String token, String valve, String view, String format, String slot, String limit,
			String blockedLimit, String activeLimit, boolean forHtml) {
		return AntiDoSStatusRenderer.buildDashboardUrl(token, valve, view, format, slot, limit, blockedLimit, activeLimit, forHtml);
	}

	public static String escapeHtml(String text) {
		return AntiDoSStatusRenderer.escapeHtml(text);
	}

	public static String escapeJson(String text) {
		return AntiDoSStatusRenderer.escapeJson(text);
	}

	@Override
	protected void initInternal() throws LifecycleException {
		super.initInternal();
		checkConfiguration();
	}

	@Override
	protected synchronized void startInternal() throws LifecycleException {
		checkConfiguration();
		super.startInternal();
		this.stopped = false;
		if (this.registrationIndex == 0) {
			this.registrationIndex = registrationSequence.incrementAndGet();
		}
		activeValves.add(this);

		if (statusUri != null) {
			if (statusPassword != null && !statusPassword.trim().isEmpty()) {
				log.info(name4logging + " Status dashboard active at: " + statusUri + " (using configured password)");
			} else {
				String token = getEffectiveStatusPassword();
				log.info("======================================================================\n"
						+ name4logging + " Status dashboard active at: " + statusUri + "\n"
						+ name4logging + " No password configured. Generated random HEX access token:\n"
						+ "               --> " + token + " <--\n"
						+ "======================================================================");
			}
		}
	}

	@Override
	protected synchronized void stopInternal() throws LifecycleException {
		this.stopped = true;
		activeValves.remove(this);
		super.stopInternal();
		AntiDoSMonitor monitor = monitors.get(monitorName);
		if (monitor != null) {
			monitor.shutdown();
		}
	}

	/**
	 * Checks the valve configuration. Creates the internal {@link AntiDoSMonitor}
	 * instance if it does not yet exit
	 * 
	 * @throws LifecycleException Thrown if configuration is invalid
	 */
	private void checkConfiguration() throws LifecycleException {
		if (!alwaysForbiddenIPsValid)
			throw new LifecycleException(name4logging + ".alwaysForbiddenIPs is invalid");
		if (!alwaysAllowedIPsValid)
			throw new LifecycleException(name4logging + ".alwaysAllowedIPs is invalid");
		if (!relevantPathsValid)
			throw new LifecycleException(name4logging + ".relevantPaths is invalid");
		if (!statusAllowedIPsValid)
			throw new LifecycleException(name4logging + ".statusAllowedIPs is invalid: " + statusAllowedIPsConfigValue);
		if (!isMonitorModeValid())
			throw new LifecycleException(name4logging + ".monitorMode is invalid");
		if (!isHttpStatusCodeValid())
			throw new LifecycleException(name4logging + ".httpStatusCode is invalid: " + httpStatusCode);
		if (!isIpv4SubnetMaskValid())
			throw new LifecycleException(name4logging + ".ipv4SubnetMask is invalid: " + ipv4SubnetMask);
		if (!isIpv6SubnetMaskValid())
			throw new LifecycleException(name4logging + ".ipv6SubnetMask is invalid: " + ipv6SubnetMask);
		if (!isCollectorIntegrationValid())
			throw new LifecycleException(name4logging + ".collectorIntegration is invalid: " + collectorIntegration);
		if (visitorCookieEnabled) {
			if (visitorCookieTtlSeconds <= 0) {
				throw new LifecycleException(name4logging + ".visitorCookieTtlSeconds must be positive: " + visitorCookieTtlSeconds);
			}
			if (visitorCookieRefreshRatio <= 0.0f || visitorCookieRefreshRatio >= 1.0f) {
				throw new LifecycleException(name4logging + ".visitorCookieRefreshRatio must be between 0.0 and 1.0: " + visitorCookieRefreshRatio);
			}
			if (visitorCookieDomain != null && (visitorCookieDomain.contains("/") || visitorCookieDomain.contains(";") || visitorCookieDomain.contains(" "))) {
				throw new LifecycleException(name4logging + ".visitorCookieDomain contains invalid characters: " + visitorCookieDomain);
			}
			if (visitorTokenService == null) {
				initVisitorTokenService();
			}
		}
		if (!isAuthTrackingModeValid()) {
			throw new LifecycleException(name4logging + ".authTrackingMode is invalid: " + authTrackingMode);
		}
		if (!authLoginPathsValid) {
			throw new LifecycleException(name4logging + ".authLoginPaths is invalid: " + authLoginPathsConfigValue);
		}
		if (isAuthTrackingEnabled()) {
			if (authCookieName == null || authCookieName.isEmpty()) {
				throw new LifecycleException(name4logging + ".authCookieName must be configured when authTrackingMode=COOKIE");
			}
			if (authLoginPaths == null) {
				throw new LifecycleException(name4logging + ".authLoginPaths must be configured when authTrackingMode=COOKIE");
			}
			if (authSessionTtlSeconds <= 0) {
				throw new LifecycleException(name4logging + ".authSessionTtlSeconds must be positive: " + authSessionTtlSeconds);
			}
			if (maxAuthCacheSize <= 0) {
				throw new LifecycleException(name4logging + ".maxAuthCacheSize must be positive: " + maxAuthCacheSize);
			}
			sharedAuthSessionCache.setMaxCapacity(maxAuthCacheSize);
		}

		if (provideMonitor() == null) {
			String monitorMsg = reloadMonitor();
			if (monitorMsg != null)
				throw new LifecycleException(name4logging + ".AntiDoSMonitor parameter is invalid: " + monitorMsg);
		}
	}

	/**
	 * (Re)Creates the internal {@link AntiDoSMonitor} instance. The method was
	 * originally established for the unit tests. Another application is the
	 * configuration via JMX. After a configuration change the monitor can be
	 * reloaded.
	 * 
	 * @return Returns <code>null</code>, if the monitor instance has been created
	 *         without problems. If a parameter is missing or invalid, a text with a
	 *         corresponding message is provided
	 */
	public String reloadMonitor() {
		synchronized (monitors) {
			try {
				int effectiveMaxBlockedIPCacheSize = maxBlockedIPCacheSize > 0 ? maxBlockedIPCacheSize : maxIPCacheSize;
				AntiDoSMonitor monitor = new AntiDoSMonitor(monitorName, maxIPCacheSize, effectiveMaxBlockedIPCacheSize,
						numberOfSlots, slotLength, allowedRequestsPerSlot, shareOfRetainedFormerRequests);

				if (monitorName == null)
					monitorName = DEFAULT_MONITOR_NAME;

				if (asyncEviction != null) {
					monitor.setAsyncEviction(asyncEviction);
				}
				monitor.setMaxBlockLogsPerSecond(maxBlockLogsPerSecond);

				if (visitorCookieEnabled && visitorTokenService == null) {
					initVisitorTokenService();
				}
				if (isAuthTrackingEnabled() && maxAuthCacheSize > 0) {
					sharedAuthSessionCache.setMaxCapacity(maxAuthCacheSize);
				}

				AntiDoSMonitor old = monitors.put(monitorName, monitor);
				if (old != null && old != monitor) {
					old.shutdown();
				}

				if (log.isInfoEnabled()) {
					if (isMonitorModeDefault())
						log.info(name4logging + " is in blocking mode");
					else if (isMonitorModeMarking())
						log.info(name4logging + " is in marking mode");

					if (simulationMode)
						log.info(name4logging + " is in SIMULATION MODE");

					if (serverWideBlocking)
						log.info(name4logging + " is in SERVER-WIDE BLOCKING mode");
				}
				return null;
			} catch (IllegalArgumentException ex) {
				return ex.getMessage();
			}
		}
	}

	/**
	 * Programmatically controls whether asynchronous batch eviction is used.
	 * 
	 * @param asyncEviction <code>true</code> to force async, <code>false</code> to force sync,
	 *                      or <code>null</code> for automatic decision based on maxIPCacheSize &gt; 500.
	 */
	public void setAsyncEviction(Boolean asyncEviction) {
		this.asyncEviction = asyncEviction;
		AntiDoSMonitor monitor = provideMonitor();
		if (monitor != null) {
			monitor.setAsyncEviction(asyncEviction);
		}
	}

	public Boolean getAsyncEviction() {
		return this.asyncEviction;
	}

	/**
	 * Programmatically controls the maximum number of block log entries allowed per second.
	 * Negative values (&lt; 0) disable throttling completely.
	 * 0 suppresses all block log messages.
	 *
	 * @param maxBlockLogsPerSecond the maximum logs per second or negative to disable throttling.
	 */
	public void setMaxBlockLogsPerSecond(int maxBlockLogsPerSecond) {
		this.maxBlockLogsPerSecond = maxBlockLogsPerSecond;
		AntiDoSMonitor monitor = provideMonitor();
		if (monitor != null) {
			monitor.setMaxBlockLogsPerSecond(maxBlockLogsPerSecond);
		}
	}

	/**
	 * Sets the maximum number of block log entries allowed per second from a string.
	 * If null or empty, defaults to -1 (disabled).
	 *
	 * @param maxBlockLogsPerSecond the maximum logs per second as string
	 */
	public void setMaxBlockLogsPerSecond(String maxBlockLogsPerSecond) {
		if (maxBlockLogsPerSecond == null || maxBlockLogsPerSecond.trim().isEmpty()) {
			setMaxBlockLogsPerSecond(-1);
		} else {
			setMaxBlockLogsPerSecond(Integer.parseInt(maxBlockLogsPerSecond.trim()));
		}
	}

	public int getMaxBlockLogsPerSecond() {
		return this.maxBlockLogsPerSecond;
	}

	/**
	 * Calculates the remaining seconds until the current time slot ends for use in
	 * the {@code Retry-After} HTTP response header (RFC 6585).
	 *
	 * @return Remaining seconds in current slot, at least 1.
	 */
	public int provideRetryAfterSeconds() {
		return provideRetryAfterSeconds(getTimeInMillis());
	}

	/**
	 * Calculates the remaining seconds until the current time slot ends relative to
	 * the provided timestamp.
	 *
	 * @param currentTimeMillis The timestamp in milliseconds
	 * @return Remaining seconds in current slot, at least 1.
	 */
	public int provideRetryAfterSeconds(long currentTimeMillis) {
		int len = this.slotLength;
		if (len <= 0) {
			AntiDoSMonitor monitor = provideMonitor();
			if (monitor != null && monitor.getSlotLength() > 0) {
				len = monitor.getSlotLength() / 1000;
			}
		}
		if (len <= 0) {
			len = 30; // fallback if unconfigured
		}
		long slotLengthMillis = len * 1000L;
		long currentSlotStartMillis = (currentTimeMillis / slotLengthMillis) * slotLengthMillis;
		long remainingMillis = (currentSlotStartMillis + slotLengthMillis) - currentTimeMillis;
		int remainingSec = (int) Math.ceil(remainingMillis / 1000.0);
		return Math.max(1, remainingSec);
	}

	/**
	 * Provides current time in milliseconds. Can be overridden in tests.
	 */
	protected long getTimeInMillis() {
		return System.currentTimeMillis();
	}

	/**
	 * This method implements the actual business logic of the valve. The method is
	 * public and can be called by JMX. The test runs in this order:
	 * 
	 * <ul>
	 * <li>Is the IP address always blocked? Calls
	 * {@link #isIPAddressInAlwaysForbidden(String)}. If <code>true</code> the
	 * check is finished and <code>false</code> returned as result, but the IP
	 * address is not counted in the {@link AntiDoSMonitor} instance
	 * <li>Is the IP address always allowed? Calls
	 * {@link #isIPAddressInAlwaysAllowed(String)}. If <code>true</code> the check
	 * is finished and <code>true</code> returned as result, but the IP address is
	 * not counted
	 * <li>Is the request URI in the non relevant paths? Calls
	 * {@link #isRequestURIInNonRelevantPaths(String)}. If <code>true</code> the check
	 * is finished and <code>true</code> returned as result, but the IP address is
	 * not counted
	 * <li>Is the request URI in the relevant paths? Calls
	 * {@link #isRequestURIInRelevantPaths(String)}. If <code>true</code>, the
	 * actual rate limitation is tested via {@link #isIPAddressBlocked(String)}.
	 * <li>If the request URI is not in the relevant paths: If {@link #isServerWideBlocking()}
	 * is enabled and the IP is currently blocked (via {@link #isIPAddressCurrentlyBlocked(String)}),
	 * returns <code>false</code>. Otherwise returns <code>true</code>.
	 * </ul>
	 *
	 * @param ip         The IP address
	 * @param requestURI The path, should be the result of
	 *                   {@link HttpServletRequest#getRequestURI()}
	 * @return <code>true</code> if the request is allowed, <code>false</code> if it
	 *         should be blocked
	 */
	public boolean isRequestAllowed(String ip, String requestURI) {

		if (isIPAddressInAlwaysForbidden(ip)) {
			alwaysForbiddenBlockedRequests.increment();
			if (log.isDebugEnabled())
				log.debug(name4logging + " Is in AlwaysForbiddenIPs: " + ip);

			return false;
		}

		if (isIPAddressInAlwaysAllowed(ip)) {
			if (log.isDebugEnabled())
				log.debug(name4logging + " Is in alwaysAllowedIPs: " + ip);

			return true;
		}

		if (isRequestURIInNonRelevantPaths(requestURI)) {
			if (log.isDebugEnabled())
				log.debug(name4logging + " Is in nonRelevantPaths: " + requestURI);

			return true;
		}

		if (isRequestURIInRelevantPaths(requestURI)) {
			return !isIPAddressBlocked(ip, false);
		}

		if (serverWideBlocking && isIPAddressCurrentlyBlocked(ip)) {
			if (log.isDebugEnabled())
				log.debug(name4logging + " Server-wide blocked: " + ip);

			return false;
		}

		if (log.isDebugEnabled())
			log.debug(name4logging + " Not in relevantPaths: " + requestURI);

		return true;
	}

	public boolean isRequestAllowed(String ip, String requestURI, boolean returningVisitor) {
		return isRequestAllowed(ip, requestURI, returningVisitor, false);
	}

	public boolean isRequestAllowed(String ip, String requestURI, boolean returningVisitor, boolean authenticated) {
		if (isIPAddressInAlwaysForbidden(ip)) {
			alwaysForbiddenBlockedRequests.increment();
			if (log.isDebugEnabled())
				log.debug(name4logging + " In alwaysForbidden: " + ip);

			return false;
		}

		if (isIPAddressInAlwaysAllowed(ip)) {
			if (log.isDebugEnabled())
				log.debug(name4logging + " Is in alwaysAllowedIPs: " + ip);

			return true;
		}

		if (isRequestURIInNonRelevantPaths(requestURI)) {
			if (log.isDebugEnabled())
				log.debug(name4logging + " Is in nonRelevantPaths: " + requestURI);

			return true;
		}

		if (isRequestURIInRelevantPaths(requestURI)) {
			return !isIPAddressBlocked(ip, returningVisitor, authenticated);
		}

		if (serverWideBlocking && isIPAddressCurrentlyBlocked(ip)) {
			if (log.isDebugEnabled())
				log.debug(name4logging + " Server-wide blocked: " + ip);

			return false;
		}

		if (log.isDebugEnabled())
			log.debug(name4logging + " Not in relevantPaths: " + requestURI);

		return true;
	}

	/**
	 * This method checks if an IP address is blocked in the internal
	 * {@link AntiDoSMonitor} instance. At the same time, the call increases the
	 * counter for this IP address. The method is public and can be called by JMX
	 * 
	 * @param ip The IP address
	 * @see AntiDoSMonitor#registerAndCheckRequest(String)
	 * @throws IllegalArgumentException If the parameter is <code>null</code> or
	 *                                  empty
	 */
	public boolean isIPAddressBlocked(String ip) throws IllegalArgumentException {
		return isIPAddressBlocked(ip, false, false);
	}

	/**
	 * This method checks if an IP address is blocked in the internal
	 * {@link AntiDoSMonitor} instance, registering the access and whether it was a returning visitor.
	 * 
	 * @param ip               The IP address
	 * @param returningVisitor true if request presented a valid authenticated visitor cookie
	 * @return true if blocked, false if allowed
	 * @throws IllegalArgumentException If the parameter is null or empty
	 */
	public boolean isIPAddressBlocked(String ip, boolean returningVisitor) throws IllegalArgumentException {
		return isIPAddressBlocked(ip, returningVisitor, false);
	}

	/**
	 * This method checks if an IP address is blocked in the internal
	 * {@link AntiDoSMonitor} instance, registering the access, returning visitor state,
	 * and authenticated login session state.
	 * 
	 * @param ip               The IP address
	 * @param returningVisitor true if request presented a valid authenticated visitor cookie
	 * @param authenticated    true if request presented a valid authenticated login session cookie
	 * @return true if blocked, false if allowed
	 * @throws IllegalArgumentException If the parameter is null or empty
	 */
	public boolean isIPAddressBlocked(String ip, boolean returningVisitor, boolean authenticated)
			throws IllegalArgumentException {
		if (ip == null || ip.isEmpty()) {
			throw new IllegalArgumentException("IP address must not be null or empty");
		}
		int v4Mask = this.ipv4SubnetMask;
		int v6Mask = this.ipv6SubnetMask;
		boolean v4Active = v4Mask > 0 && v4Mask < 32;
		boolean v6Active = v6Mask > 0 && v6Mask < 128;

		String counterName = ip;
		byte[] rawIpv4Bytes = null;
		if (v4Active || v6Active) {
			if (v4Active) {
				rawIpv4Bytes = parseIPv4Literal(ip);
				if (rawIpv4Bytes != null) {
					byte[] maskedBytes = rawIpv4Bytes.clone();
					maskBytes(maskedBytes, v4Mask);
					counterName = formatIPv4Subnet(maskedBytes, v4Mask);
				}
			}
			if (counterName.equals(ip) && v6Active && ip.indexOf(':') >= 0) {
				counterName = aggregateSubnet(ip, false, v4Mask, true, v6Mask);
			}
		}

		boolean trackCardinality = isExtendedMetricsActive() && !counterName.equals(ip);
		AntiDoSMonitor monitor = provideMonitor();
		if (monitor == null || monitor.registerAndCheckRequest(counterName, ip, rawIpv4Bytes, trackCardinality, v4Mask, v6Mask, returningVisitor, authenticated)) {
			if (log.isDebugEnabled())
				if (monitor == null)
					log.debug(name4logging + " not available");
				else
					log.debug(name4logging + " Not blocked in AntiDoSMonitor: " + ip
							+ (counterName.equals(ip) ? "" : " (counter: " + counterName + ")"));

			return false;
		}

		if (log.isDebugEnabled())
			log.debug(name4logging + " blocks: " + ip
					+ (counterName.equals(ip) ? "" : " (counter: " + counterName + ")"));

		return true;
	}

	/**
	 * This method checks if an IP address is currently blocked in the internal
	 * {@link AntiDoSMonitor} instance, without incrementing any counters or
	 * registering a request. The method is public and can be called by JMX.
	 * 
	 * @param ip The IP address
	 * @return <code>true</code> if the IP address is currently blocked, <code>false</code> otherwise
	 * @throws IllegalArgumentException If parameter is null or empty
	 */
	public boolean isIPAddressCurrentlyBlocked(String ip) throws IllegalArgumentException {
		if (ip == null || ip.isEmpty()) {
			throw new IllegalArgumentException("IP address must not be null or empty");
		}
		String counterName = resolveCounterName(ip);
		AntiDoSMonitor monitor = provideMonitor();
		if (monitor == null) {
			return false;
		}
		return monitor.isCounterBlocked(counterName);
	}

	/**
	 * This method returns the current status of an IP address in the internal
	 * {@link AntiDoSMonitor} instance. This call does not alter the status of the
	 * IP address. The method is public and can be called by JMX
	 * 
	 * @param ip The IP address
	 * @see AntiDoSMonitor#provideCurrentCounter(String)
	 * @throws IllegalArgumentException Thrown if parameter is empty
	 */
	public String getIPAddressStatus(String ip) throws IllegalArgumentException {
		if (ip == null || ip.isEmpty()) {
			throw new IllegalArgumentException("IP address must not be null or empty");
		}
		String counterName = resolveCounterName(ip);
		AntiDoSMonitor monitor = provideMonitor();

		AntiDoSCounter ipCounter = monitor != null ? monitor.provideCurrentCounter(counterName) : null;

		return ipCounter != null ? ipCounter.toString() : "-";
	}

	/**
	 * Resolves the internal counter name for a given client IP address.
	 * If subnet aggregation is active (e.g. {@link #getIpv4SubnetMask()} &lt; 32
	 * or {@link #getIpv6SubnetMask()} &lt; 128), addresses belonging to the same
	 * subnet map to a common counter key (e.g. "192.168.1.0/24" or "2001:db8::/64").
	 * 
	 * @param ip The IP address string
	 * @return The counter key to use for rate limiting
	 */
	public String resolveCounterName(String ip) {
		if (ip == null || ip.isEmpty()) {
			return ip;
		}

		int v4Mask = this.ipv4SubnetMask;
		int v6Mask = this.ipv6SubnetMask;
		boolean v4Active = v4Mask > 0 && v4Mask < 32;
		boolean v6Active = v6Mask > 0 && v6Mask < 128;

		if (!v4Active && !v6Active) {
			return ip;
		}

		return aggregateSubnet(ip, v4Active, v4Mask, v6Active, v6Mask);
	}

	private String aggregateSubnet(String ip, boolean v4Active, int v4Mask, boolean v6Active, int v6Mask) {
		if (v4Active) {
			byte[] ipv4Bytes = parseIPv4Literal(ip);
			if (ipv4Bytes != null) {
				maskBytes(ipv4Bytes, v4Mask);
				return formatIPv4Subnet(ipv4Bytes, v4Mask);
			}
		}

		if (v6Active && ip.indexOf(':') >= 0) {
			try {
				InetAddress addr = InetAddress.getByName(ip);
				if (addr instanceof Inet6Address) {
					byte[] bytes = addr.getAddress();
					maskBytes(bytes, v6Mask);
					return InetAddress.getByAddress(bytes).getHostAddress() + "/" + v6Mask;
				}
			} catch (UnknownHostException e) {
				return ip;
			}
		}

		return ip;
	}

	private static byte[] parseIPv4Literal(String ip) {
		int len = ip.length();
		if (len < 7 || len > 15) {
			return null;
		}
		int octetCount = 0;
		byte[] bytes = new byte[4];
		int curOctet = 0;
		int digits = 0;
		for (int i = 0; i < len; i++) {
			char c = ip.charAt(i);
			if (c >= '0' && c <= '9') {
				curOctet = curOctet * 10 + (c - '0');
				digits++;
				if (digits > 3 || curOctet > 255) {
					return null;
				}
			} else if (c == '.') {
				if (digits == 0 || octetCount >= 3) {
					return null;
				}
				bytes[octetCount++] = (byte) curOctet;
				curOctet = 0;
				digits = 0;
			} else {
				return null;
			}
		}
		if (digits == 0 || octetCount != 3) {
			return null;
		}
		bytes[3] = (byte) curOctet;
		return bytes;
	}

	private static void maskBytes(byte[] bytes, int prefixBits) {
		int fullBytes = prefixBits / 8;
		int remBits = prefixBits % 8;
		if (fullBytes < bytes.length) {
			if (remBits > 0) {
				bytes[fullBytes] = (byte) (bytes[fullBytes] & (0xFF << (8 - remBits)));
				fullBytes++;
			}
			for (int i = fullBytes; i < bytes.length; i++) {
				bytes[i] = 0;
			}
		}
	}

	private static String formatIPv4Subnet(byte[] b, int prefixBits) {
		return (b[0] & 0xFF) + "." + (b[1] & 0xFF) + "." + (b[2] & 0xFF) + "." + (b[3] & 0xFF) + "/" + prefixBits;
	}

	static int parseSubnetMask(String mask, int maxBits) {
		if (mask == null || mask.trim().isEmpty()) {
			return maxBits;
		}
		String s = mask.trim();
		if (s.startsWith("/")) {
			s = s.substring(1).trim();
		}
		if (maxBits == 32 && s.contains(".")) {
			byte[] b = parseIPv4Literal(s);
			if (b == null) {
				throw new IllegalArgumentException("Invalid dotted-decimal netmask: " + mask);
			}
			long val = ((long) (b[0] & 0xFF) << 24) | ((long) (b[1] & 0xFF) << 16) | ((long) (b[2] & 0xFF) << 8)
					| ((long) (b[3] & 0xFF));
			int prefix = Long.bitCount(val);
			long expected = prefix == 0 ? 0L : (0xFFFFFFFF00000000L >>> prefix) & 0xFFFFFFFFL;
			if (val != expected) {
				throw new IllegalArgumentException(
						"Invalid dotted-decimal netmask (non-contiguous mask bits): " + mask);
			}
			return prefix;
		}
		int prefix;
		try {
			prefix = Integer.parseInt(s);
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid subnet mask: " + mask, e);
		}
		if (prefix == -1) {
			return maxBits;
		}
		if (prefix < 1 || prefix > maxBits) {
			throw new IllegalArgumentException("Subnet mask prefix must be between 1 and " + maxBits + ": " + mask);
		}
		return prefix;
	}

	/**
	 * This method checks if an IP address is matched by the pattern in
	 * {@link #getAlwaysForbiddenIPsConfigValue()}. The method is public and can be
	 * called by JMX
	 *
	 * @param ip The IP address
	 */
	public boolean isIPAddressInAlwaysForbidden(String ip) {
		// Local copy for thread safety
		Pattern alwaysForbidden = this.alwaysForbiddenIPs;

		return alwaysForbidden != null && alwaysForbidden.matcher(ip).matches();
	}

	/**
	 * This method checks if an IP address is matched by the pattern in
	 * {@link #getAlwaysAllowedIPsConfigValue()}. The method is public and can be
	 * called by JMX
	 *
	 * @param ip The IP address
	 */
	public boolean isIPAddressInAlwaysAllowed(String ip) {
		// Local copy for thread safety
		Pattern alwaysAllowed = this.alwaysAllowedIPs;

		return alwaysAllowed != null && alwaysAllowed.matcher(ip).matches();
	}

	/**
	 * This method checks if a URL is matched by the pattern in
	 * {@link #getRelevantPathsConfigValue()}. The method is public and can be called by JMX
	 *
	 * @param requestURI The path. Should be the result of
	 *                   {@link HttpServletRequest#getRequestURI()}
	 */
	public boolean isRequestURIInRelevantPaths(String requestURI) {
		// Local copy for thread safety
		Pattern relevant = this.relevantPaths;

		return relevant != null && relevant.matcher(requestURI).matches();
	}

	/**
	 * This method checks if a URL is matched by the pattern in
	 * {@link #getNonRelevantPathsConfigValue()}. The method is public and can be called by JMX
	 *
	 * @param requestURI The path. Should be the result of
	 *                   {@link HttpServletRequest#getRequestURI()}
	 */
	public boolean isRequestURIInNonRelevantPaths(String requestURI) {
		// Local copy for thread safety
		Pattern nonrelevant = this.nonRelevantPaths;

		return nonrelevant != null && nonrelevant.matcher(requestURI).matches();
	}

	/**
	 * @return Prints the current status of the internal monitoring object, e. g.
	 *         for JMX monitoring
	 */
	public String getMonitorStatus() {
		AntiDoSMonitor monitor = provideMonitor();
		return monitor != null ? monitor.toString() : "NOT INITIALIZED!";
	}
}
