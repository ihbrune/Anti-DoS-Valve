package org.henbru.antidos;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

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
	 * Set of all currently active valve instances in the JVM.
	 */
	private static final Set<AntiDoSValve> activeValves = ConcurrentHashMap.newKeySet();

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	private static volatile String generatedStatusToken = null;

	private volatile String statusUri = null;
	private volatile String statusAllowedIPsConfigValue = null;
	private volatile Pattern statusAllowedIPs = null;
	private volatile boolean statusAllowedIPsValid = true;
	private volatile String statusPassword = null;

	private volatile int maxIPCacheSize = -1;
	private volatile int maxBlockedIPCacheSize = -1;
	private volatile int ipv4SubnetMask = 32;
	private volatile int ipv6SubnetMask = 128;
	private volatile int numberOfSlots = -1;
	private volatile int slotLength = -1;
	private volatile int allowedRequestsPerSlot = -1;
	private volatile float shareOfRetainedFormerRequests = -1;
	private volatile boolean simulationMode = false;
	private volatile boolean serverWideBlocking = false;
	private volatile int httpStatusCode = DEFAULT_HTTP_STATUS_CODE;
	private volatile Boolean asyncEviction = null;
	private volatile int maxBlockLogsPerSecond = AntiDoSLogThrottler.DEFAULT_MAX_LOGS_PER_SECOND;

	/**
	 * Monitor operation mode. If not set the default mode is used
	 */
	private volatile String monitorMode = DEFAULT_MONITOR_MODE;

	/**
	 * Internal monitor name. If not set a default name is used
	 */
	private volatile String monitorName = DEFAULT_MONITOR_NAME;

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
	 * @see {@link #setMonitorName(String)}
	 * @return always <code>true</code>
	 */
	public boolean isMonitorNameValid() {
		return true;
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
	 *                               allowed within a slot until it is blocked
	 */
	public void setAllowedRequestsPerSlot(int allowedRequestsPerSlot) {
		this.allowedRequestsPerSlot = allowedRequestsPerSlot;
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
	public void setShareOfRetainedFormerRequests(String shareOfRetainedFormerRequests) {
		this.shareOfRetainedFormerRequests = -1;
		try {
			this.shareOfRetainedFormerRequests = Float.parseFloat(shareOfRetainedFormerRequests);
		} catch (NumberFormatException | NullPointerException ex) {
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
		activeValves.clear();
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

		boolean allowed = isRequestAllowed(ip, path);
		if (allowed || simulationMode) {
			getNext().invoke(request, response);
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
			getNext().invoke(request, response);
		}
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

		if (isJson) {
			renderStatusJson(response, filterValve, view);
		} else {
			renderStatusHtml(response, filterValve, view, token);
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

	static record CounterEntry(String key, int count, int retained, int effective, boolean locked)
			implements Comparable<CounterEntry> {
		@Override
		public int compareTo(CounterEntry other) {
			int cmp = Integer.compare(other.effective, this.effective);
			if (cmp != 0) return cmp;
			cmp = Integer.compare(other.count, this.count);
			if (cmp != 0) return cmp;
			return this.key.compareTo(other.key);
		}
	}

	static String buildDashboardUrl(String token, String valve, String view, String format) {
		return buildDashboardUrl(token, valve, view, format, true);
	}

	static String buildDashboardUrl(String token, String valve, String view, String format, boolean forHtml) {
		List<String> params = new ArrayList<>();
		if (token != null && !token.isEmpty()) {
			params.add("token=" + URLEncoder.encode(token, StandardCharsets.UTF_8));
		}
		if (valve != null && !valve.isEmpty()) {
			params.add("valve=" + URLEncoder.encode(valve, StandardCharsets.UTF_8));
		}
		if (view != null && !view.isEmpty()) {
			params.add("view=" + URLEncoder.encode(view, StandardCharsets.UTF_8));
		}
		if (format != null && !format.isEmpty()) {
			params.add("format=" + URLEncoder.encode(format, StandardCharsets.UTF_8));
		}
		if (params.isEmpty()) {
			return "?";
		}
		String separator = forHtml ? "&amp;" : "&";
		return "?" + String.join(separator, params);
	}

	/**
	 * Generates the HTML status dashboard.
	 *
	 * @param response    The HTTP response
	 * @param filterValve The valve to filter by
	 * @param view        The dashboard view ("details" or overview)
	 * @param token       The active access token for building carry-over links
	 * @throws IOException If an I/O error occurs
	 */
	private void renderStatusHtml(Response response, String filterValve, String view, String token) throws IOException {
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		PrintWriter out = response.getWriter();
		if ("details".equalsIgnoreCase(view)) {
			out.write(buildStatusHtmlDetails(filterValve, token));
		} else {
			out.write(buildStatusHtml(filterValve, token));
		}
		out.flush();
	}

	/**
	 * Generates the JSON status dashboard.
	 *
	 * @param response    The HTTP response
	 * @param filterValve The valve to filter by
	 * @param view        The dashboard view ("details" or overview)
	 * @throws IOException If an I/O error occurs
	 */
	private void renderStatusJson(Response response, String filterValve, String view) throws IOException {
		response.setContentType("application/json;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		PrintWriter out = response.getWriter();
		if ("details".equalsIgnoreCase(view)) {
			out.write(buildStatusJsonDetails(filterValve));
		} else {
			out.write(buildStatusJson(filterValve));
		}
		out.flush();
	}

	private Set<AntiDoSValve> getValvesToRender() {
		if (activeValves.isEmpty()) {
			Set<AntiDoSValve> fallback = ConcurrentHashMap.newKeySet();
			fallback.add(this);
			return fallback;
		}
		if (!activeValves.contains(this)) {
			activeValves.add(this);
		}
		return activeValves;
	}

	String buildStatusHtml(String filterValve) {
		return buildStatusHtml(filterValve, null);
	}

	String buildStatusHtml(String filterValve, String token) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		sdf.setTimeZone(TimeZone.getDefault());
		String serverTime = sdf.format(new Date(getTimeInMillis()));

		Set<AntiDoSValve> valves = getValvesToRender();

		StringBuilder sb = new StringBuilder(4096);
		sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
				.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
				.append("<title>Anti-DoS Valve Monitor</title>\n")
				.append("<style>\n")
				.append(":root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--border:#334155;--accent:#38bdf8;--green:#22c55e;--red:#ef4444;--yellow:#eab308}\n")
				.append("body{font-family:ui-monospace,\"SF Mono\",Menlo,Consolas,\"Liberation Mono\",monospace;background:var(--bg);color:var(--text);margin:0;padding:24px;font-size:13px;line-height:1.5}\n")
				.append(".header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:12px;margin-bottom:24px;flex-wrap:wrap;gap:8px}\n")
				.append(".title{font-size:16px;font-weight:700;color:var(--accent);display:flex;align-items:center;gap:8px}\n")
				.append(".subtitle{color:var(--muted);font-size:12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}\n")
				.append(".card{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:16px 20px;margin-bottom:20px}\n")
				.append(".card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px}\n")
				.append(".card-title-group{display:flex;align-items:center;gap:10px;flex-wrap:wrap}\n")
				.append(".card-actions{display:flex;align-items:center;gap:8px}\n")
				.append(".valve-name{font-size:15px;font-weight:700}\n")
				.append(".btn{display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;text-decoration:none;cursor:pointer;border:1px solid var(--border);color:var(--text);background:#0b1120}\n")
				.append(".btn:hover{background:#1e293b;border-color:var(--accent);color:var(--accent)}\n")
				.append(".badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;letter-spacing:0.5px}\n")
				.append(".badge-blocking{background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d}\n")
				.append(".badge-marking{background:#172554;color:#93c5fd;border:1px solid #1e40af}\n")
				.append(".badge-warn{background:#422006;color:#fde047;border:1px solid #713f12}\n")
				.append(".badge-info{background:#0b1329;color:#7dd3fc;border:1px solid #0369a1}\n")
				.append("table{width:100%;border-collapse:collapse;margin-top:6px}\n")
				.append("th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border)}\n")
				.append("th{color:var(--muted);font-weight:500;width:30%;vertical-align:top}\n")
				.append("td{color:var(--text)}\n")
				.append(".data-table{width:100%;border-collapse:collapse;margin-top:6px}\n")
				.append(".data-table th{background:#0b1120;color:var(--muted);font-weight:600;padding:6px 10px;border-bottom:1px solid var(--border);width:auto;text-align:left}\n")
				.append(".data-table td{padding:6px 10px;border-bottom:1px solid var(--border)}\n")
				.append("code{background:#0b1120;padding:2px 6px;border-radius:4px;color:#cbd5e1;border:1px solid #1e293b}\n")
				.append(".metric-bar{background:#0b1120;border-radius:3px;height:8px;width:120px;display:inline-block;vertical-align:middle;overflow:hidden;margin-left:8px;border:1px solid var(--border)}\n")
				.append(".metric-fill{height:100%;background:var(--accent)}\n")
				.append(".metric-fill.high{background:var(--red)}\n")
				.append(".metric-fill.med{background:var(--yellow)}\n")
				.append("</style>\n</head>\n<body>\n")
				.append("<div class=\"header\">\n")
				.append("  <div class=\"title\"><span>&#9889;</span> Anti-DoS Valve Monitor</div>\n")
				.append("  <div class=\"subtitle\"><span>Server Time: ").append(serverTime)
				.append(" &bull; Active Valves: ").append(valves.size()).append("</span>")
				.append("<a class=\"btn\" href=\"").append(buildDashboardUrl(token, null, null, "json")).append("\">{ } JSON (All)</a>")
				.append("</div>\n")
				.append("</div>\n");

		int renderedCount = 0;
		for (AntiDoSValve v : valves) {
			if (filterValve != null && !filterValve.trim().isEmpty()) {
				if (!v.getMonitorName().equalsIgnoreCase(filterValve.trim())) {
					continue;
				}
			}
			renderedCount++;

			AntiDoSMonitor monitor = v.provideMonitor();
			int activeCounters = monitor != null ? monitor.getCurrentActiveCounterCount() : 0;
			int blockedCounters = monitor != null ? monitor.getCurrentBlockedCounterCount() : 0;
			long totalReqs = monitor != null ? monitor.getTotalrequests() : 0;
			int activeSlots = monitor != null ? monitor.getNumberOfActiveSlots() : 0;

			int maxActive = v.getMaxIPCacheSize();
			int maxBlocked = v.getMaxBlockedIPCacheSize() > 0 ? v.getMaxBlockedIPCacheSize() : maxActive;

			double activeRatio = maxActive > 0 ? (double) activeCounters / maxActive : 0.0;
			double blockedRatio = maxBlocked > 0 ? (double) blockedCounters / maxBlocked : 0.0;

			int activePercent = (int) Math.min(100, Math.round(activeRatio * 100));
			int blockedPercent = (int) Math.min(100, Math.round(blockedRatio * 100));

			String activeFillClass = activePercent > 85 ? "high" : (activePercent > 50 ? "med" : "");
			String blockedFillClass = blockedPercent > 85 ? "high" : (blockedPercent > 50 ? "med" : "");

			sb.append("<div class=\"card\">\n")
					.append("  <div class=\"card-header\">\n")
					.append("    <div class=\"card-title-group\">\n")
					.append("      <span class=\"valve-name\">").append(escapeHtml(v.getName4logging())).append("</span>\n");

			if (v.isMonitorModeDefault()) {
				sb.append("      <span class=\"badge badge-blocking\">MODE: BLOCKING (").append(v.getHttpStatusCode()).append(")</span>\n");
			} else {
				sb.append("      <span class=\"badge badge-marking\">MODE: MARKING</span>\n");
			}

			if (v.isSimulationMode()) {
				sb.append("      <span class=\"badge badge-warn\">SIMULATION MODE</span>\n");
			}
			if (v.isServerWideBlocking()) {
				sb.append("      <span class=\"badge badge-warn\">SERVER-WIDE BLOCKING</span>\n");
			}

			sb.append("    </div>\n")
					.append("    <div class=\"card-actions\">\n")
					.append("      <a class=\"btn\" href=\"").append(buildDashboardUrl(token, v.getMonitorName(), "details", null)).append("\">&#128269; Details &amp; Caches</a>\n")
					.append("      <a class=\"btn\" href=\"").append(buildDashboardUrl(token, v.getMonitorName(), null, "json")).append("\">{ } JSON</a>\n")
					.append("    </div>\n")
					.append("  </div>\n")
					.append("  <table>\n");

			// Relevant & non-relevant paths
			sb.append("    <tr><th>Relevant Paths</th><td>")
					.append(v.getRelevantPathsConfigValue() != null ? "<code>" + escapeHtml(v.getRelevantPathsConfigValue()) + "</code>" : "<em>none (no requests monitored)</em>")
					.append("</td></tr>\n");

			if (v.getNonRelevantPathsConfigValue() != null) {
				sb.append("    <tr><th>Non-Relevant Paths</th><td><code>").append(escapeHtml(v.getNonRelevantPathsConfigValue())).append("</code></td></tr>\n");
			}

			if (v.getAlwaysAllowedIPsConfigValue() != null) {
				sb.append("    <tr><th>Always Allowed IPs</th><td><code>").append(escapeHtml(v.getAlwaysAllowedIPsConfigValue())).append("</code></td></tr>\n");
			}
			if (v.getAlwaysForbiddenIPsConfigValue() != null) {
				sb.append("    <tr><th>Always Forbidden IPs</th><td><code>").append(escapeHtml(v.getAlwaysForbiddenIPsConfigValue())).append("</code></td></tr>\n");
			}

			// Rate limit parameters
			int retentionPct = Math.round(v.getShareOfRetainedFormerRequests() * 100);
			sb.append("    <tr><th>Rate Limit</th><td><strong>").append(v.getAllowedRequestsPerSlot())
					.append("</strong> req / <strong>").append(v.getSlotLength()).append("s</strong> slot (Slots: ")
					.append(v.getNumberOfSlots()).append(", Retention: ").append(retentionPct).append("%)</td></tr>\n");

			// Subnet masks
			String v4Str = v.getIpv4SubnetMask() == 32 ? "single IP (/32, no aggregation)" : "/" + v.getIpv4SubnetMask();
			String v6Str = v.getIpv6SubnetMask() == 128 ? "single IP (/128, no aggregation)" : "/" + v.getIpv6SubnetMask();
			sb.append("    <tr><th>Subnet Aggregation</th><td>IPv4: <code>").append(v4Str)
					.append("</code> &bull; IPv6: <code>").append(v6Str).append("</code></td></tr>\n");

			// Cache usage & slots
			sb.append("    <tr><th>Active IP Cache</th><td>").append(activeCounters).append(" / ").append(maxActive)
					.append(" <div class=\"metric-bar\"><div class=\"metric-fill ").append(activeFillClass)
					.append("\" style=\"width:").append(activePercent).append("%\"></div></div></td></tr>\n");

			sb.append("    <tr><th>Blocked IP Cache</th><td>").append(blockedCounters).append(" / ").append(maxBlocked)
					.append(" <div class=\"metric-bar\"><div class=\"metric-fill ").append(blockedFillClass)
					.append("\" style=\"width:").append(blockedPercent).append("%\"></div></div></td></tr>\n");

			sb.append("    <tr><th>Total Requests Processed</th><td><strong>").append(totalReqs)
					.append("</strong> (Active Slots: ").append(activeSlots).append(" / ").append(v.getNumberOfSlots()).append(")</td></tr>\n");

			// Log Throttling & Async Eviction
			String logThrottling = v.getMaxBlockLogsPerSecond() >= 0 ? v.getMaxBlockLogsPerSecond() + " logs/s" : "disabled";
			String asyncEvict = v.getAsyncEviction() == null ? "auto" : v.getAsyncEviction().toString();
			sb.append("    <tr><th>System Settings</th><td>Log Throttling: <code>").append(logThrottling)
					.append("</code> &bull; Async Eviction: <code>").append(asyncEvict).append("</code></td></tr>\n");

			sb.append("  </table>\n</div>\n");
		}

		if (renderedCount == 0) {
			sb.append("<div class=\"card\"><div class=\"card-header\"><span class=\"valve-name\">No valves matched the filter: ")
					.append(escapeHtml(filterValve)).append("</span></div></div>\n");
		}

		sb.append("</body>\n</html>\n");
		return sb.toString();
	}

	String buildStatusHtmlDetails(String valveName, String token) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		sdf.setTimeZone(TimeZone.getDefault());
		String serverTime = sdf.format(new Date(getTimeInMillis()));

		AntiDoSValve target = null;
		Set<AntiDoSValve> valves = getValvesToRender();
		if (valveName != null && !valveName.trim().isEmpty()) {
			for (AntiDoSValve v : valves) {
				if (v.getMonitorName().equalsIgnoreCase(valveName.trim())) {
					target = v;
					break;
				}
			}
		} else if (valves.size() == 1) {
			target = valves.iterator().next();
		}

		StringBuilder sb = new StringBuilder(6144);
		sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
				.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
				.append("<title>Anti-DoS Valve Monitor - ").append(target != null ? escapeHtml(target.getMonitorName()) : "Details").append("</title>\n")
				.append("<style>\n")
				.append(":root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--border:#334155;--accent:#38bdf8;--green:#22c55e;--red:#ef4444;--yellow:#eab308}\n")
				.append("body{font-family:ui-monospace,\"SF Mono\",Menlo,Consolas,\"Liberation Mono\",monospace;background:var(--bg);color:var(--text);margin:0;padding:24px;font-size:13px;line-height:1.5}\n")
				.append(".header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:12px;margin-bottom:24px;flex-wrap:wrap;gap:8px}\n")
				.append(".title{font-size:16px;font-weight:700;color:var(--accent);display:flex;align-items:center;gap:8px}\n")
				.append(".subtitle{color:var(--muted);font-size:12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}\n")
				.append(".card{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:16px 20px;margin-bottom:20px}\n")
				.append(".card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px}\n")
				.append(".card-title-group{display:flex;align-items:center;gap:10px;flex-wrap:wrap}\n")
				.append(".card-actions{display:flex;align-items:center;gap:8px}\n")
				.append(".valve-name{font-size:15px;font-weight:700}\n")
				.append(".btn{display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;text-decoration:none;cursor:pointer;border:1px solid var(--border);color:var(--text);background:#0b1120}\n")
				.append(".btn:hover{background:#1e293b;border-color:var(--accent);color:var(--accent)}\n")
				.append(".badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;letter-spacing:0.5px}\n")
				.append(".badge-blocking{background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d}\n")
				.append(".badge-marking{background:#172554;color:#93c5fd;border:1px solid #1e40af}\n")
				.append(".badge-warn{background:#422006;color:#fde047;border:1px solid #713f12}\n")
				.append(".badge-info{background:#0b1329;color:#7dd3fc;border:1px solid #0369a1}\n")
				.append("table{width:100%;border-collapse:collapse;margin-top:6px}\n")
				.append("th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border)}\n")
				.append("th{color:var(--muted);font-weight:500;width:30%;vertical-align:top}\n")
				.append("td{color:var(--text)}\n")
				.append(".data-table{width:100%;border-collapse:collapse;margin-top:6px}\n")
				.append(".data-table th{background:#0b1120;color:var(--muted);font-weight:600;padding:6px 10px;border-bottom:1px solid var(--border);width:auto;text-align:left}\n")
				.append(".data-table td{padding:6px 10px;border-bottom:1px solid var(--border)}\n")
				.append("code{background:#0b1120;padding:2px 6px;border-radius:4px;color:#cbd5e1;border:1px solid #1e293b}\n")
				.append(".metric-bar{background:#0b1120;border-radius:3px;height:8px;width:120px;display:inline-block;vertical-align:middle;overflow:hidden;margin-left:8px;border:1px solid var(--border)}\n")
				.append(".metric-fill{height:100%;background:var(--accent)}\n")
				.append(".metric-fill.high{background:var(--red)}\n")
				.append(".metric-fill.med{background:var(--yellow)}\n")
				.append("</style>\n</head>\n<body>\n");

		if (target == null) {
			sb.append("<div class=\"header\">\n")
					.append("  <div class=\"title\"><span>&#9889;</span> Anti-DoS Valve Monitor &bull; Details</div>\n")
					.append("  <div class=\"subtitle\"><a class=\"btn\" href=\"").append(buildDashboardUrl(token, null, null, null)).append("\">&#8592; Back to Overview</a></div>\n")
					.append("</div>\n")
					.append("<div class=\"card\"><div class=\"card-header\"><span class=\"valve-name\">Valve not found: ")
					.append(escapeHtml(valveName)).append("</span></div></div>\n")
					.append("</body>\n</html>\n");
			return sb.toString();
		}

		AntiDoSMonitor monitor = target.provideMonitor();
		int activeCounters = monitor != null ? monitor.getCurrentActiveCounterCount() : 0;
		int blockedCounters = monitor != null ? monitor.getCurrentBlockedCounterCount() : 0;
		long totalReqs = monitor != null ? monitor.getTotalrequests() : 0;
		int activeSlots = monitor != null ? monitor.getNumberOfActiveSlots() : 0;
		int numSlots = monitor != null ? monitor.getNumberOfSlots() : target.getNumberOfSlots();
		int slotLength = monitor != null ? monitor.getSlotLength() : target.getSlotLength();
		long currentSlotKey = monitor != null ? monitor.getCurrentSlotKey() : 0;
		int allowedReqs = target.getAllowedRequestsPerSlot();

		int maxActive = target.getMaxIPCacheSize();
		int maxBlocked = target.getMaxBlockedIPCacheSize() > 0 ? target.getMaxBlockedIPCacheSize() : maxActive;
		double activeRatio = maxActive > 0 ? (double) activeCounters / maxActive : 0.0;
		double blockedRatio = maxBlocked > 0 ? (double) blockedCounters / maxBlocked : 0.0;
		int activePercent = (int) Math.min(100, Math.round(activeRatio * 100));
		int blockedPercent = (int) Math.min(100, Math.round(blockedRatio * 100));
		String activeFillClass = activePercent > 85 ? "high" : (activePercent > 50 ? "med" : "");
		String blockedFillClass = blockedPercent > 85 ? "high" : (blockedPercent > 50 ? "med" : "");

		// Header
		sb.append("<div class=\"header\">\n")
				.append("  <div class=\"title\"><span>&#9889;</span> Anti-DoS Valve Monitor &bull; <span>").append(escapeHtml(target.getName4logging())).append(" Details</span></div>\n")
				.append("  <div class=\"subtitle\">\n")
				.append("    <span>Server Time: ").append(serverTime).append("</span>\n")
				.append("    <a class=\"btn\" href=\"").append(buildDashboardUrl(token, null, null, null)).append("\">&#8592; Back to Overview</a>\n")
				.append("    <a class=\"btn\" href=\"").append(buildDashboardUrl(token, target.getMonitorName(), "details", null)).append("\">&#128260; Refresh</a>\n")
				.append("    <a class=\"btn\" href=\"").append(buildDashboardUrl(token, target.getMonitorName(), "details", "json")).append("\">{ } JSON Details</a>\n")
				.append("  </div>\n")
				.append("</div>\n");

		// Card 1: Configuration & Status Summary
		sb.append("<div class=\"card\">\n")
				.append("  <div class=\"card-header\">\n")
				.append("    <div class=\"card-title-group\">\n")
				.append("      <span class=\"valve-name\">Configuration &amp; Metrics Summary</span>\n");

		if (target.isMonitorModeDefault()) {
			sb.append("      <span class=\"badge badge-blocking\">MODE: BLOCKING (").append(target.getHttpStatusCode()).append(")</span>\n");
		} else {
			sb.append("      <span class=\"badge badge-marking\">MODE: MARKING</span>\n");
		}
		if (target.isSimulationMode()) {
			sb.append("      <span class=\"badge badge-warn\">SIMULATION MODE</span>\n");
		}
		if (target.isServerWideBlocking()) {
			sb.append("      <span class=\"badge badge-warn\">SERVER-WIDE BLOCKING</span>\n");
		}

		sb.append("    </div>\n")
				.append("  </div>\n")
				.append("  <table>\n")
				.append("    <tr><th>Relevant Paths</th><td>")
				.append(target.getRelevantPathsConfigValue() != null ? "<code>" + escapeHtml(target.getRelevantPathsConfigValue()) + "</code>" : "<em>none (no requests monitored)</em>")
				.append("</td></tr>\n");

		if (target.getNonRelevantPathsConfigValue() != null) {
			sb.append("    <tr><th>Non-Relevant Paths</th><td><code>").append(escapeHtml(target.getNonRelevantPathsConfigValue())).append("</code></td></tr>\n");
		}
		if (target.getAlwaysAllowedIPsConfigValue() != null) {
			sb.append("    <tr><th>Always Allowed IPs</th><td><code>").append(escapeHtml(target.getAlwaysAllowedIPsConfigValue())).append("</code></td></tr>\n");
		}
		if (target.getAlwaysForbiddenIPsConfigValue() != null) {
			sb.append("    <tr><th>Always Forbidden IPs</th><td><code>").append(escapeHtml(target.getAlwaysForbiddenIPsConfigValue())).append("</code></td></tr>\n");
		}

		int retentionPct = Math.round(target.getShareOfRetainedFormerRequests() * 100);
		sb.append("    <tr><th>Rate Limit</th><td><strong>").append(target.getAllowedRequestsPerSlot())
				.append("</strong> req / <strong>").append(target.getSlotLength()).append("s</strong> slot (Slots: ")
				.append(target.getNumberOfSlots()).append(", Retention: ").append(retentionPct).append("%)</td></tr>\n");

		String v4Str = target.getIpv4SubnetMask() == 32 ? "single IP (/32, no aggregation)" : "/" + target.getIpv4SubnetMask();
		String v6Str = target.getIpv6SubnetMask() == 128 ? "single IP (/128, no aggregation)" : "/" + target.getIpv6SubnetMask();
		sb.append("    <tr><th>Subnet Aggregation</th><td>IPv4: <code>").append(v4Str)
				.append("</code> &bull; IPv6: <code>").append(v6Str).append("</code></td></tr>\n");

		sb.append("    <tr><th>Active IP Cache</th><td>").append(activeCounters).append(" / ").append(maxActive)
				.append(" <div class=\"metric-bar\"><div class=\"metric-fill ").append(activeFillClass)
				.append("\" style=\"width:").append(activePercent).append("%\"></div></div></td></tr>\n");

		sb.append("    <tr><th>Blocked IP Cache</th><td>").append(blockedCounters).append(" / ").append(maxBlocked)
				.append(" <div class=\"metric-bar\"><div class=\"metric-fill ").append(blockedFillClass)
				.append("\" style=\"width:").append(blockedPercent).append("%\"></div></div></td></tr>\n");

		sb.append("    <tr><th>Total Requests Processed</th><td><strong>").append(totalReqs)
				.append("</strong> (Active Slots: ").append(activeSlots).append(" / ").append(target.getNumberOfSlots()).append(")</td></tr>\n");

		String logThrottling = target.getMaxBlockLogsPerSecond() >= 0 ? target.getMaxBlockLogsPerSecond() + " logs/s" : "disabled";
		String asyncEvict = target.getAsyncEviction() == null ? "auto" : target.getAsyncEviction().toString();
		sb.append("    <tr><th>System Settings</th><td>Log Throttling: <code>").append(logThrottling)
				.append("</code> &bull; Async Eviction: <code>").append(asyncEvict).append("</code></td></tr>\n");

		sb.append("  </table>\n</div>\n");

		// Card 2: Slot Timeline
		sb.append("<div class=\"card\">\n")
				.append("  <div class=\"card-header\"><div class=\"card-title-group\"><span class=\"valve-name\">Slot Ring Buffer Timeline</span>")
				.append(" <span class=\"subtitle\">(").append(numSlots).append(" slots &bull; ").append(slotLength / 1000).append("s each)</span></div></div>\n")
				.append("  <table class=\"data-table\">\n")
				.append("    <thead><tr><th>Slot #</th><th>Slot Key</th><th>Start Time</th><th>Age</th><th>Status</th><th>Active IPs</th><th>Blocked IPs</th></tr></thead>\n")
				.append("    <tbody>\n");

		if (monitor != null) {
			for (int i = 0; i < numSlots; i++) {
				AntiDoSSlot slot = monitor.getSlot(i);
				if (slot == null) {
					sb.append("      <tr><td>#").append(i).append("</td><td>-</td><td>-</td><td>-</td>")
							.append("<td><span class=\"badge\">EMPTY</span></td><td>0</td><td>0</td></tr>\n");
				} else {
					long slotKey = slot.getSlotKey();
					boolean isCurrent = (slotKey == currentSlotKey);
					long ageSec = (currentSlotKey - slotKey) * (slotLength / 1000);
					String ageStr = isCurrent ? "current" : (ageSec + "s ago");
					String statusBadge;
					if (isCurrent) {
						statusBadge = "<span class=\"badge badge-info\">CURRENT</span>";
					} else if (currentSlotKey > slotKey && (currentSlotKey - slotKey) < numSlots) {
						statusBadge = "<span class=\"badge badge-marking\">HISTORICAL (-" + (currentSlotKey - slotKey) + " slots)</span>";
					} else {
						statusBadge = "<span class=\"badge badge-warn\">EXPIRED</span>";
					}
					String startTime = sdf.format(new Date(slotKey * slotLength));
					String rowStyle = isCurrent ? " style=\"background:rgba(56,189,248,0.06);font-weight:600;\"" : "";

					sb.append("      <tr").append(rowStyle).append("><td>#").append(i)
							.append("</td><td>").append(slotKey)
							.append("</td><td>").append(startTime)
							.append("</td><td>").append(ageStr)
							.append("</td><td>").append(statusBadge)
							.append("</td><td>").append(slot.getActiveCounterCount())
							.append("</td><td>").append(slot.getBlockedCounterCount())
							.append("</td></tr>\n");
				}
			}
		}
		sb.append("    </tbody>\n  </table>\n</div>\n");

		// Card 3: Blocked Clients
		AntiDoSSlot currentSlot = monitor != null ? monitor.getCurrentSlotIfExists() : null;
		List<CounterEntry> blockedList = new ArrayList<>();
		if (currentSlot != null) {
			for (Map.Entry<String, AntiDoSCounter> entry : currentSlot.getBlockedCounters().entrySet()) {
				AntiDoSCounter c = entry.getValue();
				int count = c.getCount();
				int retained = c.getRetainedCounts();
				blockedList.add(new CounterEntry(entry.getKey(), count, retained, count + retained, true));
			}
			Collections.sort(blockedList);
		}

		int blockedTotal = blockedList.size();
		int blockedDisplay = Math.min(blockedTotal, 50);

		sb.append("<div class=\"card\">\n")
				.append("  <div class=\"card-header\"><div class=\"card-title-group\"><span class=\"valve-name\">Blocked Clients (Current Slot)</span>")
				.append(" <span class=\"subtitle\">(").append(blockedDisplay).append(blockedTotal > 50 ? " of " + blockedTotal : "").append(" entries)</span></div></div>\n");

		if (blockedDisplay == 0) {
			sb.append("  <div style=\"color:var(--muted);padding:4px 0;\">No blocked clients in current slot.</div>\n");
		} else {
			sb.append("  <table class=\"data-table\">\n")
					.append("    <thead><tr><th>IP / Subnet Key</th><th>Slot Requests</th><th>Retained</th><th>Effective</th><th>Limit</th><th>Status</th></tr></thead>\n")
					.append("    <tbody>\n");
			for (int i = 0; i < blockedDisplay; i++) {
				CounterEntry e = blockedList.get(i);
				sb.append("      <tr><td><code>").append(escapeHtml(e.key())).append("</code></td>")
						.append("<td>").append(e.count()).append("</td>")
						.append("<td>").append(e.retained()).append("</td>")
						.append("<td><strong>").append(e.effective()).append("</strong></td>")
						.append("<td>").append(allowedReqs).append("</td>")
						.append("<td><span class=\"badge badge-blocking\">BLOCKED</span></td></tr>\n");
			}
			sb.append("    </tbody>\n  </table>\n");
		}
		sb.append("</div>\n");

		// Card 4: Top Active Clients
		List<CounterEntry> activeList = new ArrayList<>();
		if (currentSlot != null) {
			for (Map.Entry<String, AntiDoSCounter> entry : currentSlot.getActiveCounters().entrySet()) {
				AntiDoSCounter c = entry.getValue();
				int count = c.getCount();
				int retained = c.getRetainedCounts();
				activeList.add(new CounterEntry(entry.getKey(), count, retained, count + retained, false));
			}
			Collections.sort(activeList);
		}

		int activeTotal = activeList.size();
		int activeDisplay = Math.min(activeTotal, 50);

		sb.append("<div class=\"card\">\n")
				.append("  <div class=\"card-header\"><div class=\"card-title-group\"><span class=\"valve-name\">Top Active Clients (Current Slot)</span>")
				.append(" <span class=\"subtitle\">(").append(activeDisplay).append(activeTotal > 50 ? " of " + activeTotal : "").append(" entries)</span></div></div>\n");

		if (activeDisplay == 0) {
			sb.append("  <div style=\"color:var(--muted);padding:4px 0;\">No active clients in current slot.</div>\n");
		} else {
			sb.append("  <table class=\"data-table\">\n")
					.append("    <thead><tr><th>IP / Subnet Key</th><th>Slot Requests</th><th>Retained</th><th>Effective</th><th>Limit</th><th>Quota Usage</th></tr></thead>\n")
					.append("    <tbody>\n");
			for (int i = 0; i < activeDisplay; i++) {
				CounterEntry e = activeList.get(i);
				int pct = allowedReqs > 0 ? (int) Math.min(100, Math.round((double) e.effective() / allowedReqs * 100)) : 0;
				String fillClass = pct > 85 ? "high" : (pct > 50 ? "med" : "");
				sb.append("      <tr><td><code>").append(escapeHtml(e.key())).append("</code></td>")
						.append("<td>").append(e.count()).append("</td>")
						.append("<td>").append(e.retained()).append("</td>")
						.append("<td><strong>").append(e.effective()).append("</strong></td>")
						.append("<td>").append(allowedReqs).append("</td>")
						.append("<td>").append(pct).append("% <div class=\"metric-bar\"><div class=\"metric-fill ").append(fillClass)
						.append("\" style=\"width:").append(pct).append("%\"></div></div></td></tr>\n");
			}
			sb.append("    </tbody>\n  </table>\n");
		}
		sb.append("</div>\n");

		sb.append("</body>\n</html>\n");
		return sb.toString();
	}

	String buildStatusJson(String filterValve) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String serverTime = sdf.format(new Date(getTimeInMillis()));

		Set<AntiDoSValve> valves = getValvesToRender();

		StringBuilder sb = new StringBuilder(2048);
		sb.append("{\n  \"serverTime\": \"").append(serverTime).append("\",\n");
		sb.append("  \"totalActiveValves\": ").append(valves.size()).append(",\n");
		sb.append("  \"valves\": [\n");

		boolean first = true;
		for (AntiDoSValve v : valves) {
			if (filterValve != null && !filterValve.trim().isEmpty()) {
				if (!v.getMonitorName().equalsIgnoreCase(filterValve.trim())) {
					continue;
				}
			}
			if (!first) {
				sb.append(",\n");
			}
			first = false;

			AntiDoSMonitor monitor = v.provideMonitor();
			int activeCounters = monitor != null ? monitor.getCurrentActiveCounterCount() : 0;
			int blockedCounters = monitor != null ? monitor.getCurrentBlockedCounterCount() : 0;
			long totalReqs = monitor != null ? monitor.getTotalrequests() : 0;
			int activeSlots = monitor != null ? monitor.getNumberOfActiveSlots() : 0;

			int maxActive = v.getMaxIPCacheSize();
			int maxBlocked = v.getMaxBlockedIPCacheSize() > 0 ? v.getMaxBlockedIPCacheSize() : maxActive;

			sb.append("    {\n")
					.append("      \"monitorName\": \"").append(escapeJson(v.getMonitorName())).append("\",\n")
					.append("      \"monitorMode\": \"").append(escapeJson(v.getMonitorMode())).append("\",\n")
					.append("      \"simulationMode\": ").append(v.isSimulationMode()).append(",\n")
					.append("      \"serverWideBlocking\": ").append(v.isServerWideBlocking()).append(",\n")
					.append("      \"relevantPaths\": ").append(v.getRelevantPathsConfigValue() != null ? "\"" + escapeJson(v.getRelevantPathsConfigValue()) + "\"" : "null").append(",\n")
					.append("      \"nonRelevantPaths\": ").append(v.getNonRelevantPathsConfigValue() != null ? "\"" + escapeJson(v.getNonRelevantPathsConfigValue()) + "\"" : "null").append(",\n")
					.append("      \"allowedRequestsPerSlot\": ").append(v.getAllowedRequestsPerSlot()).append(",\n")
					.append("      \"slotLength\": ").append(v.getSlotLength()).append(",\n")
					.append("      \"numberOfSlots\": ").append(v.getNumberOfSlots()).append(",\n")
					.append("      \"shareOfRetainedFormerRequests\": ").append(v.getShareOfRetainedFormerRequests()).append(",\n")
					.append("      \"ipv4SubnetMask\": ").append(v.getIpv4SubnetMask()).append(",\n")
					.append("      \"ipv6SubnetMask\": ").append(v.getIpv6SubnetMask()).append(",\n")
					.append("      \"maxIPCacheSize\": ").append(maxActive).append(",\n")
					.append("      \"maxBlockedIPCacheSize\": ").append(maxBlocked).append(",\n")
					.append("      \"currentActiveCounters\": ").append(activeCounters).append(",\n")
					.append("      \"currentBlockedCounters\": ").append(blockedCounters).append(",\n")
					.append("      \"totalRequests\": ").append(totalReqs).append(",\n")
					.append("      \"activeSlots\": ").append(activeSlots).append(",\n")
					.append("      \"httpStatusCode\": ").append(v.getHttpStatusCode()).append("\n")
					.append("    }");
		}

		sb.append("\n  ]\n}\n");
		return sb.toString();
	}

	String buildStatusJsonDetails(String filterValve) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String serverTime = sdf.format(new Date(getTimeInMillis()));

		AntiDoSValve target = null;
		Set<AntiDoSValve> valves = getValvesToRender();
		if (filterValve != null && !filterValve.trim().isEmpty()) {
			for (AntiDoSValve v : valves) {
				if (v.getMonitorName().equalsIgnoreCase(filterValve.trim())) {
					target = v;
					break;
				}
			}
		} else if (valves.size() == 1) {
			target = valves.iterator().next();
		}

		if (target == null) {
			return "{\n  \"serverTime\": \"" + serverTime + "\",\n  \"error\": \"Valve not found: " + escapeJson(filterValve) + "\"\n}\n";
		}

		AntiDoSMonitor monitor = target.provideMonitor();
		int activeCounters = monitor != null ? monitor.getCurrentActiveCounterCount() : 0;
		int blockedCounters = monitor != null ? monitor.getCurrentBlockedCounterCount() : 0;
		long totalReqs = monitor != null ? monitor.getTotalrequests() : 0;
		int activeSlots = monitor != null ? monitor.getNumberOfActiveSlots() : 0;
		int maxActive = target.getMaxIPCacheSize();
		int maxBlocked = target.getMaxBlockedIPCacheSize() > 0 ? target.getMaxBlockedIPCacheSize() : maxActive;

		StringBuilder sb = new StringBuilder(4096);
		sb.append("{\n  \"serverTime\": \"").append(serverTime).append("\",\n");
		sb.append("  \"valve\": {\n")
				.append("    \"monitorName\": \"").append(escapeJson(target.getMonitorName())).append("\",\n")
				.append("    \"monitorMode\": \"").append(escapeJson(target.getMonitorMode())).append("\",\n")
				.append("    \"simulationMode\": ").append(target.isSimulationMode()).append(",\n")
				.append("    \"serverWideBlocking\": ").append(target.isServerWideBlocking()).append(",\n")
				.append("    \"relevantPaths\": ").append(target.getRelevantPathsConfigValue() != null ? "\"" + escapeJson(target.getRelevantPathsConfigValue()) + "\"" : "null").append(",\n")
				.append("    \"nonRelevantPaths\": ").append(target.getNonRelevantPathsConfigValue() != null ? "\"" + escapeJson(target.getNonRelevantPathsConfigValue()) + "\"" : "null").append(",\n")
				.append("    \"allowedRequestsPerSlot\": ").append(target.getAllowedRequestsPerSlot()).append(",\n")
				.append("    \"slotLength\": ").append(target.getSlotLength()).append(",\n")
				.append("    \"numberOfSlots\": ").append(target.getNumberOfSlots()).append(",\n")
				.append("    \"shareOfRetainedFormerRequests\": ").append(target.getShareOfRetainedFormerRequests()).append(",\n")
				.append("    \"ipv4SubnetMask\": ").append(target.getIpv4SubnetMask()).append(",\n")
				.append("    \"ipv6SubnetMask\": ").append(target.getIpv6SubnetMask()).append(",\n")
				.append("    \"maxIPCacheSize\": ").append(maxActive).append(",\n")
				.append("    \"maxBlockedIPCacheSize\": ").append(maxBlocked).append(",\n")
				.append("    \"currentActiveCounters\": ").append(activeCounters).append(",\n")
				.append("    \"currentBlockedCounters\": ").append(blockedCounters).append(",\n")
				.append("    \"totalRequests\": ").append(totalReqs).append(",\n")
				.append("    \"activeSlots\": ").append(activeSlots).append(",\n")
				.append("    \"httpStatusCode\": ").append(target.getHttpStatusCode()).append("\n")
				.append("  },\n");

		// Slots array
		int numSlots = monitor != null ? monitor.getNumberOfSlots() : target.getNumberOfSlots();
		long currentSlotKey = monitor != null ? monitor.getCurrentSlotKey() : 0;
		int slotLength = monitor != null ? monitor.getSlotLength() : target.getSlotLength();
		sb.append("  \"slots\": [\n");
		boolean firstSlot = true;
		if (monitor != null) {
			for (int i = 0; i < numSlots; i++) {
				AntiDoSSlot slot = monitor.getSlot(i);
				if (!firstSlot) sb.append(",\n");
				firstSlot = false;
				if (slot == null) {
					sb.append("    {\"index\": ").append(i).append(", \"slotKey\": null}");
				} else {
					long slotKey = slot.getSlotKey();
					boolean isCurrent = (slotKey == currentSlotKey);
					long ageSec = (currentSlotKey - slotKey) * (slotLength / 1000);
					String startTime = sdf.format(new Date(slotKey * slotLength));
					sb.append("    {\n")
							.append("      \"index\": ").append(i).append(",\n")
							.append("      \"slotKey\": ").append(slotKey).append(",\n")
							.append("      \"isCurrent\": ").append(isCurrent).append(",\n")
							.append("      \"startTime\": \"").append(startTime).append("\",\n")
							.append("      \"ageSeconds\": ").append(ageSec).append(",\n")
							.append("      \"activeCounters\": ").append(slot.getActiveCounterCount()).append(",\n")
							.append("      \"blockedCounters\": ").append(slot.getBlockedCounterCount()).append("\n")
							.append("    }");
				}
			}
		}
		sb.append("\n  ],\n");

		// Blocked clients array
		AntiDoSSlot currentSlot = monitor != null ? monitor.getCurrentSlotIfExists() : null;
		List<CounterEntry> blockedList = new ArrayList<>();
		if (currentSlot != null) {
			for (Map.Entry<String, AntiDoSCounter> entry : currentSlot.getBlockedCounters().entrySet()) {
				AntiDoSCounter c = entry.getValue();
				int count = c.getCount();
				int retained = c.getRetainedCounts();
				blockedList.add(new CounterEntry(entry.getKey(), count, retained, count + retained, true));
			}
			Collections.sort(blockedList);
		}
		sb.append("  \"blockedClients\": [\n");
		int bLimit = Math.min(blockedList.size(), 50);
		for (int i = 0; i < bLimit; i++) {
			if (i > 0) sb.append(",\n");
			CounterEntry e = blockedList.get(i);
			sb.append("    {\n")
					.append("      \"key\": \"").append(escapeJson(e.key())).append("\",\n")
					.append("      \"count\": ").append(e.count()).append(",\n")
					.append("      \"retained\": ").append(e.retained()).append(",\n")
					.append("      \"effective\": ").append(e.effective()).append(",\n")
					.append("      \"limit\": ").append(target.getAllowedRequestsPerSlot()).append(",\n")
					.append("      \"status\": \"BLOCKED\"\n")
					.append("    }");
		}
		sb.append("\n  ],\n");

		// Top active clients array
		List<CounterEntry> activeList = new ArrayList<>();
		if (currentSlot != null) {
			for (Map.Entry<String, AntiDoSCounter> entry : currentSlot.getActiveCounters().entrySet()) {
				AntiDoSCounter c = entry.getValue();
				int count = c.getCount();
				int retained = c.getRetainedCounts();
				activeList.add(new CounterEntry(entry.getKey(), count, retained, count + retained, false));
			}
			Collections.sort(activeList);
		}
		sb.append("  \"topActiveClients\": [\n");
		int aLimit = Math.min(activeList.size(), 50);
		for (int i = 0; i < aLimit; i++) {
			if (i > 0) sb.append(",\n");
			CounterEntry e = activeList.get(i);
			int pct = target.getAllowedRequestsPerSlot() > 0
					? (int) Math.min(100, Math.round((double) e.effective() / target.getAllowedRequestsPerSlot() * 100))
					: 0;
			sb.append("    {\n")
					.append("      \"key\": \"").append(escapeJson(e.key())).append("\",\n")
					.append("      \"count\": ").append(e.count()).append(",\n")
					.append("      \"retained\": ").append(e.retained()).append(",\n")
					.append("      \"effective\": ").append(e.effective()).append(",\n")
					.append("      \"limit\": ").append(target.getAllowedRequestsPerSlot()).append(",\n")
					.append("      \"quotaPercent\": ").append(pct).append("\n")
					.append("    }");
		}
		sb.append("\n  ]\n}\n");
		return sb.toString();
	}

	static String escapeHtml(String text) {
		if (text == null) return "-";
		StringBuilder sb = new StringBuilder(text.length());
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			switch (c) {
				case '<' -> sb.append("&lt;");
				case '>' -> sb.append("&gt;");
				case '&' -> sb.append("&amp;");
				case '"' -> sb.append("&quot;");
				case '\'' -> sb.append("&#39;");
				default -> sb.append(c);
			}
		}
		return sb.toString();
	}

	static String escapeJson(String text) {
		if (text == null) return "";
		StringBuilder sb = new StringBuilder(text.length());
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			switch (c) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\b' -> sb.append("\\b");
				case '\f' -> sb.append("\\f");
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				default -> {
					if (c < ' ') {
						sb.append(String.format("\\u%04x", (int) c));
					} else {
						sb.append(c);
					}
				}
			}
		}
		return sb.toString();
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
			return !isIPAddressBlocked(ip);
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
		if (ip == null || ip.isEmpty()) {
			throw new IllegalArgumentException("IP address must not be null or empty");
		}
		String counterName = resolveCounterName(ip);
		AntiDoSMonitor monitor = provideMonitor();
		if (monitor == null || monitor.registerAndCheckRequest(counterName)) {
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
