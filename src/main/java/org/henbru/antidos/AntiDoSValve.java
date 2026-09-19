package org.henbru.antidos;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;
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

	private volatile int maxIPCacheSize = -1;
	private volatile int maxBlockedIPCacheSize = -1;
	private volatile int ipv4SubnetMask = 32;
	private volatile int ipv6SubnetMask = 128;
	private volatile int numberOfSlots = -1;
	private volatile int slotLength = -1;
	private volatile int allowedRequestsPerSlot = -1;
	private volatile float shareOfRetainedFormerRequests = -1;
	private volatile boolean simulationMode = false;
	private volatile int httpStatusCode = DEFAULT_HTTP_STATUS_CODE;
	private volatile Boolean asyncEviction = null;

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
		if (!monitors.containsKey(monitorName))
			reloadMonitor();

		return monitors.get(monitorName);
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

	/**
	 * 
	 * @param slotLength The length of the individual slots in seconds
	 */
	public void setSlotLength(int slotLength) {
		this.slotLength = slotLength;
	}

	/**
	 * 
	 * @param allowedRequestsPerSlot The number of requests from one IP address
	 *                               allowed within a slot until it is blocked
	 */
	public void setAllowedRequestsPerSlot(int allowedRequestsPerSlot) {
		this.allowedRequestsPerSlot = allowedRequestsPerSlot;
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
	 * @return <code>true</code> if {@link #getHttpStatusCode()} is a valid HTTP status code
	 */
	public boolean isHttpStatusCodeValid() {
		return httpStatusCode >= 100 && httpStatusCode <= 599;
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
			response.sendError(httpStatusCode);
		} else {
			// mark request:
			response.getRequest().setAttribute(MARKING_ATTRIBUTE_NAME, name4logging);
			getNext().invoke(request, response);
		}
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
	}

	@Override
	protected synchronized void stopInternal() throws LifecycleException {
		super.stopInternal();
		AntiDoSMonitor monitor = provideMonitor();
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
		try {
			int effectiveMaxBlockedIPCacheSize = maxBlockedIPCacheSize > 0 ? maxBlockedIPCacheSize : maxIPCacheSize;
			AntiDoSMonitor monitor = new AntiDoSMonitor(monitorName, maxIPCacheSize, effectiveMaxBlockedIPCacheSize,
					numberOfSlots, slotLength, allowedRequestsPerSlot, shareOfRetainedFormerRequests);

			if (monitorName == null)
				monitorName = DEFAULT_MONITOR_NAME;

			if (asyncEviction != null) {
				monitor.setAsyncEviction(asyncEviction);
			}

			monitors.put(monitorName, monitor);

			if (log.isInfoEnabled()) {
				if (isMonitorModeDefault())
					log.info(name4logging + " is in blocking mode");
				else if (isMonitorModeMarking())
					log.info(name4logging + " is in marking mode");

				if (simulationMode)
					log.info(name4logging + " is in SIMULATION MODE");
			}
			return null;
		} catch (IllegalArgumentException ex) {
			return ex.getMessage();
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
	 * {@link #isRequestURIInRelevantPaths(String)}. If not returns
	 * <code>true</code>, but the IP address is not counted
	 * <li>Is the IP address blocked by the monitoring, which implementents the
	 * actual rate limitation? Calls {@link #isIPAddressBlocked(String)}
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

		if (!isRequestURIInRelevantPaths(requestURI)) {
			if (log.isDebugEnabled())
				log.debug(name4logging + " Not in relevantPaths: " + requestURI);

			return true;
		}

		return !isIPAddressBlocked(ip);
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
