package org.henbru.antidos;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

/**
 * Copyright 2017 Henning Brune
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
 * <li>{@link #setMaxIPCacheSize(int)}
 * <li>{@link #setNumberOfSlots(int)}
 * <li>{@link #setSlotLength(int)}
 * <li>{@link #setShareOfRetainedFormerRequests(String)}
 * <li>{@link #setSimulationMode(boolean)}
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
	 * The HTTP response status code that is set during a rejection due to too many
	 * accesses in {@link #DEFAULT_MONITOR_MODE}
	 */
	public static final int BLOCKING_HTTP_STATUS = HttpServletResponse.SC_FORBIDDEN;

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
	private static volatile Map<String, AntiDoSMonitor> monitors = null;

	private int maxIPCacheSize = -1;
	private int numberOfSlots = -1;
	private int slotLength = -1;
	private int allowedRequestsPerSlot = -1;
	private float shareOfRetainedFormerRequests = -1;
	private boolean simulationMode = false;

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

	private static final String provideName4logging(String monitorName) {
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
	 * The monitor object for the monitorName in this instance. Calls
	 * {@link #reloadMonitor()} to create monitor instance, if necessary
	 * 
	 * @return might be <code>null</code> if configuration is incomplete
	 */
	private AntiDoSMonitor provideMonitor() {
		if (monitors == null || !monitors.containsKey(monitorName))
			reloadMonitor();

		return monitors.get(monitorName);
	}

	/**
	 * Creates the map for the monitors. Should be called only once in the lifetime
	 * of the Tomcat container
	 */
	private static void initializeMonitors() {
		monitors = new ConcurrentHashMap<String, AntiDoSMonitor>(1);
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
	 * @param maxIPCacheSize The number of IP addresses that can be monitored within
	 *                       a time slot. Used to prevent the memory requirement
	 *                       from growing indefinitely. This value is used as
	 *                       <code>maxCountersPerSlot</code> in
	 *                       {@link AntiDoSMonitor#AntiDoSMonitor(int, int, int, int, float)}
	 */
	public void setMaxIPCacheSize(int maxIPCacheSize) {
		this.maxIPCacheSize = maxIPCacheSize;
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
		} catch (Exception ex) {
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
	 * This method is called on every request. It uses
	 * {@link #isRequestAllowed(String, String)} for its checks. If a request is
	 * blocked the reaction of the valve depends on its mode:
	 * <ul>
	 * <lli>{@link #DEFAULT_MONITOR_MODE}: the value of
	 * {@link #BLOCKING_HTTP_STATUS} is set as error code
	 * <li>{@link #MARKING_MONITOR_MODE}: an information is added to the request
	 * </ul>
	 * When simulationMode is on only logging information is generated
	 */
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
			response.sendError(BLOCKING_HTTP_STATUS);
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
			if (monitors == null)
				initializeMonitors();

			AntiDoSMonitor monitor = new AntiDoSMonitor(monitorName, maxIPCacheSize, numberOfSlots, slotLength,
					allowedRequestsPerSlot, shareOfRetainedFormerRequests);

			if (monitorName == null)
				monitorName = DEFAULT_MONITOR_NAME;

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
	 * This method implements the actual business logic of the valve. The method is
	 * public and can be called by JMX. The test runs in this order:
	 * 
	 * <ul>
	 * <li>Is the IP address always blocked? Calls
	 * {@link #isIPAddressInAlwaysForbidden(String)}. If <code>true</code> the
	 * checks is finished and <code>false</code> returned as result, but the IP
	 * address is not counted in the {@link AntiDoSMonitor} instance
	 * <li>Is the IP address always allowed? Calls
	 * {@link #isIPAddressInAlwaysAllowed(String)}. If <code>true</code> the checks
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
		AntiDoSMonitor monitor = provideMonitor();
		if (monitor == null || monitor.registerAndCheckRequest(ip)) {
			if (log.isDebugEnabled())
				if (monitor == null)
					log.debug(name4logging + " not available");
				else
					log.debug(name4logging + " Not blocked in AntiDoSMonitor: " + ip);

			return false;
		}

		if (log.isDebugEnabled())
			log.debug(name4logging + " blocks: " + ip);

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
		AntiDoSMonitor monitor = provideMonitor();

		AntiDoSCounter ipCounter = monitor != null ? monitor.provideCurrentCounter(ip) : null;

		return ipCounter != null ? ipCounter.toString() : "-";
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

		if (alwaysForbidden != null && alwaysForbidden.matcher(ip).matches())
			return true;

		return false;
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

		if (alwaysAllowed != null && alwaysAllowed.matcher(ip).matches())
			return true;

		return false;
	}

	/**
	 * This method checks if a URL is matched by the pattern in
	 * {@link #getRelevantePfade()}. The method is public and can be called by JMX
	 *
	 * @param requestURI The path. Should be the result of
	 *                   {@link HttpServletRequest#getRequestURI()}
	 */
	public boolean isRequestURIInRelevantPaths(String requestURI) {
		// Local copy for thread safety
		Pattern relevant = this.relevantPaths;

		if (relevant != null && relevant.matcher(requestURI).matches())
			return true;

		return false;
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
