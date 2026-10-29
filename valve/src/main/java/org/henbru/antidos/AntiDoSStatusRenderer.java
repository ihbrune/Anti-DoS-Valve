package org.henbru.antidos;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.TimeZone;

import org.apache.catalina.connector.Response;

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
 * Dedicated renderer for the Anti-DoS Valve status dashboard.
 * Generates HTML and JSON dashboards for monitor overviews and detailed cache inspection.
 */
public class AntiDoSStatusRenderer {

	private final AntiDoSValve valve;

	public AntiDoSStatusRenderer(AntiDoSValve valve) {
		this.valve = valve;
	}

	static record CounterEntry(String key, int count, int retained, int effective, boolean locked, int distinctClients, int returningCount)
			implements Comparable<CounterEntry> {
		public CounterEntry(String key, int count, int retained, int effective, boolean locked, int distinctClients) {
			this(key, count, retained, effective, locked, distinctClients, 0);
		}

		public CounterEntry(String key, int count, int retained, int effective, boolean locked) {
			this(key, count, retained, effective, locked, 1, 0);
		}

		@Override
		public int compareTo(CounterEntry other) {
			int cmp = Integer.compare(other.effective, this.effective);
			if (cmp != 0) return cmp;
			cmp = Integer.compare(other.count, this.count);
			if (cmp != 0) return cmp;
			return this.key.compareTo(other.key);
		}
	}

	static record FilteredEntries(List<CounterEntry> entries, long maxOrder) {}

	public static String buildDashboardUrl(String token, String valve, String view, String format) {
		return buildDashboardUrl(token, valve, view, format, null, null, true);
	}

	public static String buildDashboardUrl(String token, String valve, String view, String format, boolean forHtml) {
		return buildDashboardUrl(token, valve, view, format, null, null, forHtml);
	}

	public static String buildDashboardUrl(String token, String valve, String view, String format, String slot, String limit, boolean forHtml) {
		return buildDashboardUrl(token, valve, view, format, slot, limit, null, null, forHtml);
	}

	public static String buildDashboardUrl(String token, String valve, String view, String format, String slot, String limit,
			String blockedLimit, String activeLimit, boolean forHtml) {
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
		if (slot != null && !slot.isEmpty()) {
			params.add("slot=" + URLEncoder.encode(slot, StandardCharsets.UTF_8));
		}
		if (limit != null && !limit.isEmpty()) {
			params.add("limit=" + URLEncoder.encode(limit, StandardCharsets.UTF_8));
		}
		if (blockedLimit != null && !blockedLimit.isEmpty()) {
			params.add("blockedLimit=" + URLEncoder.encode(blockedLimit, StandardCharsets.UTF_8));
		}
		if (activeLimit != null && !activeLimit.isEmpty()) {
			params.add("activeLimit=" + URLEncoder.encode(activeLimit, StandardCharsets.UTF_8));
		}
		if (params.isEmpty()) {
			return "?";
		}
		String separator = forHtml ? "&amp;" : "&";
		return "?" + String.join(separator, params);
	}

	public static final int MAX_HTML_LIMIT = 1000;

	/**
	 * Parses a limit parameter string. Supports positive integers, "all", or "-1" for unlimited.
	 *
	 * @param limitParam   The limit string
	 * @param defaultLimit Default fallback limit
	 * @return The parsed limit, or {@link Integer#MAX_VALUE} for unlimited
	 */
	public static int parseLimit(String limitParam, int defaultLimit) {
		return parseLimit(limitParam, defaultLimit, false);
	}

	/**
	 * Parses a limit parameter string with optional support for 0 (meaning zero entries requested).
	 *
	 * @param limitParam   The limit string
	 * @param defaultLimit Default fallback limit
	 * @param allowZero    If true, "0" is parsed as 0 rather than falling back to defaultLimit
	 * @return The parsed limit, 0 if allowed, or {@link Integer#MAX_VALUE} for unlimited
	 */
	public static int parseLimit(String limitParam, int defaultLimit, boolean allowZero) {
		if (limitParam == null || limitParam.trim().isEmpty()) {
			return defaultLimit;
		}
		String trimmed = limitParam.trim();
		if ("all".equalsIgnoreCase(trimmed) || "-1".equals(trimmed)) {
			return Integer.MAX_VALUE;
		}
		try {
			int val = Integer.parseInt(trimmed);
			if (allowZero && val == 0) {
				return 0;
			}
			return val <= 0 ? defaultLimit : val;
		} catch (NumberFormatException e) {
			return defaultLimit;
		}
	}

	/**
	 * Resolves an effective limit integer from a specific limit (e.g. activeLimit), an optional fallback limit
	 * (e.g. generic limit), and a hard default. Supports 0 for zero entries and {@link Integer#MAX_VALUE} for unlimited.
	 */
	public static int resolveEffectiveLimit(Integer specificLimit, Integer fallbackLimit, int defaultLimit) {
		Integer target = specificLimit != null ? specificLimit : fallbackLimit;
		if (target == null) {
			return defaultLimit;
		}
		if (target == 0) {
			return 0;
		}
		if (target < 0 || target == Integer.MAX_VALUE) {
			return Integer.MAX_VALUE;
		}
		return target;
	}

	/**
	 * Extracts up to {@code limit} top counter entries from the given counter map using a bounded
	 * min-heap, while simultaneously computing the maximum accessOrder seen.
	 */
	static FilteredEntries extractTopEntriesWithMax(Map<String, AntiDoSCounter> map, int limit, boolean locked) {
		if (map == null || map.isEmpty()) {
			return new FilteredEntries(Collections.emptyList(), 0L);
		}

		long maxOrder = 0L;
		if (limit <= 0) {
			for (AntiDoSCounter c : map.values()) {
				long order = c.getAccessOrder();
				if (order > maxOrder) {
					maxOrder = order;
				}
			}
			return new FilteredEntries(Collections.emptyList(), maxOrder);
		}

		if (limit == Integer.MAX_VALUE || limit >= map.size()) {
			List<CounterEntry> list = new ArrayList<>(map.size());
			for (Map.Entry<String, AntiDoSCounter> entry : map.entrySet()) {
				AntiDoSCounter c = entry.getValue();
				long order = c.getAccessOrder();
				if (order > maxOrder) {
					maxOrder = order;
				}
				int count = c.getCount();
				int rawRetained = c.getRetainedCounts();
				int retained = rawRetained > 0 ? rawRetained : 0;
				int distinct = c.hasCardinalityTracker() ? c.getDistinctClients() : -1;
				list.add(new CounterEntry(entry.getKey(), count, retained, count + retained, locked, distinct, c.getReturningCount()));
			}
			Collections.sort(list);
			return new FilteredEntries(list, maxOrder);
		}

		PriorityQueue<CounterEntry> minHeap = new PriorityQueue<>(limit + 1, Comparator.reverseOrder());

		for (Map.Entry<String, AntiDoSCounter> entry : map.entrySet()) {
			AntiDoSCounter c = entry.getValue();
			long order = c.getAccessOrder();
			if (order > maxOrder) {
				maxOrder = order;
			}
			int count = c.getCount();
			int rawRetained = c.getRetainedCounts();
			int retained = rawRetained > 0 ? rawRetained : 0;
			int effective = count + retained;
			int distinct = c.hasCardinalityTracker() ? c.getDistinctClients() : -1;

			if (minHeap.size() == limit) {
				CounterEntry worst = minHeap.peek();
				if (effective < worst.effective()) {
					continue;
				}
				CounterEntry candidate = new CounterEntry(entry.getKey(), count, retained, effective, locked, distinct, c.getReturningCount());
				if (candidate.compareTo(worst) < 0) {
					minHeap.poll();
					minHeap.offer(candidate);
				}
			} else {
				minHeap.offer(new CounterEntry(entry.getKey(), count, retained, effective, locked, distinct, c.getReturningCount()));
			}
		}

		List<CounterEntry> result = new ArrayList<>(minHeap);
		Collections.sort(result);
		return new FilteredEntries(result, maxOrder);
	}

	/**
	 * Linearly extracts counter entries that have an accessOrder strictly greater than {@code sinceOrder}
	 * and an effective count greater than or equal to {@code minCount}.
	 * Runs in O(N) with zero heap-sorting overhead.
	 */
	static FilteredEntries extractFilteredEntries(Map<String, AntiDoSCounter> map, Long sinceOrder, Integer minCount, boolean locked) {
		if (map == null || map.isEmpty()) {
			return new FilteredEntries(Collections.emptyList(), 0L);
		}
		long threshold = sinceOrder != null ? sinceOrder : Long.MIN_VALUE;
		int min = minCount != null ? minCount : 1;
		long maxOrder = 0L;
		List<CounterEntry> list = new ArrayList<>();

		for (Map.Entry<String, AntiDoSCounter> entry : map.entrySet()) {
			AntiDoSCounter c = entry.getValue();
			long order = c.getAccessOrder();
			if (order > maxOrder) {
				maxOrder = order;
			}
			if (order > threshold) {
				int count = c.getCount();
				int rawRetained = c.getRetainedCounts();
				int retained = rawRetained > 0 ? rawRetained : 0;
				int effective = count + retained;
				if (effective >= min) {
					int distinct = c.hasCardinalityTracker() ? c.getDistinctClients() : -1;
					list.add(new CounterEntry(entry.getKey(), count, retained, effective, locked, distinct, c.getReturningCount()));
				}
			}
		}
		return new FilteredEntries(list, maxOrder);
	}

	/**
	 * Extracts up to {@code limit} top counter entries from the given counter map using a bounded
	 * min-heap. This avoids full sorting and unnecessary object allocations when inspecting large caches.
	 *
	 * @param map    The counter map (active or blocked counters)
	 * @param limit  Maximum number of entries to extract. If 0, returns an empty list immediately.
	 * @param locked Whether the entries represent locked/blocked counters
	 * @return A sorted list of the top entries in descending order of significance
	 */
	static List<CounterEntry> extractTopEntries(Map<String, AntiDoSCounter> map, int limit, boolean locked) {
		return extractTopEntriesWithMax(map, limit, locked).entries();
	}

	/**
	 * Resolves the target slot from an optional slot parameter (e.g. "current", "previous", or numeric slotKey/index).
	 *
	 * @param monitor   The monitor instance
	 * @param slotParam The slot parameter string
	 * @return The resolved slot, or <code>null</code> if unavailable
	 */
	public static AntiDoSSlot resolveTargetSlot(AntiDoSMonitor monitor, String slotParam) {
		if (monitor == null) {
			return null;
		}
		if (slotParam == null || slotParam.trim().isEmpty() || "current".equalsIgnoreCase(slotParam.trim())) {
			return monitor.getCurrentSlotIfExists();
		}
		String trimmed = slotParam.trim();
		if ("previous".equalsIgnoreCase(trimmed)) {
			return monitor.getPreviousSlotIfExists();
		}
		try {
			long keyOrIndex = Long.parseLong(trimmed);
			AntiDoSSlot slotByKey = monitor.getSlotByKey(keyOrIndex);
			if (slotByKey != null) {
				return slotByKey;
			}
			if (keyOrIndex >= 0 && keyOrIndex < monitor.getNumberOfSlots()) {
				AntiDoSSlot slotByIndex = monitor.getSlot((int) keyOrIndex);
				if (slotByIndex != null) {
					long age = monitor.getCurrentSlotKey() - slotByIndex.getSlotKey();
					if (age >= 0 && age < monitor.getNumberOfSlots()) {
						return slotByIndex;
					}
				}
			}
		} catch (NumberFormatException ignored) {
		}
		return null;
	}

	/**
	 * Determines a human-readable and machine-readable slot type ("current", "previous", or "historical").
	 */
	public static String determineSlotType(AntiDoSMonitor monitor, AntiDoSSlot slot, String slotParam) {
		if (slot == null) {
			return "none";
		}
		if (monitor != null && slot.getSlotKey() == monitor.getCurrentSlotKey()) {
			return "current";
		}
		if (monitor != null && slot.getSlotKey() == (monitor.getCurrentSlotKey() - 1)) {
			return "previous";
		}
		return "historical";
	}

	/**
	 * Generates and writes the HTML status dashboard to the HTTP response.
	 *
	 * @param response    The HTTP response
	 * @param filterValve The valve to filter by
	 * @param view        The dashboard view ("details" or overview)
	 * @param token       The active access token for building carry-over links
	 * @throws IOException If an I/O error occurs
	 */
	public void renderStatusHtml(Response response, String filterValve, String view, String token) throws IOException {
		renderStatusHtml(response, filterValve, view, token, null, null, null, null);
	}

	public void renderStatusHtml(Response response, String filterValve, String view, String token, String slotParam, String limitParam) throws IOException {
		renderStatusHtml(response, filterValve, view, token, slotParam, limitParam, null, null);
	}

	public void renderStatusHtml(Response response, String filterValve, String view, String token, String slotParam,
			String limitParam, String blockedLimitParam, String activeLimitParam) throws IOException {
		response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
		response.setHeader("Pragma", "no-cache");
		response.setHeader("Referrer-Policy", "no-referrer");
		response.setHeader("X-Content-Type-Options", "nosniff");
		response.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'");
		response.setContentType("text/html;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		PrintWriter out = response.getWriter();
		if ("details".equalsIgnoreCase(view)) {
			String effBlockedParam = (blockedLimitParam != null && !blockedLimitParam.trim().isEmpty()) ? blockedLimitParam : limitParam;
			String effActiveParam = (activeLimitParam != null && !activeLimitParam.trim().isEmpty()) ? activeLimitParam : limitParam;
			Integer blockedLimit = effBlockedParam != null ? parseLimit(effBlockedParam, 50, true) : null;
			Integer activeLimit = effActiveParam != null ? parseLimit(effActiveParam, 50, true) : null;
			out.write(buildStatusHtmlDetails(filterValve, token, slotParam, blockedLimit, activeLimit));
		} else {
			out.write(buildStatusHtml(filterValve, token));
		}
		out.flush();
	}

	/**
	 * Generates and writes the JSON status dashboard to the HTTP response.
	 *
	 * @param response    The HTTP response
	 * @param filterValve The valve to filter by
	 * @param view        The dashboard view ("details" or overview)
	 * @throws IOException If an I/O error occurs
	 */
	public void renderStatusJson(Response response, String filterValve, String view) throws IOException {
		renderStatusJson(response, filterValve, view, null, null, null, null);
	}

	public void renderStatusJson(Response response, String filterValve, String view, String slotParam, String limitParam) throws IOException {
		renderStatusJson(response, filterValve, view, slotParam, limitParam, null, null);
	}

	public void renderStatusJson(Response response, String filterValve, String view, String slotParam, String limitParam,
			String blockedLimitParam, String activeLimitParam) throws IOException {
		renderStatusJson(response, filterValve, view, slotParam, limitParam, blockedLimitParam, activeLimitParam, null, null, null);
	}

	public void renderStatusJson(Response response, String filterValve, String view, String slotParam, String limitParam,
			String blockedLimitParam, String activeLimitParam, String sinceBlockedOrderParam, String sinceActiveOrderParam,
			String activeMinCountParam) throws IOException {
		response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
		response.setHeader("Pragma", "no-cache");
		response.setHeader("Referrer-Policy", "no-referrer");
		response.setHeader("X-Content-Type-Options", "nosniff");
		response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
		response.setContentType("application/json;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		PrintWriter out = response.getWriter();
		if ("details".equalsIgnoreCase(view)) {
			String effBlockedParam = (blockedLimitParam != null && !blockedLimitParam.trim().isEmpty()) ? blockedLimitParam : limitParam;
			String effActiveParam = (activeLimitParam != null && !activeLimitParam.trim().isEmpty()) ? activeLimitParam : limitParam;
			Integer blockedLimit = effBlockedParam != null ? parseLimit(effBlockedParam, 50, true) : null;
			Integer activeLimit = effActiveParam != null ? parseLimit(effActiveParam, 50, true) : null;
			Long sinceBlockedOrder = parseLongParam(sinceBlockedOrderParam);
			Long sinceActiveOrder = parseLongParam(sinceActiveOrderParam);
			Integer activeMinCount = parseIntParam(activeMinCountParam);
			out.write(buildStatusJsonDetails(filterValve, slotParam, blockedLimit, activeLimit, sinceBlockedOrder, sinceActiveOrder, activeMinCount));
		} else {
			out.write(buildStatusJson(filterValve));
		}
		out.flush();
	}

	public static Long parseLongParam(String param) {
		if (param == null || param.trim().isEmpty()) {
			return null;
		}
		try {
			return Long.valueOf(param.trim());
		} catch (NumberFormatException e) {
			return null;
		}
	}

	public static Integer parseIntParam(String param) {
		if (param == null || param.trim().isEmpty()) {
			return null;
		}
		try {
			return Integer.valueOf(param.trim());
		} catch (NumberFormatException e) {
			return null;
		}
	}

	private Set<AntiDoSValve> getValvesToRender() {
		return valve.getValvesToRender();
	}

	private long getTimeInMillis() {
		return valve.getTimeInMillis();
	}

	static String formatDuration(long seconds) {
		if (seconds < 60) {
			return seconds + "s";
		}
		if (seconds < 3600) {
			long m = seconds / 60;
			long s = seconds % 60;
			return m + "m " + s + "s";
		}
		long h = seconds / 3600;
		long m = (seconds % 3600) / 60;
		return h + "h " + m + "m";
	}

	public String buildStatusHtml(String filterValve) {
		return buildStatusHtml(filterValve, null);
	}

	private static void appendCommonHeadStyles(StringBuilder sb) {
		sb.append("<style>\n")
				.append(":root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--border:#334155;--accent:#38bdf8;--green:#22c55e;--red:#ef4444;--yellow:#eab308}\n")
				.append(":root[data-theme=\"light\"]{--bg:#f8fafc;--card:#ffffff;--text:#0f172a;--muted:#64748b;--border:#cbd5e1;--accent:#0284c7;--green:#16a34a;--red:#dc2626;--yellow:#d97706}\n")
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
				.append("[data-theme=\"light\"] .btn{background:#ffffff;border-color:#cbd5e1;color:#0f172a}\n")
				.append("[data-theme=\"light\"] .btn:hover{background:#f1f5f9;border-color:var(--accent);color:var(--accent)}\n")
				.append(".badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;letter-spacing:0.5px}\n")
				.append(".badge-blocking{background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d}\n")
				.append(".badge-marking{background:#172554;color:#93c5fd;border:1px solid #1e40af}\n")
				.append(".badge-warn{background:#422006;color:#fde047;border:1px solid #713f12}\n")
				.append(".badge-info{background:#0b1329;color:#7dd3fc;border:1px solid #0369a1}\n")
				.append(".badge-status{background:#064e3b;color:#6ee7b7;border:1px solid #047857}\n")
				.append("[data-theme=\"light\"] .badge-blocking{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}\n")
				.append("[data-theme=\"light\"] .badge-marking{background:#dbeafe;color:#1e40af;border:1px solid #93c5fd}\n")
				.append("[data-theme=\"light\"] .badge-warn{background:#fef3c7;color:#92400e;border:1px solid #fde047}\n")
				.append("[data-theme=\"light\"] .badge-info{background:#e0f2fe;color:#0369a1;border:1px solid #7dd3fc}\n")
				.append("[data-theme=\"light\"] .badge-status{background:#d1fae5;color:#065f46;border:1px solid #6ee7b7}\n")
				.append(".valve-desc{color:#cbd5e1;background:#0b1120;border-left:3px solid var(--accent);padding:6px 12px;margin:4px 0 10px 0;border-radius:0 4px 4px 0;font-size:12px;line-height:1.4}\n")
				.append("[data-theme=\"light\"] .valve-desc{color:#334155;background:#f8fafc;border-left:3px solid var(--accent)}\n")
				.append("table{width:100%;border-collapse:collapse;margin-top:6px}\n")
				.append("th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border)}\n")
				.append("th{color:var(--muted);font-weight:500;width:30%;vertical-align:top}\n")
				.append("td{color:var(--text)}\n")
				.append(".data-table{width:100%;border-collapse:collapse;margin-top:6px}\n")
				.append(".data-table th{background:#0b1120;color:var(--muted);font-weight:600;padding:6px 10px;border-bottom:1px solid var(--border);width:auto;text-align:left}\n")
				.append("[data-theme=\"light\"] .data-table th{background:#f1f5f9;border-bottom:1px solid var(--border)}\n")
				.append(".data-table td{padding:6px 10px;border-bottom:1px solid var(--border)}\n")
				.append("code{background:#0b1120;padding:2px 6px;border-radius:4px;color:#cbd5e1;border:1px solid #1e293b}\n")
				.append("[data-theme=\"light\"] code{background:#f1f5f9;color:#0f172a;border:1px solid #cbd5e1}\n")
				.append(".metric-bar{background:#0b1120;border-radius:3px;height:8px;width:120px;display:inline-block;vertical-align:middle;overflow:hidden;margin-left:8px;border:1px solid var(--border)}\n")
				.append("[data-theme=\"light\"] .metric-bar{background:#e2e8f0}\n")
				.append(".metric-fill{height:100%;background:var(--accent)}\n")
				.append(".metric-fill.high{background:var(--red)}\n")
				.append(".metric-fill.med{background:var(--yellow)}\n")
				.append("html:not([data-theme=\"light\"]) .theme-moon{display:none}\n")
				.append("html:not([data-theme=\"light\"]) .theme-sun{display:inline}\n")
				.append("html[data-theme=\"light\"] .theme-sun{display:none}\n")
				.append("html[data-theme=\"light\"] .theme-moon{display:inline}\n")
				.append("</style>\n")
				.append("<script>\n")
				.append("(function(){try{var t=localStorage.getItem('theme');if(!t){var m=document.cookie.match(/(?:^|; )theme=([^;]*)/);t=m?decodeURIComponent(m[1]):null}if(t==='light'||(!t&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)){document.documentElement.setAttribute('data-theme','light')}else{document.documentElement.setAttribute('data-theme','dark')}}catch(e){}})();\n")
				.append("function toggleTheme(){try{var c=document.documentElement.getAttribute('data-theme')==='light'?'dark':'light';document.documentElement.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.cookie='theme='+c+';path=/;max-age=31536000;SameSite=Lax'}catch(e){}}\n")
				.append("</script>\n");
	}

	public String buildStatusHtml(String filterValve, String token) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		sdf.setTimeZone(TimeZone.getDefault());
		String serverTime = sdf.format(new Date(getTimeInMillis()));

		Set<AntiDoSValve> valves = getValvesToRender();

		StringBuilder sb = new StringBuilder(4096);
		sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
				.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
				.append("<title>Anti-DoS Valve Monitor</title>\n");
		appendCommonHeadStyles(sb);
		sb.append("</head>\n<body>\n")
				.append("<div class=\"header\">\n")
				.append("  <div class=\"title\"><span>&#9889;</span> Anti-DoS Valve Monitor</div>\n")
				.append("  <div class=\"subtitle\"><span>Server Time: ").append(serverTime)
				.append(" &bull; Active Valves: ").append(valves.size());
		if (valve != null && valve.getStatusUri() != null) {
			sb.append(" &bull; Dashboard Host: <strong>").append(escapeHtml(valve.getName4logging()))
					.append("</strong> (<code>").append(escapeHtml(valve.getStatusUri())).append("</code>)");
		}
		sb.append("</span>")
				.append("<a class=\"btn\" href=\"").append(buildDashboardUrl(token, null, null, "json")).append("\">{ } JSON (All)</a>")
				.append("<button type=\"button\" class=\"btn\" onclick=\"toggleTheme()\" title=\"Toggle Light/Dark Theme\"><span class=\"theme-sun\">&#9728;&#65039;</span><span class=\"theme-moon\">&#127769;</span> Theme</button>")
				.append("</div>\n")
				.append("</div>\n");

		int renderedCount = 0;
		int pipelineOrder = 0;
		for (AntiDoSValve v : valves) {
			pipelineOrder++;
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
					.append("      <span class=\"valve-name\">").append(escapeHtml(v.getName4logging())).append("</span>\n")
					.append("      <span class=\"badge badge-info\">#").append(pipelineOrder).append(" IN PIPELINE</span>\n");

			if (v.getStatusUri() != null) {
				if (v == valve) {
					sb.append("      <span class=\"badge badge-status\">&#9889; STATUS DASHBOARD (CURRENT HOST): ").append(escapeHtml(v.getStatusUri())).append("</span>\n");
				} else {
					sb.append("      <span class=\"badge badge-status\">&#9889; STATUS DASHBOARD: ").append(escapeHtml(v.getStatusUri())).append("</span>\n");
				}
			}

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
					.append("  </div>\n");

			if (v.getDescription() != null) {
				sb.append("  <div class=\"valve-desc\">").append(escapeHtml(v.getDescription())).append("</div>\n");
			}

			sb.append("  <table>\n")
					.append("    <tr><th>Pipeline Order</th><td><strong>#").append(pipelineOrder).append("</strong></td></tr>\n");

			if (v.getDescription() != null) {
				sb.append("    <tr><th>Description</th><td>").append(escapeHtml(v.getDescription())).append("</td></tr>\n");
			}

			// Status Dashboard row
			if (v.getStatusUri() != null) {
				sb.append("    <tr><th>Status Dashboard</th><td><code>").append(escapeHtml(v.getStatusUri())).append("</code>");
				if (v == valve) {
					sb.append(" <span class=\"badge badge-status\">Current Host</span>");
				} else {
					sb.append(" <span class=\"badge badge-info\">Active</span>");
				}
				if (v.getStatusPassword() != null && !v.getStatusPassword().isEmpty()) {
					sb.append(" &bull; <em>Password Protected</em>");
				} else {
					sb.append(" &bull; <em>Auto-Generated Token</em>");
				}
				sb.append("</td></tr>\n");
				sb.append("    <tr><th>Status Allowed IPs</th><td>");
				if (v.getStatusAllowedIPs() != null) {
					sb.append("<code>").append(escapeHtml(v.getStatusAllowedIPs())).append("</code>");
				} else {
					sb.append("<em>all (unrestricted)</em>");
				}
				sb.append("</td></tr>\n");
			} else {
				sb.append("    <tr><th>Status Dashboard</th><td><em>none (disabled on this valve)</em></td></tr>\n");
			}

			// Relevant & non-relevant paths
			sb.append("    <tr><th>Relevant Paths</th><td>");
			if (v.getRelevantPathsConfigValue() != null) {
				sb.append("<code>").append(escapeHtml(v.getRelevantPathsConfigValue())).append("</code>");
			} else if (v.getStatusUri() != null) {
				sb.append("<em>none (no requests monitored &mdash; dedicated to Status Dashboard at <code>").append(escapeHtml(v.getStatusUri())).append("</code>)</em>");
			} else {
				sb.append("<em>none (no requests monitored)</em>");
			}
			sb.append("</td></tr>\n");

			if (v.getNonRelevantPathsConfigValue() != null) {
				sb.append("    <tr><th>Non-Relevant Paths</th><td><code>").append(escapeHtml(v.getNonRelevantPathsConfigValue())).append("</code></td></tr>\n");
			}

			if (v.getAlwaysAllowedIPsConfigValue() != null) {
				sb.append("    <tr><th>Always Allowed IPs</th><td><code>").append(escapeHtml(v.getAlwaysAllowedIPsConfigValue())).append("</code></td></tr>\n");
			}
			if (v.getAlwaysForbiddenIPsConfigValue() != null) {
				sb.append("    <tr><th>Always Forbidden IPs</th><td><code>").append(escapeHtml(v.getAlwaysForbiddenIPsConfigValue())).append("</code></td></tr>\n");
				sb.append("    <tr><th>Always Forbidden Blocks</th><td><strong>").append(v.getAlwaysForbiddenBlockedRequests()).append("</strong> requests rejected</td></tr>\n");
			}

			// Rate limit parameters
			int retentionPct = Math.round(v.getShareOfRetainedFormerRequests() * 100);
			String limitLabel = v.getAllowedRequestsPerSlot() == 0 ? "0 (Zero Tolerance / Honeypot)" : String.valueOf(v.getAllowedRequestsPerSlot());
			sb.append("    <tr><th>Rate Limit</th><td><strong>").append(limitLabel)
					.append("</strong> req / <strong>").append(v.getSlotLength()).append("s</strong> slot (Slots: ")
					.append(v.getNumberOfSlots()).append(", Retention: ").append(retentionPct).append("%)</td></tr>\n");

			// Subnet masks
			String v4Str = v.getIpv4SubnetMask() == 32 ? "single IP (/32, no aggregation)" : "/" + v.getIpv4SubnetMask();
			String v6Str = v.getIpv6SubnetMask() == 128 ? "single IP (/128, no aggregation)" : "/" + v.getIpv6SubnetMask();
			sb.append("    <tr><th>Subnet Aggregation</th><td>IPv4: <code>").append(v4Str)
					.append("</code> &bull; IPv6: <code>").append(v6Str).append("</code></td></tr>\n");

			// Collector Integration
			String cMode = v.getCollectorIntegration();
			boolean cActive = v.isExtendedMetricsActive();
			String cBadge = "auto".equalsIgnoreCase(cMode)
					? (cActive ? " <span class=\"badge badge-active\">Active (Lease)</span>" : " <span class=\"badge\" style=\"background:var(--accent-subtle);\">Idle</span>")
					: (cActive ? " <span class=\"badge badge-active\">Forced On</span>" : " <span class=\"badge\" style=\"background:var(--accent-subtle);\">Disabled</span>");
			long lastScrape = v.getLastCollectorScrapeTime();
			String lastScrapeHtml = lastScrape <= 0
					? "<span style=\"color:var(--muted);\">never</span>"
					: sdf.format(new Date(lastScrape)) + " (" + formatDuration(Math.max(0, (getTimeInMillis() - lastScrape) / 1000)) + " ago)";
			sb.append("    <tr><th>Collector Integration</th><td><code>").append(escapeHtml(cMode)).append("</code>").append(cBadge)
					.append(" &bull; Last Access: ").append(lastScrapeHtml).append("</td></tr>\n");

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

	public String buildStatusHtmlDetails(String valveName) {
		return buildStatusHtmlDetails(valveName, null, null, null, null);
	}

	public String buildStatusHtmlDetails(String valveName, String token) {
		return buildStatusHtmlDetails(valveName, token, null, null, null);
	}

	public String buildStatusHtmlDetails(String valveName, String token, String slotParam, Integer limit) {
		return buildStatusHtmlDetails(valveName, token, slotParam, limit, limit);
	}

	public String buildStatusHtmlDetails(String valveName, String token, String slotParam, Integer blockedLimit, Integer activeLimit) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		sdf.setTimeZone(TimeZone.getDefault());
		String serverTime = sdf.format(new Date(getTimeInMillis()));

		AntiDoSValve target = null;
		Set<AntiDoSValve> valves = getValvesToRender();
		int targetPipelineOrder = 1;
		int orderCounter = 1;
		if (valveName != null && !valveName.trim().isEmpty()) {
			for (AntiDoSValve v : valves) {
				if (v.getMonitorName().equalsIgnoreCase(valveName.trim())) {
					target = v;
					targetPipelineOrder = orderCounter;
					break;
				}
				orderCounter++;
			}
		} else if (valves.size() == 1) {
			target = valves.iterator().next();
			targetPipelineOrder = 1;
		}

		StringBuilder sb = new StringBuilder(6144);
		sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
				.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
				.append("<title>Anti-DoS Valve Monitor - ").append(target != null ? escapeHtml(target.getMonitorName()) : "Details").append("</title>\n");
		appendCommonHeadStyles(sb);
		sb.append("</head>\n<body>\n");

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

		int effBlockedLimit = resolveEffectiveLimit(blockedLimit, null, 50);
		if (effBlockedLimit != Integer.MAX_VALUE && effBlockedLimit > MAX_HTML_LIMIT) {
			effBlockedLimit = MAX_HTML_LIMIT;
		}
		int effActiveLimit = resolveEffectiveLimit(activeLimit, null, 50);
		if (effActiveLimit != Integer.MAX_VALUE && effActiveLimit > MAX_HTML_LIMIT) {
			effActiveLimit = MAX_HTML_LIMIT;
		}

		String limitStr = (blockedLimit != null && blockedLimit.equals(activeLimit) && blockedLimit != Integer.MAX_VALUE) ? String.valueOf(blockedLimit) : null;
		String blockedLimitStr = (blockedLimit != null && !blockedLimit.equals(activeLimit))
				? (blockedLimit == Integer.MAX_VALUE ? "all" : String.valueOf(blockedLimit))
				: null;
		String activeLimitStr = (activeLimit != null && !activeLimit.equals(blockedLimit))
				? (activeLimit == Integer.MAX_VALUE ? "all" : String.valueOf(activeLimit))
				: null;

		// Header
		sb.append("<div class=\"header\">\n")
				.append("  <div class=\"title\"><span>&#9889;</span> Anti-DoS Valve Monitor &bull; <span>").append(escapeHtml(target.getName4logging())).append(" Details</span></div>\n")
				.append("  <div class=\"subtitle\">\n")
				.append("    <span>Server Time: ").append(serverTime);
		if (valve != null && valve.getStatusUri() != null) {
			sb.append(" &bull; Dashboard Host: <strong>").append(escapeHtml(valve.getName4logging()))
					.append("</strong> (<code>").append(escapeHtml(valve.getStatusUri())).append("</code>)");
		}
		sb.append("</span>\n")
				.append("    <a class=\"btn\" href=\"").append(buildDashboardUrl(token, null, null, null)).append("\">&#8592; Back to Overview</a>\n")
				.append("    <a class=\"btn\" href=\"").append(buildDashboardUrl(token, target.getMonitorName(), "details", null, slotParam, limitStr, blockedLimitStr, activeLimitStr, true)).append("\">&#128260; Refresh</a>\n")
				.append("    <a class=\"btn\" href=\"").append(buildDashboardUrl(token, target.getMonitorName(), "details", "json", slotParam, limitStr, blockedLimitStr, activeLimitStr, true)).append("\">{ } JSON Details</a>\n")
				.append("    <button type=\"button\" class=\"btn\" onclick=\"toggleTheme()\" title=\"Toggle Light/Dark Theme\"><span class=\"theme-sun\">&#9728;&#65039;</span><span class=\"theme-moon\">&#127769;</span> Theme</button>\n")
				.append("  </div>\n")
				.append("</div>\n");

		// Card 1: Configuration & Status Summary
		sb.append("<div class=\"card\">\n")
				.append("  <div class=\"card-header\">\n")
				.append("    <div class=\"card-title-group\">\n")
				.append("      <span class=\"valve-name\">Configuration &amp; Metrics Summary</span>\n")
				.append("      <span class=\"badge badge-info\">#").append(targetPipelineOrder).append(" IN PIPELINE</span>\n");

		if (target.getStatusUri() != null) {
			if (target == valve) {
				sb.append("      <span class=\"badge badge-status\">&#9889; STATUS DASHBOARD (CURRENT HOST): ").append(escapeHtml(target.getStatusUri())).append("</span>\n");
			} else {
				sb.append("      <span class=\"badge badge-status\">&#9889; STATUS DASHBOARD: ").append(escapeHtml(target.getStatusUri())).append("</span>\n");
			}
		}

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
				.append("  </div>\n");

		if (target.getDescription() != null) {
			sb.append("  <div class=\"valve-desc\">").append(escapeHtml(target.getDescription())).append("</div>\n");
		}

		sb.append("  <table>\n")
				.append("    <tr><th>Pipeline Order</th><td><strong>#").append(targetPipelineOrder).append("</strong></td></tr>\n");

		if (target.getDescription() != null) {
			sb.append("    <tr><th>Description</th><td>").append(escapeHtml(target.getDescription())).append("</td></tr>\n");
		}

		// Status Dashboard row
		if (target.getStatusUri() != null) {
			sb.append("    <tr><th>Status Dashboard</th><td><code>").append(escapeHtml(target.getStatusUri())).append("</code>");
			if (target == valve) {
				sb.append(" <span class=\"badge badge-status\">Current Host</span>");
			} else {
				sb.append(" <span class=\"badge badge-info\">Active</span>");
			}
			if (target.getStatusPassword() != null && !target.getStatusPassword().isEmpty()) {
				sb.append(" &bull; <em>Password Protected</em>");
			} else {
				sb.append(" &bull; <em>Auto-Generated Token</em>");
			}
			sb.append("</td></tr>\n");
			sb.append("    <tr><th>Status Allowed IPs</th><td>");
			if (target.getStatusAllowedIPs() != null) {
				sb.append("<code>").append(escapeHtml(target.getStatusAllowedIPs())).append("</code>");
			} else {
				sb.append("<em>all (unrestricted)</em>");
			}
			sb.append("</td></tr>\n");
		} else {
			sb.append("    <tr><th>Status Dashboard</th><td><em>none (disabled on this valve)</em></td></tr>\n");
		}

		sb.append("    <tr><th>Relevant Paths</th><td>");
		if (target.getRelevantPathsConfigValue() != null) {
			sb.append("<code>").append(escapeHtml(target.getRelevantPathsConfigValue())).append("</code>");
		} else if (target.getStatusUri() != null) {
			sb.append("<em>none (no requests monitored &mdash; dedicated to Status Dashboard at <code>").append(escapeHtml(target.getStatusUri())).append("</code>)</em>");
		} else {
			sb.append("<em>none (no requests monitored)</em>");
		}
		sb.append("</td></tr>\n");

		if (target.getNonRelevantPathsConfigValue() != null) {
			sb.append("    <tr><th>Non-Relevant Paths</th><td><code>").append(escapeHtml(target.getNonRelevantPathsConfigValue())).append("</code></td></tr>\n");
		}
		if (target.getAlwaysAllowedIPsConfigValue() != null) {
			sb.append("    <tr><th>Always Allowed IPs</th><td><code>").append(escapeHtml(target.getAlwaysAllowedIPsConfigValue())).append("</code></td></tr>\n");
		}
		if (target.getAlwaysForbiddenIPsConfigValue() != null) {
			sb.append("    <tr><th>Always Forbidden IPs</th><td><code>").append(escapeHtml(target.getAlwaysForbiddenIPsConfigValue())).append("</code></td></tr>\n");
			sb.append("    <tr><th>Always Forbidden Blocks</th><td><strong>").append(target.getAlwaysForbiddenBlockedRequests()).append("</strong> requests rejected</td></tr>\n");
		}

		int retentionPct = Math.round(target.getShareOfRetainedFormerRequests() * 100);
		String targetLimitLabel = target.getAllowedRequestsPerSlot() == 0 ? "0 (Zero Tolerance / Honeypot)" : String.valueOf(target.getAllowedRequestsPerSlot());
		sb.append("    <tr><th>Rate Limit</th><td><strong>").append(targetLimitLabel)
				.append("</strong> req / <strong>").append(target.getSlotLength()).append("s</strong> slot (Slots: ")
				.append(target.getNumberOfSlots()).append(", Retention: ").append(retentionPct).append("%)</td></tr>\n");

		String v4Str = target.getIpv4SubnetMask() == 32 ? "single IP (/32, no aggregation)" : "/" + target.getIpv4SubnetMask();
		String v6Str = target.getIpv6SubnetMask() == 128 ? "single IP (/128, no aggregation)" : "/" + target.getIpv6SubnetMask();
		sb.append("    <tr><th>Subnet Aggregation</th><td>IPv4: <code>").append(v4Str)
				.append("</code> &bull; IPv6: <code>").append(v6Str).append("</code></td></tr>\n");

		String cModeTarget = target.getCollectorIntegration();
		boolean cActiveTarget = target.isExtendedMetricsActive();
		String cBadgeTarget = "auto".equalsIgnoreCase(cModeTarget)
				? (cActiveTarget ? " <span class=\"badge badge-active\">Active (Lease)</span>" : " <span class=\"badge\" style=\"background:var(--accent-subtle);\">Idle</span>")
				: (cActiveTarget ? " <span class=\"badge badge-active\">Forced On</span>" : " <span class=\"badge\" style=\"background:var(--accent-subtle);\">Disabled</span>");
		long lastScrapeTarget = target.getLastCollectorScrapeTime();
		String lastScrapeTargetHtml = lastScrapeTarget <= 0
				? "<span style=\"color:var(--muted);\">never</span>"
				: sdf.format(new Date(lastScrapeTarget)) + " (" + formatDuration(Math.max(0, (getTimeInMillis() - lastScrapeTarget) / 1000)) + " ago)";
		sb.append("    <tr><th>Collector Integration</th><td><code>").append(escapeHtml(cModeTarget)).append("</code>").append(cBadgeTarget)
				.append(" &bull; Last Access: ").append(lastScrapeTargetHtml).append("</td></tr>\n");

		sb.append("    <tr><th>Active IP Cache</th><td>").append(activeCounters).append(" / ").append(maxActive)
				.append(" <div class=\"metric-bar\"><div class=\"metric-fill ").append(activeFillClass)
				.append("\" style=\"width:").append(activePercent).append("%\"></div></div></td></tr>\n");

		sb.append("    <tr><th>Blocked IP Cache</th><td>").append(blockedCounters).append(" / ").append(maxBlocked)
				.append(" <div class=\"metric-bar\"><div class=\"metric-fill ").append(blockedFillClass)
				.append("\" style=\"width:").append(blockedPercent).append("%\"></div></div></td></tr>\n");

		sb.append("    <tr><th>Total Requests Processed</th><td><strong>").append(totalReqs)
				.append("</strong> (Active Slots: ").append(activeSlots).append(" / ").append(target.getNumberOfSlots()).append(")</td></tr>\n");

		sb.append("    <tr><th>Slot Timeline Keys</th><td>Current: <code>").append(currentSlotKey)
				.append("</code> &bull; Last Completed: <code>").append(currentSlotKey > 0 ? (currentSlotKey - 1) : 0).append("</code></td></tr>\n");

		String logThrottling = target.getMaxBlockLogsPerSecond() >= 0 ? target.getMaxBlockLogsPerSecond() + " logs/s" : "disabled";
		String asyncEvict = target.getAsyncEviction() == null ? "auto" : target.getAsyncEviction().toString();
		sb.append("    <tr><th>System Settings</th><td>Log Throttling: <code>").append(logThrottling)
				.append("</code> &bull; Async Eviction: <code>").append(asyncEvict).append("</code></td></tr>\n");

		String visitorCookieStatus;
		if (target.isVisitorCookieEnabled()) {
			visitorCookieStatus = "Enabled (name: <code>" + escapeHtml(target.getVisitorCookieName()) + "</code>, TTL: <strong>"
					+ target.getVisitorCookieTtlSeconds() + "s</strong>, masks: /" + target.getVisitorCookieSubnetMaskV4()
					+ " v4, /" + target.getVisitorCookieSubnetMaskV6() + " v6"
					+ (target.getVisitorCookieDomain() != null ? ", domain: <code>" + escapeHtml(target.getVisitorCookieDomain()) + "</code>" : "") + ")";
		} else if (target.isVisitorTrackingActive()) {
			AntiDoSValve upstream = target.getInheritedVisitorCookieValve();
			String upstreamName = upstream != null ? escapeHtml(upstream.getMonitorName()) : "upstream";
			visitorCookieStatus = "Inherited from <strong>" + upstreamName + "</strong> (name: <code>"
					+ escapeHtml(target.getEffectiveVisitorCookieName()) + "</code>"
					+ (target.getEffectiveVisitorCookieDomain() != null ? ", domain: <code>" + escapeHtml(target.getEffectiveVisitorCookieDomain()) + "</code>" : "") + ")";
		} else {
			visitorCookieStatus = "Disabled";
		}
		sb.append("    <tr><th>Visitor Cookie</th><td>").append(visitorCookieStatus).append("</td></tr>\n");

		sb.append("  </table>\n</div>\n");

		// Card 2: Slot Timeline
		boolean isSubnetMode = target.isSubnetAggregationActive();
		sb.append("<div class=\"card\">\n")
				.append("  <div class=\"card-header\"><div class=\"card-title-group\"><span class=\"valve-name\">Slot Ring Buffer Timeline</span>")
				.append(" <span class=\"subtitle\">(").append(numSlots).append(" slots &bull; ").append(slotLength / 1000).append("s each)</span></div></div>\n")
				.append("  <table class=\"data-table\">\n")
				.append("    <thead><tr><th>Slot #</th><th>Slot Key</th><th>Start Time</th><th>Age</th><th>Status</th><th>Requests</th><th>")
				.append(isSubnetMode ? "Active Subnets" : "Active IPs")
				.append("</th><th>")
				.append(isSubnetMode ? "Blocked Subnets" : "Blocked IPs")
				.append("</th><th>Action</th></tr></thead>\n")
				.append("    <tbody>\n");

		if (monitor != null) {
			for (int i = 0; i < numSlots; i++) {
				AntiDoSSlot slot = monitor.getSlot(i);
				if (slot == null) {
					sb.append("      <tr><td>#").append(i).append("</td><td>-</td><td>-</td><td>-</td>")
							.append("<td><span class=\"badge\">EMPTY</span></td><td>0</td><td>0</td><td>0</td><td>-</td></tr>\n");
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
					String inspectUrl = buildDashboardUrl(token, target.getMonitorName(), "details", null, String.valueOf(slotKey), limitStr, blockedLimitStr, activeLimitStr, true);

					sb.append("      <tr").append(rowStyle).append("><td>#").append(i)
							.append("</td><td>").append(slotKey)
							.append("</td><td>").append(startTime)
							.append("</td><td>").append(ageStr)
							.append("</td><td>").append(statusBadge)
							.append("</td><td>").append(slot.getTotalRequests())
							.append("</td><td>").append(slot.getActiveCounterCount())
							.append("</td><td>").append(slot.getBlockedCounterCount())
							.append("</td><td><a class=\"btn\" href=\"").append(inspectUrl).append("\">Inspect</a></td></tr>\n");
				}
			}
		}
		sb.append("    </tbody>\n  </table>\n</div>\n");

		// Target Slot resolution
		AntiDoSSlot selectedSlot = resolveTargetSlot(monitor, slotParam);
		boolean isSelectedCurrent = (selectedSlot != null && monitor != null && selectedSlot.getSlotKey() == currentSlotKey);
		boolean isSelectedPrev = (selectedSlot != null && monitor != null && selectedSlot.getSlotKey() == (currentSlotKey - 1));
		String slotLabel;
		if (selectedSlot == null) {
			slotLabel = "Slot Not Available";
		} else if (isSelectedCurrent) {
			slotLabel = "Current Slot";
		} else if (isSelectedPrev) {
			slotLabel = "Previous Slot";
		} else {
			slotLabel = "Slot #" + Math.floorMod(selectedSlot.getSlotKey(), numSlots) + ", key " + selectedSlot.getSlotKey();
		}

		String currentSlotUrl = buildDashboardUrl(token, target.getMonitorName(), "details", null, "current", limitStr, blockedLimitStr, activeLimitStr, true);
		String prevSlotUrl = buildDashboardUrl(token, target.getMonitorName(), "details", null, "previous", limitStr, blockedLimitStr, activeLimitStr, true);
		String jsonSlotUrl = buildDashboardUrl(token, target.getMonitorName(), "details", "json", slotParam, limitStr, blockedLimitStr, activeLimitStr, true);

		// Card 3: Blocked Clients
		int blockedTotal = selectedSlot != null ? selectedSlot.getBlockedCounterCount() : 0;
		List<CounterEntry> blockedList = (selectedSlot != null && effBlockedLimit > 0)
				? extractTopEntries(selectedSlot.getBlockedCounters(), effBlockedLimit, true)
				: Collections.emptyList();
		int blockedDisplay = blockedList.size();

		sb.append("<div class=\"card\">\n")
				.append("  <div class=\"card-header\">\n")
				.append("    <div class=\"card-title-group\"><span class=\"valve-name\">Blocked Clients (").append(escapeHtml(slotLabel)).append(")</span>")
				.append(" <span class=\"subtitle\">(").append(blockedDisplay).append(blockedTotal > blockedDisplay ? " of " + blockedTotal : "").append(" entries)</span></div>\n")
				.append("    <div class=\"card-actions\">\n")
				.append("      <a class=\"btn\" href=\"").append(currentSlotUrl).append("\">Current Slot</a>\n")
				.append("      <a class=\"btn\" href=\"").append(prevSlotUrl).append("\">Previous Slot</a>\n")
				.append("      <a class=\"btn\" href=\"").append(jsonSlotUrl).append("\">{ } JSON (This Slot)</a>\n")
				.append("    </div>\n")
				.append("  </div>\n");

		if (blockedDisplay == 0) {
			sb.append("  <div style=\"color:var(--muted);padding:4px 0;\">No blocked clients in ").append(escapeHtml(slotLabel.toLowerCase())).append(".</div>\n");
		} else {
			boolean showSubnetDistinct = target.isSubnetAggregationActive();
			boolean showReturning = target.isVisitorTrackingActive();
			sb.append("  <table class=\"data-table\">\n")
					.append("    <thead><tr><th>IP / Subnet Key</th>");
			if (showSubnetDistinct) {
				sb.append("<th title=\"Distinct client IP addresses observed in this subnet\">Distinct IPs</th>");
			}
			sb.append("<th>Slot Requests</th><th>Retained</th><th>Effective</th>")
					.append(showReturning ? "<th title=\"Requests carrying valid visitor cookie\">Returning</th>" : "")
					.append("<th>Limit</th><th>Status</th></tr></thead>\n")
					.append("    <tbody>\n");
			for (int i = 0; i < blockedDisplay; i++) {
				CounterEntry e = blockedList.get(i);
				sb.append("      <tr><td><code>").append(escapeHtml(e.key())).append("</code></td>");
				if (showSubnetDistinct) {
					if (e.distinctClients() > 0) {
						sb.append("<td><span class=\"badge\" style=\"font-size:0.75rem;padding:2px 6px;border-radius:4px;background:var(--accent-subtle);color:var(--text);\" title=\"Distinct client IPs in this subnet\">")
								.append(e.distinctClients()).append(e.distinctClients() == 1 ? " IP" : " IPs").append("</span></td>");
					} else {
						sb.append("<td style=\"color:var(--muted);\" title=\"Cardinality tracking inactive (Collector integration idle or disabled)\">-</td>");
					}
				}
				sb.append("<td>").append(e.count()).append("</td>")
						.append("<td>").append(e.retained()).append("</td>")
						.append("<td><strong>").append(e.effective()).append("</strong></td>");
				if (showReturning) {
					sb.append("<td>").append(e.returningCount()).append("</td>");
				}
				sb.append("<td>").append(allowedReqs).append("</td>")
						.append("<td><span class=\"badge badge-blocking\">BLOCKED</span></td></tr>\n");
			}
			sb.append("    </tbody>\n  </table>\n");
		}
		sb.append("</div>\n");

		// Card 4: Top Active Clients
		int activeTotal = selectedSlot != null ? selectedSlot.getActiveCounterCount() : 0;
		List<CounterEntry> activeList = (selectedSlot != null && effActiveLimit > 0)
				? extractTopEntries(selectedSlot.getActiveCounters(), effActiveLimit, false)
				: Collections.emptyList();
		int activeDisplay = activeList.size();

		sb.append("<div class=\"card\">\n")
				.append("  <div class=\"card-header\"><div class=\"card-title-group\"><span class=\"valve-name\">Top Active Clients (").append(escapeHtml(slotLabel)).append(")</span>")
				.append(" <span class=\"subtitle\">(").append(activeDisplay).append(activeTotal > activeDisplay ? " of " + activeTotal : "").append(" entries)</span></div></div>\n");

		if (activeDisplay == 0) {
			sb.append("  <div style=\"color:var(--muted);padding:4px 0;\">No active clients in ").append(escapeHtml(slotLabel.toLowerCase())).append(".</div>\n");
		} else {
			boolean showSubnetDistinct = target.isSubnetAggregationActive();
			boolean showReturning = target.isVisitorTrackingActive();
			sb.append("  <table class=\"data-table\">\n")
					.append("    <thead><tr><th>IP / Subnet Key</th>");
			if (showSubnetDistinct) {
				sb.append("<th title=\"Distinct client IP addresses observed in this subnet\">Distinct IPs</th>");
			}
			sb.append("<th>Slot Requests</th><th>Retained</th><th>Effective</th>")
					.append(showReturning ? "<th title=\"Requests carrying valid visitor cookie\">Returning</th>" : "")
					.append("<th>Limit</th><th>Quota Usage</th></tr></thead>\n")
					.append("    <tbody>\n");
			for (int i = 0; i < activeDisplay; i++) {
				CounterEntry e = activeList.get(i);
				int pct = allowedReqs > 0 ? (int) Math.min(100, Math.round((double) e.effective() / allowedReqs * 100)) : 0;
				String fillClass = pct > 85 ? "high" : (pct > 50 ? "med" : "");
				sb.append("      <tr><td><code>").append(escapeHtml(e.key())).append("</code></td>");
				if (showSubnetDistinct) {
					if (e.distinctClients() > 0) {
						sb.append("<td><span class=\"badge\" style=\"font-size:0.75rem;padding:2px 6px;border-radius:4px;background:var(--accent-subtle);color:var(--text);\" title=\"Distinct client IPs in this subnet\">")
								.append(e.distinctClients()).append(e.distinctClients() == 1 ? " IP" : " IPs").append("</span></td>");
					} else {
						sb.append("<td style=\"color:var(--muted);\" title=\"Cardinality tracking inactive (Collector integration idle or disabled)\">-</td>");
					}
				}
				sb.append("<td>").append(e.count()).append("</td>")
						.append("<td>").append(e.retained()).append("</td>")
						.append("<td><strong>").append(e.effective()).append("</strong></td>");
				if (showReturning) {
					sb.append("<td>").append(e.returningCount()).append("</td>");
				}
				sb.append("<td>").append(allowedReqs).append("</td>")
						.append("<td>").append(pct).append("% <div class=\"metric-bar\"><div class=\"metric-fill ").append(fillClass)
						.append("\" style=\"width:").append(pct).append("%\"></div></div></td></tr>\n");
			}
			sb.append("    </tbody>\n  </table>\n");
		}
		sb.append("</div>\n");

		sb.append("</body>\n</html>\n");
		return sb.toString();
	}

	public String buildStatusJson(String filterValve) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String serverTime = sdf.format(new Date(getTimeInMillis()));

		Set<AntiDoSValve> valves = getValvesToRender();

		StringBuilder sb = new StringBuilder(2048);
		sb.append("{\n  \"serverTime\": \"").append(serverTime).append("\",\n");
		sb.append("  \"totalActiveValves\": ").append(valves.size()).append(",\n");
		sb.append("  \"valves\": [\n");

		boolean first = true;
		int pipelineOrder = 0;
		for (AntiDoSValve v : valves) {
			pipelineOrder++;
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
			long currentSlotKey = monitor != null ? monitor.getCurrentSlotKey() : 0;
			AntiDoSSlot prevSlot = monitor != null ? monitor.getPreviousSlotIfExists() : null;

			int maxActive = v.getMaxIPCacheSize();
			int maxBlocked = v.getMaxBlockedIPCacheSize() > 0 ? v.getMaxBlockedIPCacheSize() : maxActive;

			sb.append("    {\n")
					.append("      \"monitorName\": \"").append(escapeJson(v.getMonitorName())).append("\",\n")
					.append("      \"description\": ").append(v.getDescription() != null ? "\"" + escapeJson(v.getDescription()) + "\"" : "null").append(",\n")
					.append("      \"pipelineOrder\": ").append(pipelineOrder).append(",\n")
					.append("      \"monitorMode\": \"").append(escapeJson(v.getMonitorMode())).append("\",\n")
					.append("      \"simulationMode\": ").append(v.isSimulationMode()).append(",\n")
					.append("      \"serverWideBlocking\": ").append(v.isServerWideBlocking()).append(",\n")
					.append("      \"relevantPaths\": ").append(v.getRelevantPathsConfigValue() != null ? "\"" + escapeJson(v.getRelevantPathsConfigValue()) + "\"" : "null").append(",\n")
					.append("      \"nonRelevantPaths\": ").append(v.getNonRelevantPathsConfigValue() != null ? "\"" + escapeJson(v.getNonRelevantPathsConfigValue()) + "\"" : "null").append(",\n")
					.append("      \"alwaysAllowedIPs\": ").append(v.getAlwaysAllowedIPsConfigValue() != null ? "\"" + escapeJson(v.getAlwaysAllowedIPsConfigValue()) + "\"" : "null").append(",\n")
					.append("      \"alwaysForbiddenIPs\": ").append(v.getAlwaysForbiddenIPsConfigValue() != null ? "\"" + escapeJson(v.getAlwaysForbiddenIPsConfigValue()) + "\"" : "null").append(",\n")
					.append("      \"allowedRequestsPerSlot\": ").append(v.getAllowedRequestsPerSlot()).append(",\n")
					.append("      \"slotLength\": ").append(v.getSlotLength()).append(",\n")
					.append("      \"numberOfSlots\": ").append(v.getNumberOfSlots()).append(",\n")
					.append("      \"shareOfRetainedFormerRequests\": ").append(v.getShareOfRetainedFormerRequests()).append(",\n")
					.append("      \"ipv4SubnetMask\": ").append(v.getIpv4SubnetMask()).append(",\n")
					.append("      \"ipv6SubnetMask\": ").append(v.getIpv6SubnetMask()).append(",\n")
					.append("      \"collectorIntegration\": \"").append(escapeJson(v.getCollectorIntegration())).append("\",\n")
					.append("      \"collectorActive\": ").append(v.isExtendedMetricsActive()).append(",\n")
					.append("      \"lastCollectorAccess\": ").append(v.getLastCollectorScrapeTime() > 0 ? "\"" + sdf.format(new Date(v.getLastCollectorScrapeTime())) + "\"" : "null").append(",\n")
					.append("      \"visitorCookieEnabled\": ").append(v.isVisitorTrackingActive()).append(",\n")
					.append("      \"visitorCookieInherited\": ").append(!v.isVisitorCookieEnabled() && v.isVisitorTrackingActive()).append(",\n")
					.append("      \"visitorCookieName\": \"").append(escapeJson(v.getEffectiveVisitorCookieName())).append("\",\n")
					.append("      \"visitorCookieDomain\": ").append(v.getEffectiveVisitorCookieDomain() != null ? "\"" + escapeJson(v.getEffectiveVisitorCookieDomain()) + "\"" : "null").append(",\n")
					.append("      \"maxIPCacheSize\": ").append(maxActive).append(",\n")
					.append("      \"maxBlockedIPCacheSize\": ").append(maxBlocked).append(",\n")
					.append("      \"currentActiveCounters\": ").append(activeCounters).append(",\n")
					.append("      \"currentBlockedCounters\": ").append(blockedCounters).append(",\n")
					.append("      \"currentSlotKey\": ").append(currentSlotKey).append(",\n")
					.append("      \"lastCompletedSlotKey\": ").append(currentSlotKey > 0 ? (currentSlotKey - 1) : 0).append(",\n")
					.append("      \"previousActiveCounters\": ").append(prevSlot != null ? prevSlot.getActiveCounterCount() : 0).append(",\n")
					.append("      \"previousBlockedCounters\": ").append(prevSlot != null ? prevSlot.getBlockedCounterCount() : 0).append(",\n")
					.append("      \"previousTotalRequests\": ").append(prevSlot != null ? prevSlot.getTotalRequests() : 0).append(",\n")
					.append("      \"totalRequests\": ").append(totalReqs).append(",\n")
					.append("      \"activeSlots\": ").append(activeSlots).append(",\n")
					.append("      \"statusUri\": ").append(v.getStatusUri() != null ? "\"" + escapeJson(v.getStatusUri()) + "\"" : "null").append(",\n")
					.append("      \"statusAllowedIPs\": ").append(v.getStatusAllowedIPs() != null ? "\"" + escapeJson(v.getStatusAllowedIPs()) + "\"" : "null").append(",\n")
					.append("      \"isStatusHost\": ").append(v.getStatusUri() != null).append(",\n")
					.append("      \"isCurrentHost\": ").append(v == valve).append(",\n")
					.append("      \"alwaysForbiddenBlockedRequests\": ").append(v.getAlwaysForbiddenBlockedRequests()).append(",\n")
					.append("      \"httpStatusCode\": ").append(v.getHttpStatusCode()).append("\n")
					.append("    }");
		}

		sb.append("\n  ]\n}\n");
		return sb.toString();
	}

	public String buildStatusJsonDetails(String filterValve) {
		return buildStatusJsonDetails(filterValve, null, null, null);
	}

	public String buildStatusJsonDetails(String filterValve, String slotParam, Integer limit) {
		return buildStatusJsonDetails(filterValve, slotParam, limit, limit);
	}

	public String buildStatusJsonDetails(String filterValve, String slotParam, Integer blockedLimit, Integer activeLimit) {
		return buildStatusJsonDetails(filterValve, slotParam, blockedLimit, activeLimit, null, null, null);
	}

	public String buildStatusJsonDetails(String filterValve, String slotParam, Integer blockedLimit, Integer activeLimit,
			Long sinceBlockedOrder, Long sinceActiveOrder, Integer activeMinCount) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String serverTime = sdf.format(new Date(getTimeInMillis()));

		AntiDoSValve target = null;
		Set<AntiDoSValve> valves = getValvesToRender();
		int targetPipelineOrder = 1;
		int orderCounter = 1;
		if (filterValve != null && !filterValve.trim().isEmpty()) {
			for (AntiDoSValve v : valves) {
				if (v.getMonitorName().equalsIgnoreCase(filterValve.trim())) {
					target = v;
					targetPipelineOrder = orderCounter;
					break;
				}
				orderCounter++;
			}
		} else if (valves.size() == 1) {
			target = valves.iterator().next();
			targetPipelineOrder = 1;
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
		long currentSlotKey = monitor != null ? monitor.getCurrentSlotKey() : 0;

		int effBlockedLimit = resolveEffectiveLimit(blockedLimit, null, 50);
		int effActiveLimit = resolveEffectiveLimit(activeLimit, null, 50);

		StringBuilder sb = new StringBuilder(4096);
		sb.append("{\n  \"serverTime\": \"").append(serverTime).append("\",\n");
		sb.append("  \"valve\": {\n")
				.append("    \"monitorName\": \"").append(escapeJson(target.getMonitorName())).append("\",\n")
				.append("    \"description\": ").append(target.getDescription() != null ? "\"" + escapeJson(target.getDescription()) + "\"" : "null").append(",\n")
				.append("    \"pipelineOrder\": ").append(targetPipelineOrder).append(",\n")
				.append("    \"monitorMode\": \"").append(escapeJson(target.getMonitorMode())).append("\",\n")
				.append("    \"simulationMode\": ").append(target.isSimulationMode()).append(",\n")
				.append("    \"serverWideBlocking\": ").append(target.isServerWideBlocking()).append(",\n")
				.append("    \"relevantPaths\": ").append(target.getRelevantPathsConfigValue() != null ? "\"" + escapeJson(target.getRelevantPathsConfigValue()) + "\"" : "null").append(",\n")
				.append("    \"nonRelevantPaths\": ").append(target.getNonRelevantPathsConfigValue() != null ? "\"" + escapeJson(target.getNonRelevantPathsConfigValue()) + "\"" : "null").append(",\n")
				.append("    \"alwaysAllowedIPs\": ").append(target.getAlwaysAllowedIPsConfigValue() != null ? "\"" + escapeJson(target.getAlwaysAllowedIPsConfigValue()) + "\"" : "null").append(",\n")
				.append("    \"alwaysForbiddenIPs\": ").append(target.getAlwaysForbiddenIPsConfigValue() != null ? "\"" + escapeJson(target.getAlwaysForbiddenIPsConfigValue()) + "\"" : "null").append(",\n")
				.append("    \"allowedRequestsPerSlot\": ").append(target.getAllowedRequestsPerSlot()).append(",\n")
				.append("    \"slotLength\": ").append(target.getSlotLength()).append(",\n")
				.append("    \"numberOfSlots\": ").append(target.getNumberOfSlots()).append(",\n")
				.append("    \"shareOfRetainedFormerRequests\": ").append(target.getShareOfRetainedFormerRequests()).append(",\n")
				.append("    \"ipv4SubnetMask\": ").append(target.getIpv4SubnetMask()).append(",\n")
				.append("    \"ipv6SubnetMask\": ").append(target.getIpv6SubnetMask()).append(",\n")
				.append("    \"collectorIntegration\": \"").append(escapeJson(target.getCollectorIntegration())).append("\",\n")
				.append("    \"collectorActive\": ").append(target.isExtendedMetricsActive()).append(",\n")
				.append("    \"lastCollectorAccess\": ").append(target.getLastCollectorScrapeTime() > 0 ? "\"" + sdf.format(new Date(target.getLastCollectorScrapeTime())) + "\"" : "null").append(",\n")
				.append("    \"visitorCookieEnabled\": ").append(target.isVisitorTrackingActive()).append(",\n")
				.append("    \"visitorCookieInherited\": ").append(!target.isVisitorCookieEnabled() && target.isVisitorTrackingActive()).append(",\n")
				.append("    \"visitorCookieName\": \"").append(escapeJson(target.getEffectiveVisitorCookieName())).append("\",\n")
				.append("    \"visitorCookieDomain\": ").append(target.getEffectiveVisitorCookieDomain() != null ? "\"" + escapeJson(target.getEffectiveVisitorCookieDomain()) + "\"" : "null").append(",\n")
				.append("    \"maxIPCacheSize\": ").append(maxActive).append(",\n")
				.append("    \"maxBlockedIPCacheSize\": ").append(maxBlocked).append(",\n")
				.append("    \"currentActiveCounters\": ").append(activeCounters).append(",\n")
				.append("    \"currentBlockedCounters\": ").append(blockedCounters).append(",\n")
				.append("    \"currentSlotKey\": ").append(currentSlotKey).append(",\n")
				.append("    \"lastCompletedSlotKey\": ").append(currentSlotKey > 0 ? (currentSlotKey - 1) : 0).append(",\n")
				.append("    \"totalRequests\": ").append(totalReqs).append(",\n")
				.append("    \"activeSlots\": ").append(activeSlots).append(",\n")
				.append("    \"statusUri\": ").append(target.getStatusUri() != null ? "\"" + escapeJson(target.getStatusUri()) + "\"" : "null").append(",\n")
				.append("    \"statusAllowedIPs\": ").append(target.getStatusAllowedIPs() != null ? "\"" + escapeJson(target.getStatusAllowedIPs()) + "\"" : "null").append(",\n")
				.append("    \"isStatusHost\": ").append(target.getStatusUri() != null).append(",\n")
				.append("    \"isCurrentHost\": ").append(target == valve).append(",\n")
				.append("    \"alwaysForbiddenBlockedRequests\": ").append(target.getAlwaysForbiddenBlockedRequests()).append(",\n")
				.append("    \"httpStatusCode\": ").append(target.getHttpStatusCode()).append("\n")
				.append("  },\n");

		// Slots array
		int numSlots = monitor != null ? monitor.getNumberOfSlots() : target.getNumberOfSlots();
		int slotLength = monitor != null ? monitor.getSlotLength() : target.getSlotLength();
		sb.append("  \"slots\": [\n");
		boolean firstSlot = true;
		if (monitor != null) {
			for (int i = 0; i < numSlots; i++) {
				AntiDoSSlot slot = monitor.getSlot(i);
				if (!firstSlot) sb.append(",\n");
				firstSlot = false;
				if (slot == null) {
					sb.append("    {\"index\": ").append(i).append(", \"slotKey\": null, \"totalRequests\": 0}");
				} else {
					long slotKey = slot.getSlotKey();
					boolean isCurrent = (slotKey == currentSlotKey);
					long ageSec = (currentSlotKey - slotKey) * (slotLength / 1000);
					String startTime = sdf.format(new Date(slotKey * slotLength));
					String endTime = sdf.format(new Date((slotKey + 1) * slotLength));
					sb.append("    {\n")
							.append("      \"index\": ").append(i).append(",\n")
							.append("      \"slotKey\": ").append(slotKey).append(",\n")
							.append("      \"isCurrent\": ").append(isCurrent).append(",\n")
							.append("      \"startTime\": \"").append(startTime).append("\",\n")
							.append("      \"endTime\": \"").append(endTime).append("\",\n")
							.append("      \"ageSeconds\": ").append(ageSec).append(",\n")
							.append("      \"totalRequests\": ").append(slot.getTotalRequests()).append(",\n")
							.append("      \"activeCounters\": ").append(slot.getActiveCounterCount()).append(",\n")
							.append("      \"blockedCounters\": ").append(slot.getBlockedCounterCount()).append("\n")
							.append("    }");
				}
			}
		}
		sb.append("\n  ],\n");

		// Selected slot metadata
		AntiDoSSlot selectedSlot = resolveTargetSlot(monitor, slotParam);
		String selectedSlotType = determineSlotType(monitor, selectedSlot, slotParam);
		if (selectedSlot == null) {
			sb.append("  \"selectedSlot\": null,\n");
		} else {
			long selKey = selectedSlot.getSlotKey();
			boolean selIsCurrent = (selKey == currentSlotKey);
			long selAgeSec = (currentSlotKey - selKey) * (slotLength / 1000);
			String selStart = sdf.format(new Date(selKey * slotLength));
			String selEnd = sdf.format(new Date((selKey + 1) * slotLength));
			int selIndex = (int) Math.floorMod(selKey, numSlots);
			sb.append("  \"selectedSlot\": {\n")
					.append("    \"type\": \"").append(escapeJson(selectedSlotType)).append("\",\n")
					.append("    \"index\": ").append(selIndex).append(",\n")
					.append("    \"slotKey\": ").append(selKey).append(",\n")
					.append("    \"isCurrent\": ").append(selIsCurrent).append(",\n")
					.append("    \"startTime\": \"").append(selStart).append("\",\n")
					.append("    \"endTime\": \"").append(selEnd).append("\",\n")
					.append("    \"ageSeconds\": ").append(selAgeSec).append(",\n")
					.append("    \"totalRequests\": ").append(selectedSlot.getTotalRequests()).append(",\n")
					.append("    \"activeCounters\": ").append(selectedSlot.getActiveCounterCount()).append(",\n")
					.append("    \"blockedCounters\": ").append(selectedSlot.getBlockedCounterCount()).append("\n")
					.append("  },\n");
		}

		// Blocked clients array
		int totalBlockedClients = selectedSlot != null ? selectedSlot.getBlockedCounterCount() : 0;
		FilteredEntries blockedEntries;
		if (selectedSlot == null) {
			blockedEntries = new FilteredEntries(Collections.emptyList(), 0L);
		} else if (sinceBlockedOrder != null) {
			blockedEntries = extractFilteredEntries(selectedSlot.getBlockedCounters(), sinceBlockedOrder, null, true);
		} else if (effBlockedLimit > 0) {
			blockedEntries = extractTopEntriesWithMax(selectedSlot.getBlockedCounters(), effBlockedLimit, true);
		} else {
			blockedEntries = extractTopEntriesWithMax(selectedSlot.getBlockedCounters(), 0, true);
		}
		List<CounterEntry> blockedList = blockedEntries.entries();

		sb.append("  \"blockedLimit\": ").append(effBlockedLimit == Integer.MAX_VALUE ? "null" : effBlockedLimit).append(",\n")
				.append("  \"totalBlockedClients\": ").append(totalBlockedClients).append(",\n")
				.append("  \"maxBlockedOrder\": ").append(blockedEntries.maxOrder()).append(",\n");
		if (sinceBlockedOrder != null) {
			sb.append("  \"sinceBlockedOrder\": ").append(sinceBlockedOrder).append(",\n");
		}
		sb.append("  \"blockedClients\": [\n");
		for (int i = 0; i < blockedList.size(); i++) {
			if (i > 0) sb.append(",\n");
			CounterEntry e = blockedList.get(i);
			sb.append("    {\n")
					.append("      \"key\": \"").append(escapeJson(e.key())).append("\",\n")
					.append("      \"count\": ").append(e.count()).append(",\n")
					.append("      \"retained\": ").append(e.retained()).append(",\n")
					.append("      \"effective\": ").append(e.effective()).append(",\n")
					.append("      \"limit\": ").append(target.getAllowedRequestsPerSlot()).append(",\n")
					.append("      \"distinctClients\": ").append(e.distinctClients() > 0 ? e.distinctClients() : 1).append(",\n")
					.append("      \"returningCount\": ").append(target.isVisitorTrackingActive() ? e.returningCount() : "null").append(",\n")
					.append("      \"status\": \"BLOCKED\"\n")
					.append("    }");
		}
		sb.append("\n  ],\n");

		// Top active clients array
		int totalActiveClients = selectedSlot != null ? selectedSlot.getActiveCounterCount() : 0;
		FilteredEntries activeEntries;
		if (selectedSlot == null) {
			activeEntries = new FilteredEntries(Collections.emptyList(), 0L);
		} else if (sinceActiveOrder != null) {
			activeEntries = extractFilteredEntries(selectedSlot.getActiveCounters(), sinceActiveOrder, activeMinCount, false);
		} else if (effActiveLimit > 0) {
			activeEntries = extractTopEntriesWithMax(selectedSlot.getActiveCounters(), effActiveLimit, false);
		} else {
			activeEntries = extractTopEntriesWithMax(selectedSlot.getActiveCounters(), 0, false);
		}
		List<CounterEntry> activeList = activeEntries.entries();

		sb.append("  \"activeLimit\": ").append(effActiveLimit == Integer.MAX_VALUE ? "null" : effActiveLimit).append(",\n")
				.append("  \"totalActiveClients\": ").append(totalActiveClients).append(",\n")
				.append("  \"maxActiveOrder\": ").append(activeEntries.maxOrder()).append(",\n");
		if (sinceActiveOrder != null) {
			sb.append("  \"sinceActiveOrder\": ").append(sinceActiveOrder).append(",\n");
		}
		if (activeMinCount != null) {
			sb.append("  \"activeMinCount\": ").append(activeMinCount).append(",\n");
		}
		sb.append("  \"topActiveClients\": [\n");
		for (int i = 0; i < activeList.size(); i++) {
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
					.append("      \"quotaPercent\": ").append(pct).append(",\n")
					.append("      \"distinctClients\": ").append(e.distinctClients() > 0 ? e.distinctClients() : 1).append(",\n")
					.append("      \"returningCount\": ").append(target.isVisitorTrackingActive() ? e.returningCount() : "null").append("\n")
					.append("    }");
		}
		sb.append("\n  ]\n}\n");
		return sb.toString();
	}

	public static String escapeHtml(String text) {
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

	public static String escapeJson(String text) {
		if (text == null) return "";
		// Fast path for clean ASCII strings without quotes or control characters (e.g. IPs and CIDR keys)
		boolean needsEscaping = false;
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (c == '"' || c == '\\' || c < ' ') {
				needsEscaping = true;
				break;
			}
		}
		if (!needsEscaping) {
			return text;
		}

		StringBuilder sb = new StringBuilder(text.length() + 16);
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
}
