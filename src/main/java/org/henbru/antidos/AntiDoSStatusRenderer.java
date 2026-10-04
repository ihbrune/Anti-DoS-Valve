package org.henbru.antidos;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
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

	public static String buildDashboardUrl(String token, String valve, String view, String format) {
		return buildDashboardUrl(token, valve, view, format, true);
	}

	public static String buildDashboardUrl(String token, String valve, String view, String format, boolean forHtml) {
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
	 * Generates and writes the HTML status dashboard to the HTTP response.
	 *
	 * @param response    The HTTP response
	 * @param filterValve The valve to filter by
	 * @param view        The dashboard view ("details" or overview)
	 * @param token       The active access token for building carry-over links
	 * @throws IOException If an I/O error occurs
	 */
	public void renderStatusHtml(Response response, String filterValve, String view, String token) throws IOException {
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
	 * Generates and writes the JSON status dashboard to the HTTP response.
	 *
	 * @param response    The HTTP response
	 * @param filterValve The valve to filter by
	 * @param view        The dashboard view ("details" or overview)
	 * @throws IOException If an I/O error occurs
	 */
	public void renderStatusJson(Response response, String filterValve, String view) throws IOException {
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
		return valve.getValvesToRender();
	}

	private long getTimeInMillis() {
		return valve.getTimeInMillis();
	}

	public String buildStatusHtml(String filterValve) {
		return buildStatusHtml(filterValve, null);
	}

	public String buildStatusHtml(String filterValve, String token) {
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
				.append(".badge-status{background:#064e3b;color:#6ee7b7;border:1px solid #047857}\n")
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
				.append(" &bull; Active Valves: ").append(valves.size());
		if (valve != null && valve.getStatusUri() != null) {
			sb.append(" &bull; Dashboard Host: <strong>").append(escapeHtml(valve.getName4logging()))
					.append("</strong> (<code>").append(escapeHtml(valve.getStatusUri())).append("</code>)");
		}
		sb.append("</span>")
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
					.append("  </div>\n")
					.append("  <table>\n");

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

	public String buildStatusHtmlDetails(String valveName, String token) {
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
				.append(".badge-status{background:#064e3b;color:#6ee7b7;border:1px solid #047857}\n")
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
				.append("    <span>Server Time: ").append(serverTime);
		if (valve != null && valve.getStatusUri() != null) {
			sb.append(" &bull; Dashboard Host: <strong>").append(escapeHtml(valve.getName4logging()))
					.append("</strong> (<code>").append(escapeHtml(valve.getStatusUri())).append("</code>)");
		}
		sb.append("</span>\n")
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
				.append("  </div>\n")
				.append("  <table>\n");

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
					.append("      \"statusUri\": ").append(v.getStatusUri() != null ? "\"" + escapeJson(v.getStatusUri()) + "\"" : "null").append(",\n")
					.append("      \"isStatusHost\": ").append(v.getStatusUri() != null).append(",\n")
					.append("      \"isCurrentHost\": ").append(v == valve).append(",\n")
					.append("      \"httpStatusCode\": ").append(v.getHttpStatusCode()).append("\n")
					.append("    }");
		}

		sb.append("\n  ]\n}\n");
		return sb.toString();
	}

	public String buildStatusJsonDetails(String filterValve) {
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
				.append("    \"statusUri\": ").append(target.getStatusUri() != null ? "\"" + escapeJson(target.getStatusUri()) + "\"" : "null").append(",\n")
				.append("    \"isStatusHost\": ").append(target.getStatusUri() != null).append(",\n")
				.append("    \"isCurrentHost\": ").append(target == valve).append(",\n")
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
}
