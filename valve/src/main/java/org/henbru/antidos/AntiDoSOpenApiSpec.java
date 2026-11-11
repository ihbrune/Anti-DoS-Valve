package org.henbru.antidos;

/**
 * Provides the OpenAPI 3.1.0 specification for the Apache Tomcat Anti-DoS Valve
 * status and monitoring endpoints.
 * <p>
 * This specification can be consumed directly by SIEM systems (e.g. Splunk,
 * Elastic, Microsoft Sentinel), Postman, Insomnia, and OpenAPI SDK generators.
 */
public final class AntiDoSOpenApiSpec {

	private AntiDoSOpenApiSpec() {
		// Utility class
	}

	public static final String DEFAULT_STATUS_URI = "/antidos-status";

	/**
	 * Builds and returns the OpenAPI 3.1.0 JSON specification for the given status URI.
	 *
	 * @param statusUri The configured status URI (e.g. "/antidos-status")
	 * @return The formatted OpenAPI JSON string
	 */
	public static String buildOpenApiJson(String statusUri) {
		String uri = (statusUri != null && !statusUri.trim().isEmpty()) ? statusUri.trim() : DEFAULT_STATUS_URI;
		return OPENAPI_JSON_TEMPLATE.replace("{{STATUS_URI}}", uri);
	}

	/**
	 * Builds and returns the OpenAPI 3.1.0 JSON specification using the default status URI.
	 *
	 * @return The formatted OpenAPI JSON string
	 */
	public static String buildOpenApiJson() {
		return buildOpenApiJson(DEFAULT_STATUS_URI);
	}

	private static final String OPENAPI_JSON_TEMPLATE = """
{
  "openapi": "3.1.0",
  "info": {
    "title": "Anti-DoS Valve Monitor & Metrics API",
    "description": "High-performance Apache Tomcat Valve protecting web applications against Denial-of-Service (DoS) and abusive request rates. This API exposes real-time monitor states, sliding-window slot statistics, and counter forensics for SIEM and monitoring integrations.",
    "version": "1.9.0",
    "license": {
      "name": "Apache-2.0",
      "url": "https://www.apache.org/licenses/LICENSE-2.0.html"
    }
  },
  "servers": [
    {
      "url": "/",
      "description": "Current Tomcat Server"
    }
  ],
  "security": [
    {
      "BearerAuth": []
    },
    {
      "TokenQuery": []
    }
  ],
  "paths": {
    "{{STATUS_URI}}": {
      "get": {
        "summary": "Query Valve monitor metrics, counter caches, or OpenAPI documentation",
        "description": "Retrieves monitor configuration, sliding-window slot statistics, active/blocked client IP counters, or the OpenAPI specification. Supports content negotiation via the 'format' query parameter or the 'Accept' header.",
        "operationId": "getValveStatus",
        "parameters": [
          {
            "name": "format",
            "in": "query",
            "description": "Response format: 'json' for metrics, 'openapi' or 'openapi.json' for the machine-readable OpenAPI specification.",
            "required": false,
            "schema": {
              "type": "string",
              "enum": [
                "json",
                "openapi",
                "openapi.json"
              ]
            }
          },
          {
            "name": "view",
            "in": "query",
            "description": "View selection: 'summary' (default overview of all valves), 'details' (in-depth counter caches & slots for a valve), 'docs' (interactive HTML documentation), or 'openapi' (OpenAPI JSON).",
            "required": false,
            "schema": {
              "type": "string",
              "enum": [
                "summary",
                "details",
                "docs",
                "openapi",
                "openapi.json"
              ],
              "default": "summary"
            }
          },
          {
            "name": "valve",
            "in": "query",
            "description": "Filter by monitorName when multiple Anti-DoS Valves are configured in the Catalina pipeline.",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "slot",
            "in": "query",
            "description": "Target slot in details view: 'current', 'previous', or a specific numeric slotKey.",
            "required": false,
            "schema": {
              "type": "string",
              "default": "current"
            }
          },
          {
            "name": "limit",
            "in": "query",
            "description": "Default max entries returned in counter arrays (fallback for blockedLimit and activeLimit).",
            "required": false,
            "schema": {
              "type": "integer",
              "default": 50
            }
          },
          {
            "name": "blockedLimit",
            "in": "query",
            "description": "Max blocked clients returned in details view. Supports positive integers, 'all', or '-1' for unlimited.",
            "required": false,
            "schema": {
              "type": "integer",
              "default": 50
            }
          },
          {
            "name": "activeLimit",
            "in": "query",
            "description": "Max top active clients returned in details view. Supports positive integers, 'all', or '-1' for unlimited.",
            "required": false,
            "schema": {
              "type": "integer",
              "default": 50
            }
          },
          {
            "name": "sinceBlockedOrder",
            "in": "query",
            "description": "Incremental cursor for blocked counters (pagination). Returns only counters with order > sinceBlockedOrder.",
            "required": false,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          },
          {
            "name": "sinceActiveOrder",
            "in": "query",
            "description": "Incremental cursor for active counters (pagination). Returns only counters with order > sinceActiveOrder.",
            "required": false,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          },
          {
            "name": "activeMinCount",
            "in": "query",
            "description": "Minimum request count filter for top active clients list.",
            "required": false,
            "schema": {
              "type": "integer"
            }
          },
          {
            "name": "includeDynamicBlocks",
            "in": "query",
            "description": "Whether to include dynamic CIDR blocks in slot details response (defaults to true if slot is omitted, false if a slot is specified).",
            "required": false,
            "schema": {
              "type": "boolean"
            }
          },
          {
            "name": "token",
            "in": "query",
            "description": "Authentication token/password (alternative to Bearer Authorization header).",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "Authorization",
            "in": "header",
            "description": "Bearer token authentication header (e.g. 'Bearer <token>').",
            "required": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "Accept",
            "in": "header",
            "description": "Content negotiation header. Use 'application/json' for JSON responses, 'application/vnd.oai.openapi+json' for OpenAPI, or 'text/html' for HTML dashboard.",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Successful response containing either monitor summary, counter details, OpenAPI specification, or HTML dashboard.",
            "content": {
              "application/json": {
                "schema": {
                  "oneOf": [
                    {
                      "$ref": "#/components/schemas/ValveSummaryResponse"
                    },
                    {
                      "$ref": "#/components/schemas/ValveDetailsResponse"
                    },
                    {
                      "$ref": "#/components/schemas/OpenApiSpecResponse"
                    }
                  ]
                }
              },
              "text/html": {
                "schema": {
                  "type": "string",
                  "description": "Self-contained HTML status dashboard or interactive API documentation."
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized: Missing or invalid authentication token/password. Note: Failed authentication attempts are asymmetrically counted in the monitor against the requesting client IP.",
            "content": {
              "text/html": {
                "schema": {
                  "type": "string"
                }
              }
            }
          },
          "404": {
            "description": "Not Found: The client IP address is not permitted by 'statusAllowedIPs'.",
            "content": {
              "text/html": {
                "schema": {
                  "type": "string"
                }
              }
            }
          },
          "429": {
            "description": "Too Many Requests: The requesting client IP is currently blocked by the monitor and provided no valid token.",
            "headers": {
              "Retry-After": {
                "description": "Seconds until client IP block window expires.",
                "schema": {
                  "type": "integer"
                }
              }
            },
            "content": {
              "text/html": {
                "schema": {
                  "type": "string"
                }
              }
            }
          }
        }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "BearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "description": "Bearer token authentication passed in the HTTP Authorization header."
      },
      "TokenQuery": {
        "type": "apiKey",
        "in": "query",
        "name": "token",
        "description": "Authentication token passed as query parameter."
      }
    },
    "schemas": {
      "ValveSummaryResponse": {
        "type": "object",
        "required": [
          "serverTime",
          "totalActiveValves",
          "valves"
        ],
        "properties": {
          "serverTime": {
            "type": "string",
            "format": "date-time",
            "description": "Server time in ISO-8601 UTC format (e.g. 2026-11-07T22:30:00Z)."
          },
          "totalActiveValves": {
            "type": "integer",
            "description": "Total number of Anti-DoS Valve instances configured in the pipeline."
          },
          "valves": {
            "type": "array",
            "items": {
              "$ref": "#/components/schemas/ValveSummaryDto"
            }
          },
          "serverGenerationMs": {
            "type": "integer",
            "format": "int64",
            "description": "Time in milliseconds taken by the server to generate this JSON response."
          }
        }
      },
      "ValveSummaryDto": {
        "type": "object",
        "required": [
          "monitorName",
          "pipelineOrder",
          "monitorMode",
          "simulationMode",
          "serverWideBlocking",
          "allowedRequestsPerSlot",
          "slotLength",
          "numberOfSlots",
          "shareOfRetainedFormerRequests",
          "ipv4SubnetMask",
          "ipv6SubnetMask",
          "collectorIntegration",
          "collectorActive",
          "visitorCookieEnabled",
          "visitorCookieInherited",
          "visitorCookieName",
          "authTrackingEnabled",
          "authTrackingInherited",
          "authTrackingMode",
          "relevantAuthScope",
          "authSessionTtlSeconds",
          "maxAuthCacheSize",
          "activeAuthSessions",
          "maxIPCacheSize",
          "maxBlockedIPCacheSize",
          "currentActiveCounters",
          "currentBlockedCounters",
          "currentSlotKey",
          "lastCompletedSlotKey",
          "previousActiveCounters",
          "previousBlockedCounters",
          "previousTotalRequests",
          "previousAuthenticatedRequests",
          "totalRequests",
          "totalAuthenticatedRequests",
          "activeSlots",
          "activeSampleThreshold",
          "isStatusHost",
          "isCurrentHost",
          "alwaysForbiddenBlockedRequests",
          "httpStatusCode"
        ],
        "properties": {
          "monitorName": {
            "type": "string",
            "description": "Unique identifier of the Valve monitor."
          },
          "description": {
            "type": [
              "string",
              "null"
            ],
            "description": "Optional human-readable description of the Valve purpose."
          },
          "pipelineOrder": {
            "type": "integer",
            "description": "1-based order index of this Valve in the Catalina pipeline."
          },
          "monitorMode": {
            "type": "string",
            "enum": [
              "BLOCKING",
              "MARKING",
              "SIMULATION"
            ],
            "description": "Operational mode of the Valve."
          },
          "simulationMode": {
            "type": "boolean",
            "description": "Whether simulation mode is active (log-only, no requests rejected)."
          },
          "serverWideBlocking": {
            "type": "boolean",
            "description": "Whether blocked clients are rejected server-wide across all applications."
          },
          "relevantPaths": {
            "type": [
              "string",
              "null"
            ],
            "description": "Regular expression pattern of monitored request paths."
          },
          "nonRelevantPaths": {
            "type": [
              "string",
              "null"
            ],
            "description": "Regular expression pattern of excluded request paths (e.g. static assets)."
          },
          "alwaysAllowedIPs": {
            "type": [
              "string",
              "null"
            ],
            "description": "Regular expression pattern of whitelisted IPs that bypass rate limits."
          },
          "alwaysAllowPrivateIPs": {
            "type": "boolean",
            "description": "Whether requests from RFC 1918, RFC 4193 ULA, loopback, and link-local addresses unconditionally bypass rate limits."
          },
          "alwaysForbiddenIPs": {
            "type": [
              "string",
              "null"
            ],
            "description": "Regular expression pattern of blacklisted IPs that are unconditionally rejected."
          },
          "trackAlwaysForbiddenInMonitor": {
            "type": "boolean",
            "description": "Whether hits from alwaysForbiddenIPs are tracked in the monitor cache."
          },
          "allowedRequestsPerSlot": {
            "type": "integer",
            "description": "Maximum allowed requests per client per sliding time slot."
          },
          "slotLength": {
            "type": "integer",
            "description": "Duration of each sliding time slot in seconds."
          },
          "numberOfSlots": {
            "type": "integer",
            "description": "Number of sliding time slots maintained in memory."
          },
          "shareOfRetainedFormerRequests": {
            "type": "number",
            "format": "double",
            "description": "Fraction of request counts retained and carried forward into subsequent slots."
          },
          "ipv4SubnetMask": {
            "type": "integer",
            "description": "IPv4 CIDR subnet mask prefix for counter aggregation (e.g. 32 for host, 24 for class C)."
          },
          "ipv6SubnetMask": {
            "type": "integer",
            "description": "IPv6 CIDR subnet mask prefix for counter aggregation (e.g. 64 or 128)."
          },
          "collectorIntegration": {
            "type": "string",
            "enum": [
              "AUTO",
              "OFF",
              "FORCE"
            ],
            "description": "Mode for collector telemetry collection and lease management."
          },
          "collectorActive": {
            "type": "boolean",
            "description": "Whether an external Collector instance holds an active scrape lease."
          },
          "lastCollectorAccess": {
            "type": [
              "string",
              "null"
            ],
            "format": "date-time",
            "description": "Timestamp of the most recent scrape by the Collector."
          },
          "visitorCookieEnabled": {
            "type": "boolean",
            "description": "Whether visitor cookie tracking is enabled directly on this Valve."
          },
          "visitorCookieInherited": {
            "type": "boolean",
            "description": "Whether visitor cookie tracking is inherited from an upstream Valve in the pipeline."
          },
          "visitorCookieName": {
            "type": "string",
            "description": "Name of the HTTP cookie used for visitor tracking."
          },
          "visitorCookieDomain": {
            "type": [
              "string",
              "null"
            ],
            "description": "Optional cookie domain for visitor tracking."
          },
          "authTrackingEnabled": {
            "type": "boolean",
            "description": "Whether authenticated session tracking is enabled directly on this Valve."
          },
          "authTrackingInherited": {
            "type": "boolean",
            "description": "Whether authenticated session tracking is inherited from an upstream Valve."
          },
          "authTrackingMode": {
            "type": "string",
            "description": "Mode used for authenticated tracking (e.g. COOKIE, HEADER, AUTO, DISABLED)."
          },
          "relevantAuthScope": {
            "type": "string",
            "description": "Scope of authenticated tracking (e.g. ALL, PATHS)."
          },
          "authCookieName": {
            "type": [
              "string",
              "null"
            ],
            "description": "Name of the cookie identifying authenticated sessions."
          },
          "authLoginPaths": {
            "type": [
              "string",
              "null"
            ],
            "description": "Regular expression pattern of login paths establishing authentication."
          },
          "authSessionTtlSeconds": {
            "type": "integer",
            "description": "Fallback time-to-live for authenticated session cache entries in seconds."
          },
          "maxAuthCacheSize": {
            "type": "integer",
            "description": "Maximum capacity of the authenticated session cache."
          },
          "activeAuthSessions": {
            "type": "integer",
            "description": "Current number of active authenticated sessions."
          },
          "maxIPCacheSize": {
            "type": "integer",
            "description": "Maximum capacity of the active IP counter cache per slot."
          },
          "maxBlockedIPCacheSize": {
            "type": "integer",
            "description": "Maximum capacity of the blocked IP counter cache per slot."
          },
          "currentActiveCounters": {
            "type": "integer",
            "description": "Number of currently active client IP counters in the current slot."
          },
          "currentBlockedCounters": {
            "type": "integer",
            "description": "Number of currently blocked client IP counters in the current slot."
          },
          "currentSlotKey": {
            "type": "integer",
            "format": "int64",
            "description": "Epoch slot index of the current active sliding window slot."
          },
          "lastCompletedSlotKey": {
            "type": "integer",
            "format": "int64",
            "description": "Epoch slot index of the last completed sliding window slot."
          },
          "previousActiveCounters": {
            "type": "integer",
            "description": "Number of active counters in the previous completed slot."
          },
          "previousBlockedCounters": {
            "type": "integer",
            "description": "Number of blocked counters in the previous completed slot."
          },
          "previousTotalRequests": {
            "type": "integer",
            "format": "int64",
            "description": "Total requests processed during the previous completed slot."
          },
          "previousAuthenticatedRequests": {
            "type": "integer",
            "format": "int64",
            "description": "Authenticated requests processed during the previous completed slot."
          },
          "totalRequests": {
            "type": "integer",
            "format": "int64",
            "description": "Total lifetime requests registered by this Valve monitor."
          },
          "totalAuthenticatedRequests": {
            "type": "integer",
            "format": "int64",
            "description": "Total lifetime authenticated requests registered by this Valve monitor."
          },
          "activeSlots": {
            "type": "integer",
            "description": "Number of active sliding-window slot buffers currently allocated in memory."
          },
          "statusUri": {
            "type": [
              "string",
              "null"
            ],
            "description": "Configured URI path serving this status and OpenAPI endpoint."
          },
          "statusAllowedIPs": {
            "type": [
              "string",
              "null"
            ],
            "description": "Regular expression pattern of IP addresses permitted to access status and API endpoints."
          },
          "activeSampleThreshold": {
            "type": "integer",
            "description": "Threshold of requests required before client request samples (URI, method, user-agent) are captured."
          },
          "isStatusHost": {
            "type": "boolean",
            "description": "Whether this specific Valve instance hosts the statusUri endpoint."
          },
          "isCurrentHost": {
            "type": "boolean",
            "description": "Whether this specific Valve instance is serving the current HTTP request."
          },
          "alwaysForbiddenBlockedRequests": {
            "type": "integer",
            "format": "int64",
            "description": "Total requests rejected due to matching alwaysForbiddenIPs."
          },
          "statusConcurrencyTimeoutMs": {
            "type": "integer",
            "description": "Timeout in milliseconds to wait for the status generation semaphore before returning HTTP 429."
          },
          "httpStatusCode": {
            "type": "integer",
            "description": "HTTP status code sent when rejecting abusive requests (default: 429)."
          }
        }
      },
      "ValveDetailsResponse": {
        "type": "object",
        "required": [
          "serverTime",
          "valve",
          "slots",
          "totalBlockedClients",
          "maxBlockedOrder",
          "blockedClients",
          "totalActiveClients",
          "maxActiveOrder",
          "topActiveClients"
        ],
        "properties": {
          "serverTime": {
            "type": "string",
            "format": "date-time",
            "description": "Server time in ISO-8601 UTC format."
          },
          "valve": {
            "$ref": "#/components/schemas/ValveSummaryDto"
          },
          "slots": {
            "type": "array",
            "description": "Ring-buffer history of sliding window slots.",
            "items": {
              "$ref": "#/components/schemas/SlotDto"
            }
          },
          "selectedSlot": {
            "anyOf": [
              {
                "$ref": "#/components/schemas/SelectedSlotDto"
              },
              {
                "type": "null"
              }
            ],
            "description": "Detailed metadata for the currently inspected slot."
          },
          "blockedLimit": {
            "type": [
              "integer",
              "null"
            ],
            "description": "Effective limit applied to the returned blockedClients array."
          },
          "totalBlockedClients": {
            "type": "integer",
            "description": "Total number of blocked clients in the inspected slot."
          },
          "maxBlockedOrder": {
            "type": "integer",
            "format": "int64",
            "description": "Highest insertion order sequence number among blocked counters (used for incremental cursor pagination)."
          },
          "sinceBlockedOrder": {
            "type": "integer",
            "format": "int64",
            "description": "Echoed cursor parameter if provided in request."
          },
          "blockedClients": {
            "type": "array",
            "description": "List of currently blocked client IP addresses or subnets.",
            "items": {
              "$ref": "#/components/schemas/CounterEntryDto"
            }
          },
          "activeLimit": {
            "type": [
              "integer",
              "null"
            ],
            "description": "Effective limit applied to the returned topActiveClients array."
          },
          "totalActiveClients": {
            "type": "integer",
            "description": "Total number of active clients in the inspected slot."
          },
          "maxActiveOrder": {
            "type": "integer",
            "format": "int64",
            "description": "Highest insertion order sequence number among active counters (used for incremental cursor pagination)."
          },
          "sinceActiveOrder": {
            "type": "integer",
            "format": "int64",
            "description": "Echoed cursor parameter if provided in request."
          },
          "activeMinCount": {
            "type": "integer",
            "description": "Echoed minimum request count filter if provided in request."
          },
          "topActiveClients": {
            "type": "array",
            "description": "List of top active client IP addresses or subnets.",
            "items": {
              "$ref": "#/components/schemas/ActiveCounterEntryDto"
            }
          },
          "serverGenerationMs": {
            "type": "integer",
            "format": "int64",
            "description": "Time in milliseconds taken by the server to generate this JSON response."
          }
        }
      },
      "SlotDto": {
        "type": "object",
        "required": [
          "index",
          "totalRequests",
          "authenticatedRequests"
        ],
        "properties": {
          "index": {
            "type": "integer",
            "description": "Index of the slot in the internal ring buffer."
          },
          "slotKey": {
            "type": [
              "integer",
              "null"
            ],
            "format": "int64",
            "description": "Epoch slot index."
          },
          "isCurrent": {
            "type": "boolean",
            "description": "Whether this slot represents the active current window."
          },
          "startTime": {
            "type": "string",
            "format": "date-time",
            "description": "Start timestamp of the slot."
          },
          "endTime": {
            "type": "string",
            "format": "date-time",
            "description": "End timestamp of the slot."
          },
          "ageSeconds": {
            "type": "integer",
            "format": "int64",
            "description": "Age of the slot relative to the current slot in seconds."
          },
          "totalRequests": {
            "type": "integer",
            "format": "int64",
            "description": "Total requests registered during this slot."
          },
          "authenticatedRequests": {
            "type": "integer",
            "format": "int64",
            "description": "Authenticated requests registered during this slot."
          },
          "activeCounters": {
            "type": "integer",
            "description": "Number of active client counters in this slot."
          },
          "blockedCounters": {
            "type": "integer",
            "description": "Number of blocked client counters in this slot."
          }
        }
      },
      "SelectedSlotDto": {
        "type": "object",
        "required": [
          "type",
          "index",
          "slotKey",
          "isCurrent",
          "startTime",
          "endTime",
          "ageSeconds",
          "totalRequests",
          "authenticatedRequests",
          "activeCounters",
          "blockedCounters"
        ],
        "properties": {
          "type": {
            "type": "string",
            "description": "Classification of slot (CURRENT, PREVIOUS, HISTORICAL)."
          },
          "index": {
            "type": "integer",
            "description": "Index of the slot in the ring buffer."
          },
          "slotKey": {
            "type": "integer",
            "format": "int64",
            "description": "Epoch slot index."
          },
          "isCurrent": {
            "type": "boolean",
            "description": "Whether this is the current active slot."
          },
          "startTime": {
            "type": "string",
            "format": "date-time"
          },
          "endTime": {
            "type": "string",
            "format": "date-time"
          },
          "ageSeconds": {
            "type": "integer",
            "format": "int64"
          },
          "totalRequests": {
            "type": "integer",
            "format": "int64"
          },
          "authenticatedRequests": {
            "type": "integer",
            "format": "int64"
          },
          "activeCounters": {
            "type": "integer"
          },
          "blockedCounters": {
            "type": "integer"
          }
        }
      },
      "CounterEntryDto": {
        "type": "object",
        "required": [
          "key",
          "count",
          "retained",
          "effective",
          "limit",
          "distinctClients",
          "status"
        ],
        "properties": {
          "key": {
            "type": "string",
            "description": "IP address or subnet CIDR key."
          },
          "count": {
            "type": "integer",
            "description": "Requests registered in the current slot window."
          },
          "retained": {
            "type": "integer",
            "description": "Requests retained and carried forward from previous slots."
          },
          "effective": {
            "type": "integer",
            "description": "Total effective request count evaluated against the threshold (count + retained)."
          },
          "limit": {
            "type": "integer",
            "description": "Maximum allowed requests threshold for this client."
          },
          "distinctClients": {
            "type": "integer",
            "description": "Estimated count of distinct individual client IPs aggregated within this subnet key."
          },
          "distinctUserAgents": {
            "type": [
              "integer",
              "null"
            ],
            "description": "Estimated count of distinct user agents observed from this client."
          },
          "returningCount": {
            "type": [
              "integer",
              "null"
            ],
            "description": "Requests identified as returning visitors via tracking cookie."
          },
          "authenticatedCount": {
            "type": [
              "integer",
              "null"
            ],
            "description": "Requests identified as authenticated sessions."
          },
          "sampleMethod": {
            "type": [
              "string",
              "null"
            ],
            "description": "HTTP method of the most recent sampled request (e.g. GET, POST)."
          },
          "sampleUri": {
            "type": [
              "string",
              "null"
            ],
            "description": "Request URI of the most recent sampled request."
          },
          "sampleUserAgent": {
            "type": [
              "string",
              "null"
            ],
            "description": "User-Agent header of the most recent sampled request."
          },
          "sampleAuthenticated": {
            "type": [
              "boolean",
              "null"
            ],
            "description": "True if the sampled request had a valid authenticated session."
          },
          "status": {
            "type": "string",
            "enum": [
              "BLOCKED",
              "ACTIVE"
            ],
            "description": "Current counter state."
          }
        }
      },
      "ActiveCounterEntryDto": {
        "allOf": [
          {
            "$ref": "#/components/schemas/CounterEntryDto"
          },
          {
            "type": "object",
            "required": [
              "quotaPercent"
            ],
            "properties": {
              "quotaPercent": {
                "type": "integer",
                "minimum": 0,
                "maximum": 100,
                "description": "Percentage of quota consumed (effective / limit * 100)."
              }
            }
          }
        ]
      },
      "OpenApiSpecResponse": {
        "type": "object",
        "description": "Complete OpenAPI 3.1.0 document describing the Anti-DoS Valve API."
      }
    }
  }
}
""";
}
