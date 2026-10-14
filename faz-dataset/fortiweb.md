# FortiWeb Logs (device type 5)

FortiWeb log types: `attack` (WAF detections), `traffic` (one row per HTTP transaction), `event` (system and admin). Columns verified on two FAZ 7.6 instances with FortiWeb logs (October 2026); names and types were identical on both. FortiWeb's `$log-attack` and `$log-traffic` are separate tables from FortiGate's: none of the FortiGate column files apply.

## Differences from FortiGate tables

| FortiGate name | FortiWeb name | Notes |
|---|---|---|
| `devid` | **`device_id`** | `devid` → "Missing columns". `dev_id` (String) is FortiWeb's own serial field. `devname` works as usual |
| `level` | **`pri`** | Text: `alert` (all attack rows), `notice` (traffic), `critical` ... `information` (event) |
| `logid` | **`log_id`** | UInt64 |
| `srcip` / `dstip` | **`src`** / **`dst`** | `Nullable(IPv6)`, use `ipstr()` |
| `srcport` / `dstport` | **`src_port`** / **`dst_port`** | UInt16 |
| `policyname` | **`policy`** | Server policy name |
| `hostname` / `url` | **`http_host`** / **`http_url`** | |

- Columns are Nullable. Use `ifNull(col, '')` before string functions.
- Many text fields use placeholders instead of empty values: `N/A` (`subtype`, `signature_id`, `owasp_top10`, `owasp_api_top10`), `none` (`bot_info`, `false_positive_mitigation`), `unknown` (`backend_service`), `Unknown` (`user_name`, ~90 % of attack rows). Use `nullifna()` or exclude them explicitly.
- `http_host` is lowercase and can include a port (`www.example.com:8443`), so the same site can appear twice; strip it with `splitByChar(':', ifNull(http_host, ''))[1]`. `http_url` includes the query string (`/path?a=1`); cut it with `path(concat('http://x', http_url))` or `splitByChar('?', ifNull(http_url, ''))[1]`.

## `$log-attack`

| Column | Type | Description |
|---|---|---|
| `type` / `pri` | String | Always `attack` / `alert` |
| **`main_type`** | String | Detection module (see values below). Use this for "attack type" reports |
| **`subtype`** | String | Specific violation inside the module (`Known Exploits`, `WebSocket Protocol`, ...). `N/A` for modules without subtypes (`Client Management`, `URL Access`, ...) |
| **`action`** | String | `Alert`, `Alert_Deny`, `Period_Block` (seen). Capitalised |
| `severity_level` | String | `Informative`, `Low`, `Medium`, `High` |
| `threat_level` | String | `Off`, `Informational`, `Low`, `Moderate`, `Substantial`, `Severe`, `Critical` |
| `threat_weight` / `history_threat_weight` | UInt32 | Threat score of this request / of the client so far |
| `client_level` | String | Client reputation: `Trusted`, `Unidentified`, `Suspicious`, `Malicious` |
| `src` / `src_port` / `dst` / `dst_port` | IPv6 / UInt16 | Client and server address |
| `srccountry` / `dstcountry` | String | Geo-IP country |
| `policy` / `server_pool_name` / `content_switch_name` | String | Server policy / pool / content routing |
| `http_method`, `http_url`, `http_host`, `http_agent`, `http_refer`, `http_version`, `http_session_id` | String | Request details |
| `signature_id` / `signature_subclass` / `signature_cve_id` | String | Signature hit: numeric ID string, `N/A` otherwise. Filled only on signature detections (~6 % of rows) |
| `owasp_top10` | String | `A05:2021-Security Misconfiguration` style, or `N/A` |
| `owasp_api_top10` | String | `API8:2023 Security Misconfiguration` style; can hold several, comma-separated |
| `matched_field` / `matched_pattern` | String | Which part of the request matched |
| `monitor_status` | String | `Enabled` / `Disabled` (monitor mode of the policy) |
| `backend_service` | String | `https/tls1.2`, `http`, `unknown` |
| `user_name` / `login_user` / `user_id` | String | Authenticated user (plain name or `user@example.com`); `Unknown` when not authenticated |
| `bot_info`, `ml_*`, `app_id`, `app_name`, `app_domain` | String | Bot and machine-learning detail, API app. Empty or placeholder unless the feature is enabled |
| `msg` | String | Readable description |

### `main_type` values seen

`Signature Detection`, `HTTP Protocol Constraints`, `SQL/XSS Syntax Based Detection`, `Custom Access`, `URL Access`, `Allow Method`, `Protected Hostnames`, `Client Management`, `Known Bots Detection`, `IP Reputation`.

`subtype` examples: `Known Exploits`, `Generic Attacks`, `Cross Site Scripting`, `Information Disclosure`, `WebSocket Protocol`, `HTTP Duplicated Parameter Name`, `Missing POST Content Type`, `URL Parameter Number Overflow`, `Illegal HTTP Method`, `Malformed URL`, `Scanner`, `Crawler`, `Known Search Engines`, `Spam`, `Anonymous Proxy`, `Arithmetic Operation Based Boolean Injection`, `HTML Tag Based XSS Injection`.

## `$log-traffic`

One row per HTTP transaction. FortiWeb sends traffic logs only when traffic logging is enabled globally and in the server policy.

| Column | Type | Description |
|---|---|---|
| `type` / `subtype` / `pri` | String | `traffic` / `http` or `https` / `notice` |
| `status` | String | `success` (seen) |
| **`http_retcode`** | UInt16 | HTTP status code |
| `http_method` | String | **Lowercase**: `get`, `post`, `head`, `options`, `put`, `delete`, `trace`, `connect`, `webdav`, `others` |
| `http_version` | String | `1.x` (seen) |
| `http_request_bytes` / `http_response_bytes` | UInt64 | Request / response size in bytes |
| `http_request_time` / `http_response_time` | UInt64 | Processing time in **milliseconds** (FortiWeb log reference). Often `0` |
| `src` / `dst` / `original_src` | IPv6 | Client / server / original client. `original_src` equalled `src` on >99 % of rows in the sample |
| `src_port` / `dst_port` | UInt16 | |
| `proto` / `service` | String | `tcp` / `http`, `https/tls1.2`, `https/tls1.3` |
| `policy`, `server_pool_name`, `content_switch_name` | String | Server policy, pool, content routing |
| `http_url`, `http_host`, `http_agent`, `http_refer`, `user_name`, `cipher_suite`, `msg_id` (UInt64) | | Request details |

## `$log-event`

| Column | Description |
|---|---|
| `type` / `subtype` | `event` / `system`, `admin` |
| `pri` | `critical`, `alert`, `error`, `notice`, `information` |
| `action` | `login`, `logout`, `add`, `edit`, `delete`, `update`, `refresh`, `monitor`, `backup`, `check-resource`, `certificate-issue`, `dns-request`, ... |
| `status` | `success`, `failure` |
| `user`, `ui`, `msg`, `trigger_policy` | Admin / interface / text / trigger |
| `cpu`, `mem`, `total_conn`, `conn_rate`, `total_http_bytes` | Resource values on monitor events |

## Key Patterns

```sql
-- Attacks by detection module and action
SELECT main_type, action, count(*) AS cnt
FROM $log-attack
WHERE $filter
GROUP BY main_type, action
ORDER BY cnt DESC

-- Top attacking clients (blocked only)
SELECT ipstr(src) AS client, srccountry, count(*) AS blocked
FROM $log-attack
WHERE $filter AND action IN ('Alert_Deny', 'Period_Block')
GROUP BY client, srccountry
ORDER BY blocked DESC

-- Attacks per protected site
SELECT http_host, policy, count(*) AS cnt,
       countIf(action != 'Alert') AS blocked
FROM $log-attack
WHERE $filter
GROUP BY http_host, policy
ORDER BY cnt DESC

-- OWASP Top 10 categories
SELECT owasp_top10, count(*) AS cnt
FROM $log-attack
WHERE $filter AND owasp_top10 != 'N/A'
GROUP BY owasp_top10
ORDER BY cnt DESC

-- HTTP status classes and response time per site
SELECT http_host, intDiv(ifNull(http_retcode, 0), 100) AS status_class, count(*) AS requests,
       avg(http_response_time) AS avg_response_ms,
       sum(ifNull(http_request_bytes, 0) + ifNull(http_response_bytes, 0)) AS bytes
FROM $log-traffic
WHERE $filter
GROUP BY http_host, status_class
ORDER BY requests DESC
```

`action='Alert'` means detected but not blocked (or the policy is in monitor mode, see `monitor_status`). For "blocked attacks" use `action != 'Alert'`; values outside the ones seen exist (e.g. redirect or send-403 actions), so ask the user if they need a specific one.
