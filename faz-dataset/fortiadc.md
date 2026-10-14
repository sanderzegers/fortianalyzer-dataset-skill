# FortiADC Logs (device type 20)

FortiADC log types: `traffic` (one row per load-balanced connection or request), `event` (system, admin, health check), `attack` (ADC WAF/IPS; no rows in the test data, so its columns are unverified). Columns verified on FAZ 7.6 with FortiADC logs (October 2026).

## Differences from FortiGate tables

| FortiGate name | FortiADC name | Notes |
|---|---|---|
| `devid` | **`device_id`** | `devid` → "Missing columns". `devname` works as usual |
| `level` | **`pri`** | Text: `information`, `notice`, `warning`, `alert`, `critical` |
| `logid` | **`log_id`** | String |
| `srcip` / `dstip` | **`src`** / **`dst`** | `Nullable(IPv6)`, use `ipstr()` |
| `srcport` / `dstport` | **`src_port`** / **`dst_port`** | UInt16 |
| `sentbyte` / `rcvdbyte` | **`ibytes`** / **`obytes`** | UInt64. One log per connection (no interim logs like FortiGate's), so `sum()` is correct |
| `policyname` | **`policy`** | Virtual server name |

- `proto` is numeric (UInt16, `6` = TCP), unlike FortiWeb's `tcp`.
- `duration` is in **milliseconds** (UInt32). The log reference gives no unit; in the data the 90th percentile is 60 021 (a 60 s timeout), and seconds would put the maximum at over three years.
- FortiADC writes `none` for empty text fields (`user`, `usrgrp`, `auth_status`, `http_agent`, `http_qry`, `http_referer`, `http_cookie`). Filter with `!= 'none'`.
- Columns are Nullable. Use `ifNull(col, '')` before string functions.
- `date` / `time` (String) are FortiADC's own timestamp fields. Use `itime` / `$filter` for time logic.

## `$log-traffic`

Common fields on every traffic subtype:

| Column | Type | Description |
|---|---|---|
| `type` / **`subtype`** | String | `traffic` / `slb_http` (seen), `slb_layer4` (log reference). The log reference also lists TCPS, RADIUS, SIP, RDP, DNS, RTSP, SMTP, RTMP, MySQL, MSSQL, Diameter, FTP, ISO8583, GLB and LLB traffic logs; their `subtype` strings are unverified, so group by `subtype` to find them |
| `pri` | String | `information` |
| `action` | String | `none` (seen) |
| `proto` / `service` | UInt16 / String | `6` / `http`, `https` |
| `src`, `src_port`, `dst`, `dst_port` | IPv6 / UInt16 | Client and virtual server address |
| `trans_src`, `trans_src_port`, `trans_dst`, `trans_dst_port` | IPv6 / UInt16 | Translated (server-side) addresses |
| **`real_server`** | String | Back-end real server that handled the request: the real-server name as configured on the FortiADC (often a hostname or name-plus-IP) |
| **`policy`** | String | Virtual server |
| `duration` | UInt32 | Milliseconds |
| `ibytes` / `obytes` | UInt64 | Bytes in / out of the connection |
| `srccountry` / `dstcountry` | String | Geo-IP country |
| `gateway`, `fqdn`, `resip` | | Link load balancing / global load balancing. Empty in `slb_http` |
| `msg_id` | UInt64 | Message ID |

Subtype-specific fields (filled only for their subtype):

| Subtype | Fields |
|---|---|
| `slb_http` | `http_method`, `http_host` (can include `:port`), `http_url` (path only, no query), `http_qry` (query string without `?`, `none` if absent), `http_agent`, `http_referer`, `http_cookie`, **`http_retcode`** (UInt32), `user`, `usrgrp`, `auth_status` |
| FTP | `ftp_username`, `ftp_mode`, `ftp_cmd`, `ftp_retcode`, `ftp_pathname`, `ftp_d_*`, `ftp_dtr_*` |
| SMTP | `smtp_cmd`, `smtp_from`, `smtp_to`, `smtp_cc`, `smtp_subject`, `smtp_attachname`, `smtp_starttls`, `smtp_bodylen`, `smtp_retcode` |
| SIP | `sip_method`, `sip_uri`, `sip_from`, `sip_to`, `sip_callid`, `sip_retcode` |
| RTSP / RTMP | `rtsp_method`, `rtsp_uri`, `rtsp_sessionid`, `rtsp_retcode`, `rtsp_info` / `rtmp_cmd`, `rtmp_tcurl`, `rtmp_streamname`, `rtmp_retcode` |
| MySQL / MSSQL | `mysql_action`, `mysql_sql`, `mysql_retcode`, `mysql_transid`, `mysql_groupid` / `mssql_action`, `mssql_sql`, `mssql_response` |
| Diameter | `dm_cmdcode`, `dm_appid`, `dm_e2eid`, `dm_orihost`, `dm_orirealm`, `dm_desthost`, `dm_destrealm`, `dm_sessionid`, `dm_retcode` |
| DNS | `dns_req`, `dns_resp` |
| RADIUS | `reqmsglen`, `reqmti`, `respmsglen`, `respmti` |

Only `slb_http` was present in the test data; the other subtypes' fields are schema-only.

## `$log-event`

| Column | Description |
|---|---|
| `type` / `subtype` | `event` / `slb`, `health_check`, `admin`, `system`, `config`, `dns` |
| `pri` | `information`, `notice`, `warning`, `alert`, `critical` |
| `action` | `login`, `logout`, `health_check`, `ssl`, `update`, `backup`, `edit`, `del`, `none`, `load_WAF_Signature_DB`, ... |
| `status` | `success`, `failure`, `''` |
| `module` / `submod` | `slb` or `''` / `ha`, `update`, `security`, `none`, `''` |
| `logdesc`, `msg` | Short / full description (filled on every row) |
| `user`, `ui`, `reason`, `policy`, `cfgpath`, `cfgobj`, `cfgattr`, `group`, `member`, `attrtype`, `attrname`, `usergrp` | Admin and config-change details |

Health checks: `subtype='health_check'` with `status` `success`/`failure` marks a real server going up/down.

## Key Patterns

```sql
-- Requests, bytes and median duration per virtual server
SELECT policy AS virtual_server, count(*) AS requests,
       sum(ifNull(ibytes, 0) + ifNull(obytes, 0)) AS bytes,
       quantile(0.5)(duration) AS median_ms
FROM $log-traffic
WHERE $filter AND subtype = 'slb_http'
GROUP BY virtual_server
ORDER BY requests DESC

-- Load distribution across real servers
SELECT policy AS virtual_server, real_server, count(*) AS requests
FROM $log-traffic
WHERE $filter
GROUP BY virtual_server, real_server
ORDER BY virtual_server, requests DESC

-- HTTP error rate per virtual server
SELECT policy AS virtual_server, count(*) AS requests,
       countIf(http_retcode >= 500) AS server_errors,
       countIf(http_retcode >= 400 AND http_retcode < 500) AS client_errors
FROM $log-traffic
WHERE $filter AND subtype = 'slb_http'
GROUP BY virtual_server
ORDER BY server_errors DESC

-- Health check failures
SELECT $flex_timestamp AS timestamp, count(*) AS failures
FROM $log-event
WHERE $filter AND subtype = 'health_check' AND status = 'failure'
GROUP BY timestamp
ORDER BY timestamp
```

FortiADC traffic logs are high-volume (millions of rows per day). Wrap heavy reports in hcache (`###( … )###`) and test on a short period first.
