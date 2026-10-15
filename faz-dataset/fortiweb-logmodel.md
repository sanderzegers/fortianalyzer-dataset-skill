# FortiWeb Log Model

Where FortiWeb events are logged, what one row stands for, and how records link. Column details are in [fortiweb.md](fortiweb.md). Mapped on two FAZ 7.6 instances with five FortiWeb VMs running 7.6+ (October 2026). Counts below come from those two; check them on yours before relying on them.

## The reference doesn't match the firmware

Unlike FortiOS, the FortiWeb Log Message Reference (7.6.0 and 8.0.7) **doesn't describe the `log_id`s that FortiWeb 7.6+ sends**. Only 19 of the 38 IDs seen in real logs are documented anywhere. Configuration changes all arrive as `9000001`, while the reference lists a separate ID per object (`00002801`, `00009211`, ...) that never occurs. Several frequent events (`11005401`, `11001504`, `30000001`) aren't documented at all. Details and evidence: [issue #10](https://github.com/sanderzegers/fortianalyzer-dataset-skill/issues/10).

So for FortiWeb:
- The tables below come from real logs. The "Documented" column says whether the reference lists the ID.
- Use the reference only for the attack IDs, where it matches.
- Find other events with the discovery query below, not with the reference.
- `log_id` is a number in FAZ (`UInt64`): leading zeros are gone (`09000001` on the device is `9000001` in FAZ).

```sql
-- Discovery: which events does this FortiWeb send? (masked msg per log_id)
SELECT log_id, subtype, action, status, count(*) AS n,
       any(substring(replaceRegexpAll(ifNull(msg, ''), '[0-9]+', 'N'), 1, 100)) AS msg_sample
FROM $log-event
WHERE $filter
GROUP BY log_id, subtype, action, status
ORDER BY n DESC
```

## What one row stands for

| Table | One row per | Notes |
|---|---|---|
| `$log-traffic` | HTTP transaction | Only when traffic logging is enabled globally and in the server policy. `log_id` `30000001` = HTTP, `30001000` = HTTPS (`subtype` `http`/`https`). Blocked requests are logged too |
| `$log-attack` | detection | One `log_id` per detection module (`main_type`), see below. A request can trigger several modules |
| `$log-event` | event | `log_id` alone isn't always unique: combine it with `action` and `status` (`10000016` is admin login success **and** failure) |

`msg_id` is a running number per log record, not per request: it doesn't link an attack row to its traffic row (0 matches on both FAZes).

## Event logs (`$log-event`)

| log_id | subtype | `action` / `status` | Meaning | Documented |
|---|---|---|---|---|
| `9000001` | admin | `add`, `edit`, `delete` / `success` | **Any configuration change**. Object and admin are in `msg` (`User <admin> added <object> from GUI(<ip>)`) | no |
| `10000016` | system | `login` / `success`, `failure` | Admin login, successful or failed (`msg`: `... from GUI->HTTPS(<ip>)`) | yes |
| `10000017` | system | `login` / `failure` | Lockout after too many failed logins. The IP is only in `msg` (`Lock out IP:<ip> due to maximum of bad login attempts reached from ssh`) | yes |
| `10000018` | system | `logout` / `success` | Admin logout or GUI session timeout | yes |
| `10000012` | system | `logout` / `success` | Admin console session timed out (`jsconsole`) | yes |
| `10000034` | system | `browse` / `success` | Admin viewed logs | no |
| `10000031` | system | `edit` / `failure` | CLI command failed | yes |
| `11001504` | system | `login` / `success` | **End-user** login on a site-publishing policy (`User <user> [<policy>] login successfully on <host> from <ip>`). Not an admin login | no |
| `10000009` | system | `start` / `success` | FortiWeb started | yes |
| `10000023` | system | `backup`, `start` / `success` | Configuration backup (and backup daemon start) | yes |
| `11005401` | system | `update` / `success`, `failure` | Signature / FortiGuard update result. Failures report certificate errors (`errorno(N)`). The most frequent event on one FAZ | no |
| `11005402` | system | `update` / `success` | FDS update successful | no |
| `11007101` | system | `update` / `success` | Signature database synchronized | no |
| `11014402` | system | `refresh` / `failure` | Bot signature-agent public key refresh failed | no |
| `19999488` | system | `certificate-issue` / `failure` | Let's Encrypt certificate issuance failed | no |
| `19999495` / `19999496` | system | `check-resource` / `failure`, `success` | Server pool member went down / came up (`... in server pool <pool> status change from up to down`) | yes |
| `11005108` | system | `monitor` / `success` | Periodic performance statistics. Values in `cpu`, `mem`, `total_conn`, `conn_rate` | no |
| `11005104` / `11005107` | system | `check-resource` | CPU usage too high / log disk usage too high | no |
| `11008101` | system | `dns-request` | DNS resolution failed for a server name | no |
| `11000518` | system | `connect` / `success` | FortiAnalyzer connection status | no |
| `10000082` | system | `update` / `success` | NTP status | no |
| `10000046` | system | `snmp-query` / `failure` | SNMP query with an unknown community | no |
| `11005106` / `11009116` | system | `purge` / `import` | Cache flush / machine-learning data import | no |

Filter configuration changes on `subtype = 'admin'` (and `action`), not on documented admin IDs.

## Attack logs (`$log-attack`)

`log_id` maps one-to-one to `main_type`; `subtype` and `action` vary within it.

| log_id | main_type | Source |
|---|---|---|
| `20000001` | Allow Method | reference, seen |
| `20000002` | Protected Hostnames | reference, seen |
| `20000003`–`20000006` | Page Access, Start Pages, Parameter Validation, Black IP List | reference |
| `20000007` | URL Access | reference, seen |
| `20000008` | Signature Detection | reference, seen |
| `20000009`, `20000011`, `20000012` | Custom Signature Detection, Hidden Fields, Site Publish (Account Lockout) | reference |
| `20000014`–`20000018` | DoS Protection, SYN Flood Protection, HTTPS Connection Failure, File Upload Restriction, GEO IP | reference |
| `20000021` | Custom Access | reference, seen |
| `20000022` | IP Reputation | reference, seen |
| `20000023`–`20000025` | Padding Oracle, CSRF Protection, Quarantined IPs | reference |
| `20000026` | HTTP Protocol Constraints | reference, seen |
| `20000027`–`20000043` | Credential Stuffing Defense, User Tracking, XML Validation, Cookie Security, FTP, Timeout Session, Machine Learning, OpenAPI Validation, WebSocket Security, MiTB AJAX Security, Bot Detection, CORS Check, JSON Validation | reference |
| `20000045`–`20000047` | BOT Deception, Biometrics Based Detection, Threshold Based Detection | reference (examples only) |
| `20000050` | SQL/XSS Syntax Based Detection | **seen only**, not in the reference |
| `20000051` | Known Bots Detection | reference (outside the ID list), seen |
| `20000052` | Client Management | reference (example), seen |

`action` values seen: `Alert` (detected, not blocked, or the policy is in monitor mode), `Alert_Deny`, `Period_Block`. For "blocked" use `action != 'Alert'`.

## Linking records

| From | To | Key | Match |
|---|---|---|---|
| attack row | traffic row of the same request | `device_id` + `src` + `src_port` + `http_url`, `dtime` within 2 seconds | All attack rows on one FAZ, 98.7 % on the other. Blocked requests carried HTTP `500` in the traffic log on both FAZes (`404` twice): the block response, which is configurable |
| attack row | traffic of the same connection | `device_id` + `src` + `src_port` | Keep-alive connections carry several requests |
| attack row | FortiGate session in front of FortiWeb | client `src` + `src_port` ↔ FortiGate `srcip` + `srcport`, within the FortiGate session | Second query with the FortiGate device type. 99.5 % / 92.3 % matched; needs the client IP passed through (no source NAT). See investigating.md |

## Patterns

```sql
-- Admin logins and failures per account
SELECT `user` AS admin_user,
       countIf(status = 'success') AS logins,
       countIf(status != 'success') AS failed
FROM $log-event
WHERE $filter AND log_id = 10000016
GROUP BY admin_user
ORDER BY failed DESC

-- Lockouts per source IP (the IP is only in msg)
SELECT extract(msg, 'Lock out IP:(\\S+) ') AS source_ip, count(*) AS lockouts
FROM $log-event
WHERE $filter AND log_id = 10000017
GROUP BY source_ip
ORDER BY lockouts DESC

-- Configuration changes per device, admin and action
SELECT devname, `user` AS admin_user, action, count(*) AS changes
FROM $log-event
WHERE $filter AND subtype = 'admin'
GROUP BY devname, admin_user, action
ORDER BY changes DESC

-- Blocked attacks per site and detection module
SELECT splitByChar(':', ifNull(http_host, ''))[1] AS site, main_type,
       countIf(action != 'Alert') AS blocked, count(*) AS detected
FROM $log-attack
WHERE $filter
GROUP BY site, main_type
ORDER BY blocked DESC

-- What blocked clients got back: attack rows joined to their traffic rows
SELECT a.main_type, t.http_retcode, count(*) AS requests
FROM (SELECT device_id, src, src_port, http_url, dtime, main_type
      FROM $log-attack WHERE $filter AND action != 'Alert') a
JOIN (SELECT device_id, src, src_port, http_url, dtime AS tdtime, http_retcode
      FROM $log-traffic WHERE $filter) t
  ON a.device_id = t.device_id AND a.src = t.src AND a.src_port = t.src_port
 AND a.http_url = t.http_url
WHERE abs(toInt64(a.dtime) - toInt64(t.tdtime)) <= 2
GROUP BY a.main_type, t.http_retcode
ORDER BY requests DESC

-- Server pool members going down and up
SELECT devname, extract(msg, 'in server pool (.+?) status change') AS pool,
       countIf(log_id = 19999495) AS went_down, countIf(log_id = 19999496) AS came_up
FROM $log-event
WHERE $filter AND log_id IN (19999495, 19999496)
GROUP BY devname, pool
ORDER BY went_down DESC

-- Signature / FortiGuard update failures over time
SELECT $flex_timestamp AS timestamp, devname, count(*) AS failures
FROM $log-event
WHERE $filter AND log_id = 11005401 AND status = 'failure'
GROUP BY timestamp, devname
ORDER BY timestamp
```
