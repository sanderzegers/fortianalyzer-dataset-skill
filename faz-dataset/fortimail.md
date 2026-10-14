# FortiMail Logs (device type 4)

FortiMail log types: `history` (one row per message), `emailfilter` (antispam detail), `virus` (AV and FortiSandbox), `event` (system). Columns verified on FAZ 7.6 with FortiMail logs (October 2026).

## Differences from FortiGate tables

Queries copied from FortiGate patterns fail here. FortiMail tables use FortiMail's own field names:

| FortiGate name | FortiMail name | Notes |
|---|---|---|
| `devid` | **`device_id`** | `devid` → "Missing columns". `devname` works as usual |
| `level` | **`pri`** | Text: `information`, `notice`, `warning`, `error`, ... |
| `logid` | **`log_id`** | String |
| `srcip` / `dstip` | **`client_ip`** / **`dst_ip`** | `Nullable(IPv6)`, use `ipstr()` |
| `sessionid` | **`session_id`** | String. Links one message across `history`, `emailfilter` and `virus` |
| `sender` / `recipient` | **`` `from` ``** / **`` `to` ``** | Reserved words: always backtick them |

- Almost every column is `Nullable(String)`. Wrap it with `ifNull(col, '')` before string or array functions (`splitByChar(';', disposition)` on a Nullable column fails with "Nested type Array(String) cannot be inside Nullable type").
- IP columns are `IPv6`: `ifNull(client_ip, '')` fails with "There is no supertype". Use `ipstr(client_ip)` or `client_ip IS NOT NULL`.

## `$log-history` — one row per message

| Column | Type | Description |
|---|---|---|
| `type` / `subtype` | String | Always `statistics` / `''` |
| `pri` | String | `information` |
| **`` `from` ``** | String | Envelope sender (MAIL FROM), bare `user@example.com` without `<>`. **Mixed case** on ~23 % of rows: group by ``lower(`from`)``. On `SMTP Auth Failure` rows it holds the attempted login name instead of an address |
| `hfrom` | String | Header From address (`user@example.com`). Empty when the session was rejected before DATA |
| **`` `to` ``** | String | Recipient, one bare address per row. Mixed case on ~7 % of rows: use `lower()`. Empty when the session was rejected before RCPT |
| `domain` | String | Protected domain the policy matched (the domain part of `polid`), always lowercase. Empty on early-rejected sessions |
| `subject` | String | Subject. Empty on rejected sessions |
| **`direction`** | String | `in`, `out`, `unknown` (rejected before the direction was known) |
| **`classifier`** | String | Which check decided the message (see values below) |
| **`disposition`** | String | Actions taken, **`;`-joined** (`Insert Disclaimer;Defer Disposition`). Never compare with `=` |
| `resolved` | String | Client reverse-DNS check: `OK`, `FAIL`, `FORGED`, `TEMP`, `''` |
| `src_type` | String | `int`, `ext`, `unknown` (client from an internal or external network) |
| `mailer` | String | `mta` or `''` |
| `polid` | String | `<ACL id>:<IP policy id>:<recipient policy id>:<protected domain or SYSTEM>`, e.g. `0:1:2:example.com` |
| `virus` | String | Virus name, filled only when AV hit |
| `message_length` | UInt32 | Message size in bytes |
| `message_id` | String | Message-ID header |
| `client_name` / `client_ip` / `client_cc` | String / IPv6 / String | Connecting MTA: reverse-DNS hostname (empty when unresolved; ~13 % end with a space, so `trim()` it) / IP / two-letter country code, `ZZ` = unknown or private |
| `dst_ip` | IPv6 | Next-hop IP |
| `scan_time` / `xfer_time` / `recv_time` | Float64 | Seconds spent scanning / transferring / receiving |
| `notif_delay` | String | Notification delay |
| `session_id` | String | Session ID |
| `msisdn`, `endpoint`, `srcfolder`, `read_status` | String | Empty unless the matching feature is used |

### `classifier` values seen

`SMTP Auth Failure`, `Access Control-Safe-Relay`, `Access Control-Reject`, `Access Control-Relay Denied`, `Data Loss Prevention`, `Disclaimer`, `Session Domain`, `Session Limit`, `Recipient Verification`, `Sender Reputation`, `FortiGuard AntiSpam`, `FortiGuard AntiSpam-IP`, `FortiGuard WebFilter`, `Newsletter`, `Newsletter Suspicious`, `System Safe`, `System Block`, `User Safe`, `Domain Safe`, `Domain Block`, `Not Spam`, `BEC-Cousin Domain`, `BEC-Sender Alignment`, `BEC-Impersonation Analysis`, `DMARC Failure`, `SPF Failure`, `DKIM Failure`, `SURBL`, `DNSBL`, `Header Analysis`, `Heuristic`, `Behavior Analysis`, `Dictionary Filter`, `Banned Word`, `Image Spam`, `Attachment Filter`, `Content Monitor and Filter`, `Virus Signature`, `Virus Outbreak`, `Malware Outbreak`, `FortiSandbox File`, `FortiSandbox URL`, `FortiSandbox NoResult`.

These are examples, not a complete set. Mixed case with spaces: match exactly or use `ILIKE`.

### `disposition` actions seen

`Accept`, `Reject`, `Delay`, `System Quarantine`, `Defer Disposition`, `Insert Disclaimer`, `Disclaimer Body`, `Add Header`, `Modify Subject`, `Remove URL`, `Notification`, `Quarantine Notification`, `Replace`.

## `$log-emailfilter` — one row per check

**Several rows per message:** FortiMail writes one row for each check it ran (DMARC, DKIM, DLP, FortiGuard, ...), about 5 per session in the sample. `count(*)` here counts check results, not messages; use `count(DISTINCT session_id)` or `$log-history` for message counts.

| Column | Description |
|---|---|
| `type` / `subtype` | `spam` / `default` (most checks), `url` (URL checks), `admin` |
| `` `from` `` / `` `to` `` / `subject` / `client_name` / `client_ip` / `dst_ip` | As in history |
| **`msg`** | Which check and its result. The leading words identify the check (see below) |
| `url` | URL found in the message (`subtype='url'` only). Long URLs are cut off with `[...]` |
| `wf_cat_id` | FortiGuard web category ID as a numeric string, only on `FortiGuard-WebFilter` URL rows |

`msg` starts seen (filter with `LIKE 'DKIM%'` etc.): `DMARC`, `DKIM Check Succeeded`, `DK`, `SPF`, `File name`, `Identified by DLP check`, `FortiSandbox URL submission exemption`, `Newsletter`, `FortiGuard-AntiSpam identified spam URL`, `FortiGuard-AntiSpam identified spam hash`, `FortiGuard-AntiSpam identified spam IP`, `FortiGuard spam outbreak protection`, `FortiGuard-WebFilter identified URL`, `System Safe List`, `Sender reputation`, `Detected by CousinDomain`, `Recipient Rejected`, `Verification Server returned`, `Sender domain check failed for`, `Remove URL`. The rest of the text is message-specific.
| `tdtype`, `tdthreattype`, `tdthreatname`, `tdwfcate`, `tdurl`, `tdinfoid` (Int64), `tdscantime` (DateTime) | Threat-detection fields. Empty in the sample |

## `$log-virus`

| Column | Description |
|---|---|
| `type` / `subtype` | `virus` / `fortisandbox`, `infected`, `malware-outbreak`, `file-signature` |
| `virus_name` | AV name on `infected` rows (a quarter of `infected` rows have none) |
| `virus_id` / `signature_id` | Numeric string / numeric or hex hash. Filled on `infected` rows |
| `url` / `checksum` | Submitted URL / SHA-256 of a submitted file (`fortisandbox` rows) |
| `` `from` `` / `` `to` `` / `src` / `client_name` / `client_ip` | Message context |
| `score` | Never filled in the sample |

Most rows are `subtype='fortisandbox'`, and FortiMail logs **each submission stage as its own row** (~14 rows per session in the sample). `msg` tells the stage: `Queued for FortiSandbox scan`, `URL has been sent to FortiSandbox`, `URL has been scanned by FortiSandbox`, `File ...`, `Email ...`. Count `DISTINCT session_id`, or filter one stage, to count submissions. For detections, filter `subtype IN ('infected', 'malware-outbreak', 'file-signature')` or join to history and filter on `classifier`.

## `$log-event`

| Column | Description |
|---|---|
| `type` | `event` (mail service) or `kevent` (system) |
| `subtype` | `event`: `smtp`, `imap`, `webmail`. `kevent`: `admin`, `config`, `update`, `ha`, `system`, `dns` |
| `pri` | `information`, `notice`, `warning`, `error` |
| `action` | `login`, `logout` (admin), `none`, `NONE` (smtp, upper case), `unknown` (webmail), `''` (update, config, dns) |
| `status` | `success`, `failure`, `none`, `N/A` (smtp), `''` |
| `user` / `ui` | Admin or mail user / access channel: `GUI(<ip>)`, `https(<ip>)`, `ssh(<ip>)` or a bare IP on admin rows; `mail`, `spamreport`, `ha`, `system` elsewhere. Empty on `update` and `dns` |
| `reason` | Filled only on `kevent`/`admin` rows (e.g. login failures) |
| `module` / `submodule` | Mostly empty, `unknown` on config rows |
| `msg` | Readable text |

`event`/`smtp` rows (~99 % of event logs) are per-connection SMTP status lines with `action='NONE'` and `status='N/A'`. For admin logins use `type='kevent' AND subtype='admin' AND action='login'`, with `status` `success`/`failure`.

## Key Patterns

```sql
-- Mail volume over time by direction
SELECT $flex_timestamp AS timestamp, direction, count(*) AS messages,
       sum(ifNull(message_length, 0)) AS bytes
FROM $log-history
WHERE $filter
GROUP BY timestamp, direction
ORDER BY timestamp

-- What decided the messages (one row per classifier)
SELECT classifier, count(*) AS messages
FROM $log-history
WHERE $filter
GROUP BY classifier
ORDER BY messages DESC

-- Count each disposition action separately (disposition is ';'-joined)
SELECT arrayJoin(splitByChar(';', ifNull(disposition, ''))) AS action, count(*) AS messages
FROM $log-history
WHERE $filter
GROUP BY action
ORDER BY messages DESC

-- Quarantined or rejected inbound mail by protected domain
SELECT domain, countIf(disposition LIKE '%Quarantine%') AS quarantined,
       countIf(disposition LIKE '%Reject%') AS rejected, count(*) AS total
FROM $log-history
WHERE $filter AND direction = 'in'
GROUP BY domain
ORDER BY total DESC

-- Top recipients of inbound mail
SELECT `to` AS recipient, count(*) AS messages
FROM $log-history
WHERE $filter AND direction = 'in' AND ifNull(`to`, '') != ''
GROUP BY recipient
ORDER BY messages DESC

-- Virus detections with message context (virus rows link to history via session_id)
SELECT v.virus_name, h.classifier, h.direction, count(*) AS cnt
FROM $log-virus v
JOIN (SELECT session_id, classifier, direction FROM $log-history WHERE $filter) h
  ON v.session_id = h.session_id
WHERE $filter AND v.subtype = 'infected'
GROUP BY v.virus_name, h.classifier, h.direction
ORDER BY cnt DESC
```

- `` `to` `` held one address per row in the sample. A message to several recipients produces several history rows, so `count(*)` counts recipient deliveries, not unique messages. Use `count(DISTINCT message_id)` for unique messages (empty on rejected sessions).
- Rejected sessions (`SMTP Auth Failure`, `Recipient Verification`, `Session Domain`, ...) have `direction='unknown'` and empty `subject`/`hfrom`/`to`. Exclude them for "delivered mail" reports: `WHERE classifier NOT IN (...)` or `disposition NOT LIKE '%Reject%'`.
