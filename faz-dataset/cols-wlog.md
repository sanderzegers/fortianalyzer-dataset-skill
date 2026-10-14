# `$log-webfilter` — Web Filter

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`hostname`** | LowCardinality(String) | Request hostname (e.g. `www.google.com`) |
| **`url`** | Nullable(String) | Full URL path |
| **`cat`** | Nullable(UInt8) | Numeric web category ID |
| **`catdesc`** | LowCardinality(String) | Category description (e.g. `"Search Engines"`) |
| **`action`** | LowCardinality(String) | `passthrough`, `blocked` (tested), plus `warning`, `authenticate`, `override` per schema. Use `action = 'blocked'` for blocks |
| **`filtertype`** | LowCardinality(String) | What matched. Empty on every row in the FortiOS 7.2–7.6 sample, so prefer `eventtype` |
| `ruletype` | LowCardinality(String) | Rule type |
| `reqtype` | LowCardinality(String) | `direct`, `referral` |
| **`keyword`** | Nullable(String) | Matched keyword (banned-word events) |
| `banword` | LowCardinality(String) | Banned word matched |
| `urlfilterlist` | Nullable(String) | URL filter list name |
| `urlfilteridx` | Nullable(UInt32) | URL filter entry index |
| `ovrdid` / `ovrdtbl` | Nullable | Override ID / table |
| `quotaused` / `quotamax` | Nullable(UInt64) | Quota bytes used/max |
| `quotatype` / `quotaexceeded` | LowCardinality | Quota type / exceeded flag |
| `contenttype` | Nullable(String) | HTTP content type |
| `referralurl` | Nullable(String) | Referral URL |
| `antiphishdc` / `antiphishrule` | Nullable(String) | Anti-phishing fields |
| `urlrisk` | Nullable(UInt8) | URL risk score |
| `risklevel` | LowCardinality(String) | URL risk level |
| `videoid` / `videocategoryid` / `videotitle` | — | YouTube/video fields |
| `sentbyte` / `rcvdbyte` | Nullable | Session bytes |
| `eventtype` | LowCardinality(String) | `ftgd_allow`, `ftgd_blk`, `ftgd_err`, `urlfilter`, `urlmonitor` (seen on FortiOS 7.2–7.6; underscore, not hyphen) |
| `from` / `to` | LowCardinality(String) | Email from/to (webmail) |
| `direction` | — | `incoming` / `outgoing` |
| `srccountry` / `dstcountry` | — | Country (`Reserved` = private IP) |
| `httpmethod` | — | HTTP method |
| `profile` | — | Web filter profile name |
| `crscore` / `crlevel` / `craction` | — | Client reputation score / level / action |
| `filename` / `filetype` | — | Downloaded file name / type (file-type filtering) |
| `tdthreatname` / `tdthreattype` | — | Inline threat detection name / type |
| `urlsource` / `initiator` / `forwardedfor` | — | URL rating source / request initiator / X-Forwarded-For |

> **No `utmaction` or `utmevent` in webfilter logs.** Both exist only in `$log-traffic`, and querying them here fails with "Missing columns". Use `action`.

## Notable `catdesc` Values

These category descriptions appear frequently in queries and reports:

| `catdesc` Value | Notes |
|---|---|
| `Malicious Websites` | Drive-by malware, exploits |
| `Phishing` | Credential phishing sites |
| `Proxy Avoidance` | Anonymizers, VPN bypass services |
| `Spam URLs` | URLs found in spam email |
| `Dynamic DNS` | DDNS hostnames — often abused by C2 |
| `Newly Observed Domain` | Domain seen for the first time recently |
| `Newly Registered Domain` | Freshly registered domain |
| `Streaming Media and Download` | Video/audio streaming, file downloads |
| `Unknown` / `Unrated` | No category data available |

> Use `catdesc IN ('Malicious Websites','Phishing','Proxy Avoidance','Spam URLs')` for threat-related category filtering.

## Key Patterns

```sql
-- Blocked categories
SELECT catdesc, count(*) AS hits
FROM $log-webfilter
WHERE $filter AND action = 'blocked' AND catdesc IS NOT NULL
GROUP BY catdesc
ORDER BY hits DESC

-- Top sites with category
SELECT website, catdesc, sum(sessions) AS hits
FROM ###(
    SELECT hostname AS website, catdesc, count(*) AS sessions
    FROM $log-webfilter
    WHERE $filter AND hostname IS NOT NULL
    GROUP BY hostname, catdesc
    /*SkipSTART*/ORDER BY sessions DESC/*SkipEND*/
)### t
GROUP BY website, catdesc
ORDER BY hits DESC

```

## Real Values Discovered from FAZ Instance

### `action` (Webfilter Action)

Tested on a live FAZ:

| Value | Notes |
|---|---|
| `passthrough` | Allowed |
| `blocked` | Blocked |
| (empty) | Rare, a handful of rows |

### `level` (Webfilter Level)

| Value | Notes |
|---|---|
| `information` | Informational |

### `hostname` (Request Hostname)

Observed hostnames from FAZ webfilter logs:

| Pattern | Examples |
|---|---|
| Cloud auth | `login.cloudauth.example.com`, `outlook.office.example.com`, `autologon.microsoftazuread-sso.example.com`, `settings-win.data.example.com`, `vortex.data.example.com`, `browser.events.data.example.com`, `mobile.events.data.example.com`, `eu-mobile.events.data.example.com`, `eu-office.events.data.example.com`, `v10.events.data.example.com` |
| Collaboration | `teams.example.com`, `teams.events.data.example.com`, `config.teams.example.com`, `statics.teams.cdn.example.net`, `teams.cloud.example.com` |
| Email | `outlook.office.example.com`, `outlook.office.com` |
| AI/Chat | `api.ai-assistant.example.com`, `chat.ai.example.com` |
| Cloud storage | `bolt.cloud-storage.example.com`, `epivpn.example.group`, `start.cloudya.example.com` |
| Privacy proxy | `mask.proxy.example.com`, `gateway.proxy.example.com`, `p139-contacts.proxy.example.com` |
| Secure messaging | `grpc.chat.secure.example.org`, `config.edge.voice-call.example.com` |
| Telemetry | `eu.api.security-monitor.example.com`, `http-intake.logs.us5.example.com`, `in.appcenter.example.com`, `telemetry.password-manager.example.com`, `analytics.endpoint.example.com` |
| Banking | `banking-api.example.at`, `tools.example.at`, `payments.example.com` |
| Enterprise tools | `enterprise.collab.example.net`, `xp.collab.example.com`, `ticket.service.example.com`, `wifi-controller.example.net` |
| Regional sites | `www.example.at`, `vdb.example.at`, `vdbtest.example.at`, `www.regional.example.at`, `craft-beer.example.at`, `www.malt-craft.example.at`, `spirit-lovers.example.at` |
| CDN/updates | `h10141.www1.device.example.com`, `grafana.example.com`, `apt.archive.os.example.com` |
| SDKs/developer | `sdk-services.vendor.example.com`, `api.ipify.example.org` |
| Custom IPs | `203.0.113.25`, `198.51.100.40` |
