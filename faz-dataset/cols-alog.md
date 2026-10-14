# `$log-app-ctrl` — Application Control

Dedicated app-ctrl UTM log (distinct from UTM summary fields on traffic rows). All common columns apply.

| Column | Type | Description |
|---|---|---|
| **`app`** | LowCardinality(String) | Application name — may be `"N/A"`, use `nullifna()` |
| **`appcat`** | LowCardinality(String) | Application category |
| `appid` | Nullable(UInt32) | Numeric application ID |
| **`apprisk`** | LowCardinality(String) | Risk: `critical`, `high`, `medium`, `low`, `elevated` |
| `applist` | LowCardinality(String) | App control profile name |
| **`action`** | LowCardinality(String) | `pass`, `block`, `reset` |
| `eventtype` | LowCardinality(String) | `app-ctrl` |
| `clouduser` | Nullable(String) | Cloud app user identity |
| `cloudaction` | Nullable(String) | Cloud action |
| `clouddevice` | Nullable(String) | Cloud device |
| `sentbyte` | Nullable(UInt64) | Session bytes sent |
| `rcvdbyte` | Nullable(Int64) | Session bytes received |
| `filesize` | Nullable(UInt64) | File size (for file-type detection) |
| `filename` | Nullable(String) | Filename if applicable |
| `crscore` / `craction` / `crlevel` | — | Compound risk score fields |
| `hostname` / `url` / `dstname` | — | Destination host / URL / name |
| `cloudgenai` / `aiuser` / `prompt` / `model` / `usecase` / `dcgeo` | — | GenAI app fields (AI service, user, prompt text, model, use case, data-center geo). **Sent only by FortiOS 7.6.4+**, empty on older FortiGates (see version-differences.md) |

## Key Pattern

```sql
-- Top apps by bandwidth. App-ctrl logs carry no byte counts (sentbyte/rcvdbyte
-- are empty on FortiOS 7.2-7.6), so bandwidth per app comes from traffic logs
SELECT app_group, appcat, sum(bandwidth) AS bandwidth
FROM ###(
    SELECT app_group_name(app) AS app_group, appcat,
           sum(coalesce(sentdelta,sentbyte,0)+coalesce(rcvddelta,rcvdbyte,0)) AS bandwidth
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0) AND nullifna(app) IS NOT NULL
    GROUP BY app_group, appcat
    /*SkipSTART*/ORDER BY bandwidth DESC/*SkipEND*/
)### t
GROUP BY app_group, appcat
ORDER BY bandwidth DESC
```

## Real Values Discovered from FAZ Instance

### `action` (App-CTRL Action)

Observed from FAZ app-ctrl logs:

| Value | Notes |
|---|---|
| `pass` | Passed |

### `level` (App-CTRL Level)

| Value | Notes |
|---|---|
| `information` | Informational |

### `app` (Application Name)

Observed application names from FAZ app-ctrl logs:

| Value | Notes |
|---|---|
| `HTTP.BROWSER` | Most common — web browsing |
| `SSL` / `SSL_TLSv1.3` / `SSL_TLSv1.3.PQC` | TLS connections |
| `QUIC` | QUIC protocol |
| `SSH` | Secure shell |
| `Ping` | ICMP ping |
| `Microsoft.Authentication` | Microsoft login/auth |
| `Microsoft.Outlook` | Outlook email |
| `Microsoft.Portal` | Microsoft portal services |
| `iCloud` | Apple iCloud |
| `LastPass` | Password manager |
| `Rapid7.Insight.Agent` | Security monitoring agent |


### `hostname` (Destination Hostname)

Observed hostnames from FAZ logs:

| Value | Notes |
|---|---|
| `unifi-ctrl.local` / `unifi` | Wi-Fi controller |
| `vpn-gw.local` | VPN gateway |
| `login.cloudauth.example.com` | Cloud auth provider |
| `outlook.office.example.com` | Email client |
| `mask.proxy-service.example.com` / `gateway.proxy-service.example.com` | Privacy proxy |
| `telemetry.cloudauth.example.com` | Cloud telemetry |
| `events.events-data.example.com` | Event telemetry |
| `mobile.events-data.example.com` | Mobile event telemetry |
| `payments.example.com` | Payment processing |
| `push-server.example.com` | Push notifications |
| `api.security-monitor.example.com` | Security monitoring |
| `updates.cloudos.example.com` | OS updates |
| `198.51.100.143` / `192.0.2.58` | Internal IPs |
| `banking-api.example.at` | Banking API |
| `tools.example.at` | Internal tools |
| `www.banking-example.at` | Banking portal |
| `203.0.113.214` | External IP |
| `192.0.2.91` | External IP |
