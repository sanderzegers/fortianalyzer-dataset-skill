# `$log-waf` — Web Application Firewall

WAF logs are FortiGate UTM logs (`type=utm`, `subtype=waf`, log category 12) written by a Web Application Firewall security profile on a firewall policy. The FortiOS 7.6 Log Message Reference lists six event types: `waf-signature` (30248 SIGNATURE_BLOCK, 30249 SIGNATURE_PASS, 30250 SIGNATURE_ERASE), `waf-custom-signature` (30251/30252 BLOCK/PASS), `waf-http-method` (30253 METHOD_BLOCK), `waf-http-constraint` (30257/30258 CONSTRAINTS_BLOCK/PASS), `waf-address-list` (30255 ADDRESS_LIST_BLOCK) and `waf-url-access` (30259/30260/30261 URL_ACCESS_PERMIT/BYPASS/BLOCK). All common columns apply (see cols-common.md).

> Names like `wafaction`, `wafattack`, `wafattackid`, `wafseverity`, `wafprofile`, `wafvulnerability`, `serverip`, `serverport`, `statuscode`, `requestheader`, `requestbody`, `hostname`, `domain` and `intfrole` **don't exist** and fail with "Missing columns". Use `srcip`/`dstip`, `profile`, `severity`, `name` and `url`.

## Columns

| Column | Type | Description |
|---|---|---|
| **`eventtype`** | — | WAF event type (see list above) |
| **`action`** | — | Action taken |
| **`name`** | — | Method or custom signature name |
| `eventid` | — | Event ID |
| **`severity`** | — | Severity |
| `constraint` | — | Violated HTTP protocol constraint (waf-http-constraint events) |
| **`url`** / `httpmethod` / `agent` / `referralurl` | — | Request URL / HTTP method / user agent / referer |
| `ratemethod` | — | Rate method |
| `rawdata` | — | Raw request data |
| `msg` | — | Log message |
| **`profile`** / `profilegroup` | — | WAF profile / profile group |
| `service` / `proto` / `direction` / `sessionid` / `transid` | — | Service / protocol number / direction / session ID / transaction ID |
| **`srcip`** / `srcport` / **`dstip`** / **`dstport`** | — | Client and server endpoints |
| `srcintf` / `srcintfrole` / `dstintf` / `dstintfrole` | — | Interfaces and roles |
| `srczone` / `dstzone` / `srccountry` / `dstcountry` / `srcdomain` | — | Zones / GeoIP countries / source domain |
| `srcuuid` / `dstuuid` | — | Address object UUIDs |
| **`user`** / `group` / `authserver` / `dstuser` / `dstauthserver` | — | User identity |
| `unauthuser` / `unauthusersource` / `fctuid` | — | Unauthenticated user / source / FortiClient UID |
| **`policyid`** / `poluuid` / `policytype` | — | Firewall policy |
| `eventtime` / `tz` | — | Device event time / time zone |
| `logid` / `type` / `subtype` / `level` | — | Log identification |

## Key Patterns

```sql
-- Top WAF hits by event type, signature and target
SELECT eventtype, name, ipstr(dstip) AS server, count(*) AS hits
FROM $log-waf
WHERE $filter
GROUP BY eventtype, name, server
ORDER BY hits DESC
LIMIT 50

-- Top attacking clients per action
SELECT ipstr(srcip) AS client, action, count(*) AS hits
FROM $log-waf
WHERE $filter
GROUP BY client, action
ORDER BY hits DESC
LIMIT 20
```

Schema verified on FAZ 7.6 (column names exist). No log data was available, so values are unverified — run `SELECT <col>, count(*) ... GROUP BY <col>` first.
