# `$log-security` — Security Table (virtual patch, CASB, FortiSwitch flow)

FortiOS has no log type called "security": the FortiOS 7.6 Log Message Reference has no security subtype besides the event subtype `security-rating` (that one is in `$log-event`). In FAZ 7.6, `$log-security` is a table whose schema matches the newer FortiGate UTM subtypes that have no own FAZ log type: **`virtual-patch`** (category 24: 64600/64601 OT_VPATCH_BLOCK/LOG, 64610/64611 LOCALIN_VPATCH_BLOCK/LOG), **`casb`** (category 25: 10000–10002, e.g. 10000 CASB_ACCESS_BLOCKED "Web content banned activity found") and **`forti-switch`** (category 23: 56001 FSW_FLOW). `$log-virtual-patch` resolves to this same table (see cols-virtual-patch.md). This mapping is inferred from the schema: all documented fields of those three subtypes exist here, while ICAP-only fields (`infection`, `virusid`, `violations`, `reason`) do not. Fortinet's FAZ documentation does not describe it. All common columns apply (see cols-common.md).

> Names like `securityaction`, `securitytype`, `securityseverity`, `securitycategory`, `attacker`, `victim`, `attackerport`, `victimport`, `attacktype`, `attackname`, `attackeros`, `victimos`, `devvdom`, `sentpkt`, `sentbyte`, `tzsrc`, `tzdst` and `utmmode` **don't exist** and fail with "Missing columns". Only received counters (`rcvdbyte`, `rcvdpkt`) exist; they come from FortiSwitch flow logs.

## Columns

| Column | Type | Description |
|---|---|---|
| **`subtype`** | — | Separates the row kinds (expected `virtual-patch`, `casb`, `forti-switch` per FortiOS; unverified) |
| **`eventtype`** | — | e.g. `ot-vpatch`, `localin-vpatch`, `casb`, `fsw-flow` (per log reference) |
| **`action`** | — | Action taken |
| `msg` / `severity` / `level` | — | Message / severity / log level |
| **`attack`** / **`attackid`** / `attackcontext` / `attackcontextid` | — | Virtual-patch signature and context |
| `hostname` / **`url`** / `httpmethod` / `agent` / `referralurl` | — | HTTP request details |
| `rawdata` / `rawdataid` / `forwardedfor` / `trueclntip` | — | Raw data / X-Forwarded-For / true client IP |
| **`saasapp`** / `useractivity` / `activitycategory` / `operation` / `subaction` / `tenantmatch` | — | CASB: SaaS application, user activity and its category, operation, sub-action, tenant match |
| **`switchid`** / `ftlkintf` / `duration` / **`rcvdbyte`** / `rcvdpkt` | — | FortiSwitch flow: switch ID, FortiLink interface, duration, received bytes/packets |
| **`profile`** / `profilegroup` | — | Profile / profile group |
| `service` / `proto` / `direction` / `sessionid` / `vrf` | — | Service / protocol number / direction / session ID / VRF |
| **`srcip`** / `srcport` / `psrcport` / `srcmac` / `srcname` / **`dstip`** / **`dstport`** / `pdstport` | — | Endpoints |
| `srcintf` / `srcintfrole` / `dstintf` / `dstintfrole` / `srczone` / `dstzone` | — | Interfaces, roles, zones |
| `srccountry` / `dstcountry` / `srcdomain` / `srcuuid` / `dstuuid` | — | GeoIP / source domain / address UUIDs |
| `user` / `group` / `authserver` / `dstuser` / `dstauthserver` / `unauthuser` / `unauthusersource` / `fctuid` | — | User identity |
| **`policyid`** / `poluuid` / `policytype` / `policymode` | — | Firewall policy |
| `eventtime` / `tz` / `logid` / `type` | — | Log identification |

## Key Patterns

```sql
-- What is in this table
SELECT subtype, eventtype, count(*) AS cnt
FROM $log-security
WHERE $filter
GROUP BY subtype, eventtype
ORDER BY cnt DESC

-- CASB activity per SaaS application and user
SELECT saasapp, useractivity, coalesce(nullifna(`user`), ipstr(srcip)) AS who, action, count(*) AS cnt
FROM $log-security
WHERE $filter AND subtype = 'casb'
GROUP BY saasapp, useractivity, who, action
ORDER BY cnt DESC
LIMIT 50
```

Schema verified on FAZ 7.6 (column names exist). No log data was available, so values are unverified — run `SELECT <col>, count(*) ... GROUP BY <col>` first.
