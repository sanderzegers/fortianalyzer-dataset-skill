# `$log-virtual-patch` — Virtual Patching

Virtual-patch logs are FortiGate UTM logs (`type=utm`, `subtype=virtual-patch`, log category 24, added in FortiOS 7.4.1). The FortiOS 7.6 Log Message Reference lists two event types: `ot-vpatch` (64600 OT_VPATCH_BLOCK "Traffic was blocked by an OT virtual patch", 64601 OT_VPATCH_LOG) and `localin-vpatch` (64610 LOCALIN_VPATCH_BLOCK "Traffic was blocked by local-in virtual patch", 64611 LOCALIN_VPATCH_LOG). Full logid example: `2400064600`. Older builds logged local-in virtual patch hits as IPS signature logs (`$log-attack`, `msg` starting with `vPatch:`), per the FortiOS administration guide.

> **No separate virtual-patch table.** FAZ 7.6 offers no `virtual-patch` log type for FortiGate in faz_list_types. The `$log-virtual-patch` macro resolves to the **security table** — the same table as `$log-security` (see cols-security.md), which also holds the CASB and FortiSwitch flow columns. Fortinet's FAZ documentation does not say where these logs are stored. All FortiOS 7.6 virtual-patch fields below exist in that table; filter on `subtype='virtual-patch'` (value unverified). Columns named `vwpv*` (listed in earlier versions of this file) **don't exist**.

## Columns (FortiOS 7.6 virtual-patch fields that exist in the table)

| Column | Type | Description |
|---|---|---|
| **`eventtype`** | — | `ot-vpatch` or `localin-vpatch` (per log reference) |
| **`action`** | — | Action taken |
| **`attack`** / **`attackid`** | — | Virtual-patch signature name / ID |
| `attackcontext` / `attackcontextid` | — | Attack context data / ID |
| **`severity`** | — | Signature severity |
| `msg` | — | Log message (added in 7.6.1) |
| `hostname` / **`url`** / `httpmethod` / `agent` / `referralurl` | — | HTTP request details |
| `rawdata` / `rawdataid` | — | Raw data / its ID |
| `forwardedfor` / `trueclntip` | — | X-Forwarded-For value / true client IP |
| **`profile`** / `profilegroup` | — | Virtual-patch profile / profile group |
| `service` / `proto` / `direction` / `sessionid` / `vrf` | — | Service / protocol number / direction / session ID / VRF |
| **`srcip`** / `srcport` / `psrcport` / **`dstip`** / **`dstport`** / `pdstport` | — | Endpoints (`p*` = port fields as documented) |
| `srcintf` / `srcintfrole` / `dstintf` / `dstintfrole` / `srczone` / `dstzone` | — | Interfaces, roles, zones |
| `srccountry` / `dstcountry` / `srcdomain` | — | GeoIP / source domain |
| `user` / `group` / `authserver` / `dstuser` / `dstauthserver` / `unauthuser` / `unauthusersource` / `fctuid` | — | User identity |
| **`policyid`** / `poluuid` / `policytype` / `policymode` | — | Firewall policy |
| `eventtime` / `tz` / `logid` / `type` / `subtype` / `level` | — | Log identification |

## Key Pattern

```sql
-- Virtual-patch hits by signature and target
SELECT eventtype, attack, ipstr(dstip) AS target, action, count(*) AS hits
FROM $log-virtual-patch
WHERE $filter AND subtype = 'virtual-patch'
GROUP BY eventtype, attack, target, action
ORDER BY hits DESC
LIMIT 50
```

Schema verified on FAZ 7.6 (column names exist). No log data was available, so values are unverified — run `SELECT <col>, count(*) ... GROUP BY <col>` first. Run `SELECT subtype, count(*) FROM $log-security WHERE $filter GROUP BY subtype` to confirm which subtypes land in this table.
