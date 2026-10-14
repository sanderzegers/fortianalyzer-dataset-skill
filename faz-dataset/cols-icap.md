# `$log-icap` — ICAP (Internet Content Adaptation Protocol)

ICAP logs are FortiGate UTM logs (`type=utm`, `subtype=icap`, log category 20, event type `icap`) written when a proxy-based firewall policy with an ICAP profile offloads content to an ICAP server. The FortiOS 7.6 Log Message Reference lists three messages: 60000 ICAP_SERVER_ERROR, 60001 ICAP_INFECTION_BLOCK ("Traffic blocked as ICAP server found infection") and 60002 ICAP_CONN_ERROR ("Traffic dropped as ICAP connection is closed").

> **No separate ICAP table.** FAZ 7.6 offers no `icap` log type for FortiGate in faz_list_types. The `$log-icap` macro resolves to the **protocol table** — the same table as `$log-protocol` (see cols-protocol.md). Fortinet's FAZ documentation does not say where ICAP logs are stored; the FortiOS ICAP fields below all exist in that table, so filter on `subtype='icap'` (value unverified). Columns named `icap*` (listed in earlier versions of this file) **don't exist**.

## Columns (FortiOS 7.6 ICAP fields that exist in the table)

| Column | Type | Description |
|---|---|---|
| **`action`** | — | Action taken |
| **`infection`** / `virusid` / `violations` | — | Infection reported by the ICAP server / virus ID / violations |
| `reason` / `msg` | — | Reason / log message |
| **`url`** / `service` / `proto` / `sessionid` / `transid` | — | Request URL / service / protocol number / session / transaction ID |
| **`profile`** / `profilegroup` | — | ICAP profile / profile group |
| **`srcip`** / `srcport` / `srcmac` / `srcname` / **`dstip`** / **`dstport`** | — | Endpoints |
| `srcintf` / `srcintfrole` / `dstintf` / `dstintfrole` / `srczone` / `dstzone` | — | Interfaces, roles, zones |
| `srccountry` / `dstcountry` / `srcuuid` / `dstuuid` / `vrf` | — | GeoIP / address UUIDs / VRF |
| **`policyid`** / `poluuid` / `policytype` | — | Firewall policy |
| `eventtype` / `eventtime` / `tz` / `logid` / `type` / `subtype` / `level` | — | Log identification |

## Key Pattern

```sql
-- ICAP blocks and errors by message and reason
SELECT logid, action, reason, count(*) AS cnt
FROM $log-icap
WHERE $filter AND subtype = 'icap'
GROUP BY logid, action, reason
ORDER BY cnt DESC
```

Schema verified on FAZ 7.6 (column names exist). No log data was available, so values are unverified — run `SELECT <col>, count(*) ... GROUP BY <col>` first. Check `SELECT subtype, count(*) FROM $log-protocol WHERE $filter GROUP BY subtype` to confirm ICAP rows really land in this table.
