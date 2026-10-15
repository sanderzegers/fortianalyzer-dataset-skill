# `$log-fct-event` — FortiClient Event Log

**Important differences from FortiGate logs:** endpoint-agent logs, not network device logs. FortiClient is its own device type (3) in FAZ: query and build datasets with that device type. With FortiGate selected, `$log-fct-event` resolves to an empty table.

`uid` is the FortiClient UID (a UUID), the same value FortiGate logs as `fctuid` in its traffic log (investigating.md). **Count endpoints by `uid`, not `devid`:** in FortiClient logs `devid`/`devname` is the EMS server that forwarded the logs (1 value against 249 `uid`s in one day on one FAZ). FAZ also rejects a scalar subquery that aggregates `devid` over a FortiClient table (`SELECT (SELECT uniqExact(devid) FROM $log-fct-event ...)` → "SQL query is forbidden"), while the same aggregate as the main query works.
- No `srcip`/`dstip` — uses `deviceip`/`remip` instead
- `logid` is **UInt64** (not String) — do NOT use `logid_to_int()`. Don't filter on it in `WHERE`/`HAVING` either: FAZ handles a `logid` filter as a string, so `WHERE logid = 12345` fails with "no supertype for types String, UInt16" (Common Mistake #17). Count by `logid` inside `SELECT` (`countIf`) instead. Tested: `WHERE logid IN (96957)` returned 0 rows where `countIf(logid = 96957)` counted 193,281
- No `sessionid` / `policyid`

All common columns apply where relevant (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| `subtype` | LowCardinality(String) | `av`, `webfilter`, `app-ctrl`, `vpn`, `endpoint`, `vulnerability`, `ems` |
| **`hostname`** | LowCardinality(String) | Client machine hostname |
| `deviceip` | Nullable(IPv6) | Client device IP |
| `devicemac` | Nullable(String) | Client device MAC |
| `user` | LowCardinality(String) | Logged-in user |
| **`os`** | LowCardinality(String) | OS string: `"Windows 10,x64,10.0.19041"` — use `split_part(os,',',1)` for OS family |
| `fctver` | Nullable(String) | FortiClient version |
| `emsserial` | LowCardinality(String) | EMS serial number |
| `fgtserial` | LowCardinality(String) | Connected FortiGate serial |
| `uid` | Nullable(UUID) | FortiClient instance UUID |
| `logid` | **UInt64** | Log ID — integer, NOT string, no `logid_to_int()` needed |
| **`action`** | LowCardinality(String) | `blocked`, `allowed`, `detected`, `quarantine`, `removed` |
| **`virus`** | LowCardinality(String) | Detected virus/malware name |
| **`app`** | LowCardinality(String) | Application name |
| `appid` | Nullable(UInt32) | Application ID |
| `apppath` | Nullable(String) | Application file path |
| `appversion` / `appvendor` | Nullable(String) | Application metadata |
| **`vulnid`** | Nullable(UInt64) | Vulnerability ID |
| **`vulnname`** | LowCardinality(String) | Vulnerability name |
| `vulnseverity` | LowCardinality(String) | Vulnerability severity |
| `vulncat` | LowCardinality(String) | Vulnerability category |
| `vulncvss` | Nullable(String) | CVSS score |
| `vulnref` | Nullable(String) | CVE reference |
| **`vpntunnel`** | LowCardinality(String) | VPN tunnel name |
| `vpntype` / `vpnstate` | Nullable(String) | VPN type/state |
| `remotegw` | Nullable(IPv6) | Remote VPN gateway IP |
| `cat` / `catdesc` | LowCardinality | Web category / description |
| `hostname` | LowCardinality(String) | Web destination hostname |
| `url` | Nullable(String) | URL |
| `epmgmtst` | LowCardinality(String) | Endpoint management status |
| `eponlinest` | LowCardinality(String) | Endpoint online status |
| `epplace` | LowCardinality(String) | `on-net`, `off-net` |
| `score` | Nullable(Int64) | Risk score |

## Key Pattern

```sql
-- OS distribution
SELECT split_part(os, ',', 1) AS os_family, count(*) AS cnt
FROM $log-fct-event
WHERE $filter AND nullifna(os) IS NOT NULL
GROUP BY os_family
ORDER BY cnt DESC
```

## Endpoint Status Columns (column names verified on FAZ 7.6; values unverified)

| Column | Type | Description |
|---|---|---|
| `epmgmtst` | LowCardinality(String) | Endpoint management status |
| `eponlinest` | LowCardinality(String) | Endpoint online status |
| `epplace` | LowCardinality(String) | Endpoint location |

### `epmgmtst` (Endpoint Management Status)

| Value | Notes |
|---|---|
| `blocked` | Endpoint blocked |
| `quarantined` | Endpoint quarantined |
| `unblocked` | Endpoint unblocked |
| `unquarantined` | Endpoint unquarantined |

### `eponlinest` (Endpoint Online Status)

| Value | Notes |
|---|---|
| `regonline` | Registered and online |
| `regoffline` | Registered but offline |

### `epplace` (Endpoint Location)

| Value | Notes |
|---|---|
| `onnet` | On network |
| `offnet` | Off network |
