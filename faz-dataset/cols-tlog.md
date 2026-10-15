# `$log-traffic` — Traffic/Firewall Sessions

Richest log type. Represents completed or sampled firewall sessions. All common columns apply (see cols-common.md).

## Session & Bytes

| Column | Type | Description |
|---|---|---|
| **`sentbyte`** | Nullable(UInt64) | Bytes sent (client→server) — closed sessions |
| **`rcvdbyte`** | Nullable(UInt64) | Bytes received (server→client) — closed sessions |
| **`sentdelta`** | Nullable(UInt64) | Delta bytes sent — long-lived sessions (prefer over `sentbyte`) |
| **`rcvddelta`** | Nullable(UInt64) | Delta bytes received — long-lived sessions (prefer over `rcvdbyte`) |
| `sentpkt` / `rcvdpkt` | Nullable(Int64) | Packets sent/received |
| `sentpktdelta` / `rcvdpktdelta` | Nullable(UInt32) | Delta packets. **FortiOS 7.4+**, empty on 7.2 (see version-differences.md) |
| **`duration`** | Nullable(UInt32) | Session duration in seconds |
| `durationdelta` | Nullable(UInt32) | Delta duration. **FortiOS 7.4+**, empty on 7.2 |
| `wanin` / `wanout` | Nullable(UInt64) | WAN bytes in/out |
| `lanin` / `lanout` | Nullable(UInt64) | LAN bytes in/out |

> **Bytes pattern:** `coalesce(sentdelta, sentbyte, 0)` — delta exists for long-lived sessions, byte for closed. Always use this form for bandwidth queries. The byte deltas exist on every FortiOS version tested (7.2.10–7.6.7).
>
> **Packets/duration:** `coalesce(sentpktdelta, sentpkt, 0)` / `coalesce(durationdelta, duration, 0)`. On FortiOS 7.2 the packet/duration deltas are always NULL, so the sum falls back to cumulative values and overcounts long-lived sessions there.
> **logflag for bandwidth:** use `bitAnd(logflag,bitOr(1,32))>0` to include long-lived sessions.

## NAT

| Column | Type | Description |
|---|---|---|
| `tranip` / `transip` | Nullable(IPv6) | NAT translated destination/source IP |
| `tranport` / `transport` | Nullable(UInt16) | NAT translated port |
| `trandisp` | LowCardinality(String) | NAT type: `snat`, `dnat`, `noop` |
| `vip` | Nullable(String) | VIP name |

## Application

| Column | Type | Description |
|---|---|---|
| **`app`** | LowCardinality(String) | Application name — may be `"N/A"`, use `nullifna()` |
| **`appcat`** | LowCardinality(String) | Application category |
| `appid` | Nullable(UInt32) | Application ID |
| **`apprisk`** | LowCardinality(String) | Risk: `critical`, `high`, `medium`, `low`, `elevated` |
| `appact` | LowCardinality(String) | App control action |
| `applist` | LowCardinality(String) | App control profile name |
| `apps` | Array(String) | Array of app names — use `arrayJoin()` or `has()` |
| `countapp` | Nullable(UInt32) | App-ctrl UTM event count |

## UTM / Security Summary (on traffic rows)

| Column | Type | Description |
|---|---|---|
| **`utmaction`** | LowCardinality(String) | UTM action: only `allow`, `block` or empty (no UTM involved). Same on FortiOS 7.2.10, 7.4.12 and 7.6.7 (~160 M rows) |
| **`utmevent`** | LowCardinality(String) | **Always empty.** FortiOS doesn't send `utmevent` in traffic logs (absent from the log ID 13 field list in 7.2, 7.4 and 7.6; empty on ~160 M rows). Use the `count*` columns below instead |
| `utmsubtype` | Nullable(String) | UTM sub-event |
| **`attack`** | LowCardinality(String) | IPS attack name (summary) |
| **`virus`** | LowCardinality(String) | AV virus name (summary) |
| **`catdesc`** | LowCardinality(String) | Web category description |
| `dlpsensor` | Nullable(String) | DLP sensor triggered |
| **`accessctrl`** | LowCardinality(String) | Cloud access control action: `upload`, `download`, `others` |
| `countav` / `countdlp` / `countemail` / `countips` / `countweb` | Nullable(UInt32) | UTM event counts per type |
| `countff` / `countssh` / `countssl` / `countdns` / `countwaf` | Nullable(UInt32) | UTM event counts per type |

On every FortiOS version, `countX > 0` is the working way to find traffic sessions a UTM feature touched (tested: `countweb`, `countapp`, `countips`, `countav`, `countdns`, `countssl`). For example, `WHERE $filter AND countips > 0` finds sessions with an IPS event.
| `threats` | Array(String) | Threat names |
| `threattyps` | Array(String) | Threat types |
| `threatwgts` | Array(Int32) | Threat weights |
| `threatcnts` | Array(Int16) | Threat counts |
| `threatlvls` | Array(Int8) | Threat levels |

## User Identity

| Column | Type | Description |
|---|---|---|
| **`user`** | LowCardinality(String) | Authenticated user — may be `"N/A"` |
| **`unauthuser`** | LowCardinality(String) | Unauthenticated user — may be `"N/A"` |
| `dstunauthuser` | Nullable(String) | Destination unauthenticated user |
| `dstuser` | Nullable(String) | Destination user |
| `clouduser` | Nullable(String) | Cloud user identity |
| `emstag` / `emstag2` | Nullable(String) | EMS tags from FortiClient |

## Device Fingerprinting

| Column | Type | Description |
|---|---|---|
| `devtype` | LowCardinality(String) | Source device type |
| `devcategory` | LowCardinality(String) | Source device category |
| `dstdevtype` | LowCardinality(String) | Destination device type |
| `osname` / `osversion` | LowCardinality/Nullable(String) | Source OS name/version |
| `dstosname` | LowCardinality(String) | Destination OS name |
| `srcmac` | Nullable(String) | Source MAC address |
| `srcmacvendor` | Nullable(String) | Source MAC vendor |

## HTTP-specific

| Column | Type | Description |
|---|---|---|
| `httpmethod` | Nullable(String) | `GET`, `POST`, etc. |
| `statuscode` | Nullable(String) | HTTP status code |
| `scheme` | Nullable(String) | `http`, `https` |
| `referralurl` | Nullable(String) | HTTP referral URL |
| `reqlength` / `resplength` | Nullable(UInt64) | Request/response length |
| `reqtime` / `resptime` | Nullable(UInt64) | Request/response time (μs) |

## Networking

| Column | Type | Description |
|---|---|---|
| `accessproxy` | Nullable(String) | Access proxy name |
| `tunnelid` | Nullable(UInt32) | VPN tunnel ID |
| `vwlid` | Nullable(UInt32) | SD-WAN rule ID |
| `vwlservice` / `vwlname` | Nullable(String) | SD-WAN service/policy name |

## Standard logflag Filters

```sql
-- Sessions (most queries)
WHERE $filter AND (bitAnd(logflag,1)>0)

-- Bandwidth (include long-lived)
WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)

-- Blocked only
WHERE $filter AND (bitAnd(logflag,2)>0)

-- End users only (exclude FCT system user)
WHERE $filter AND (bitAnd(logflag,1)>0) AND (bitAnd(logflag,8)=0)
```

## Canonical User Identity Pattern

```sql
coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) AS user_src
```

## Real Values Discovered from FAZ Instance

Observed values from querying `query_logs` on the live FAZ instance (2026-09-28):

### `action` (Traffic)

| Value | Notes |
|---|---|
| `accept` | Session accepted |
| `close` | Session closed |
| `client-rst` | Client TCP RST |
| `server-rst` | Server TCP RST |
| `deny` | Denied |
| `ip-conn` | Failed connection attempts (FortiOS Log Reference) |
| `dns` | DNS query return error (FortiOS Log Reference). Seen on UDP/53 sessions without a reply |
| `timeout` | Timed out |

### `appcat` (Application Category)

| Value | Notes |
|---|---|
| `Web.Client` | Most common — browsers |
| `Network.Service` | DNS, NTP, protocols |
| `Collaboration` | Teams, Slack |
| `Email` | Email clients |
| `Cloud.IT` | Cloud tools |
| `Update` | Update services |
| `General.Interest` | Google, web services |
| `Remote.Access` | Remote access |
| `Storage.Backup` | Cloud storage |
| `Video/Audio` | Streaming |
| `GenAI` | AI services |
| `unknown` | Uncategorised |
| `unscanned` | Not scanned |

### `apprisk` (Application Risk)

| Value | Notes |
|---|---|
| `low` | Low risk |
| `medium` | Medium risk |
| `elevated` | Elevated risk |
| `high` | High risk |

### `level` (Traffic)

| Value | Notes |
|---|---|
| `notice` | Most common |
| `warning` | Warnings |

### `srczone` / `dstzone`

Sent from **FortiOS 7.6** onward and only when interfaces are grouped in zones. Empty in every sample (7.2.10, 7.4.12 and 7.6.7). Zone names are admin-defined, so group by them instead of hardcoding them. For mixed FortiOS estates, group by `srcintf` / `dstintf`.

### `policytype` (Policy Type)

| Value | Notes |
|---|---|
| `local-in-policy` | Local-in policy (FAZ appliance-facing) |

### `dstosname` (Destination OS Name)

| Value | Notes |
|---|---|
| `FortiAnalyzer OS` | FAZ appliance OS |

### `vwlquality` (SD-WAN Quality)

Observed SD-WAN quality strings from FAZ traffic logs:

| Pattern | Notes |
|---|---|
| `Seq_num(N {SITE}_ISP1_{N} {HEALTHCHECK}), alive, latency: X.XXX, selected` | VPN tunnel quality |
| `Seq_num(N {ISPNAME}_root {HEALTHCHECK}), alive, sla(0x1), gid(0), cfg_order(N), local cost(N), selected` | External SD-WAN member |

> **Pattern:** `Seq_num({NUM} {TUNNEL-NAME} {ZONE}), alive, sla({HEX}), gid({NUM}), cfg_order({NUM}), local cost({NUM}), selected`
> **Key fields:** `sla(0x1)` = SLA target met, `selected` = active path, `alive` = healthy


### `policyname` (Policy Name)

Free-text, admin-defined names — every deployment differs. Never assume specific values; ask the user for the policy name or group by `policyname` / `policyid` instead of filtering.

### `utmaction` (UTM Action)

| Value | Notes |
|---|---|
| `allow` | Allowed |
| `block` | Blocked |
| (empty) | No UTM involved, ~75–80 % of rows |


## Real `vd` Values

The VDOM column is **`vd`** (there's no `vdom` column). Single-VDOM FortiGates log `root`.

## Real `devtype` Values

| Value | Notes |
|---|---|
| `Server` | Server devices |
| `Home & Office` | Home/office equipment |
| `HM90` | Handheld mobile |
| `Printer` | Printers |
| `Dell Pro Precisi` | Dell Pro / Precision workstations |
| `Network` | Network equipment |
| `DSM` | Desktop / server / monitor |
| `Camera` | IP cameras |
| `Laptop` | Laptops |
| `Mobile` | Mobile phones |
| `Router` | Routers |
| `NAS` | Network-attached storage |
| `AP` | Wireless access points |
| `IoT` | IoT devices |

## Real `osname` Values

| Value | Notes |
|---|---|
| `Windows` | Windows desktop/server |
| `Linux` | Linux systems |
| `DSM` | Desktop / server / monitor |
| `macOS` | Apple macOS |
| `iOS` | Apple iOS |
| `Android` | Android devices |
| `ChromeOS` | ChromeOS devices |
| `FortiOS` | FortiOS appliances |

## Real `applist` Values

| Value | Notes |
|---|---|
| `AC-PRO` | App control profile |
| `AC-PRO-Client` | Client app control |
| `AC-PRO-monitor` | Monitoring profile |
| `AC-PRO-Admin` | Admin app control |
| `AC-PRO-Mobile` | Mobile app control |
| `AC-PRO-Web` | Web app control |

## Real `service` Values

Additional service names observed beyond the well-known defaults:

| Value | Notes |
|---|---|
| `MQTT` | Message Queuing Telemetry Transport |
| `NTP` | Network Time Protocol |
| `QUIC` | UDP-based quick UDP Internet Connections |
| `BGP` | Border Gateway Protocol |
| `OSPF` | Open Shortest Path First |
| `SNMP` | Simple Network Management Protocol |
| `custom-{PORT}` | Custom-named service on port `{PORT}` |

> **Pattern:** Custom services follow `{name}-{PORT}` format — match with `service LIKE '%-%' AND service NOT LIKE '%DNS%' AND service NOT LIKE '%HTTP%'` to exclude well-known names.


### Fields with No Non-N/A Values in Sample Window

The following fields had zero non-N/A results when queried with exclusion filters:

`appsubcategory`, `appsubcategory2`, `utmsubtype`, `devcategory`, `osversion`, `srcmacvendor`, `poluuid`, `policymode`, `policyid`, `vlanid`, `vlan`, `srcvrf`, `dstvrf`, `srcgw`, `dstgw`, `srcnatip`, `dstnatip`, `srcnatport`, `dstnatport`

These fields are either always `N/A` in the current traffic logs or not populated.
