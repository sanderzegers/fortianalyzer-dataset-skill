# Common Columns

Columns shared across `$log-*` sources, checked against real schemas for traffic, attack, webfilter and event logs. **Not every column is on every log type.** These are known gaps:

| Log type | Missing from its schema |
|---|---|
| `$log-traffic` | `direction`, `profile` |
| `$log-attack`, `$log-webfilter` | `dstname` |
| `$log-event` | `srcintf`, `dstintf`, `srczone`, `dstzone`, `sessionid`, `sfsid`, `policytype`, `policymode`, `poluuid`, `dstname` |

If unsure, `SELECT * FROM $log-x WHERE $filter LIMIT 1` lists a log type's real columns.

## Device Columns (joined automatically)

FAZ joins these onto every `$log-*` row, so **no `devtable_ext` join is needed** for device names:

| Column | Description |
|---|---|
| **`devname`** | FortiGate hostname |
| **`devid`** | FortiGate serial number |
| **`vd`** | VDOM name |
| `devgrps` | Device groups (array) |
| `csf` | Security Fabric name |
| `_adomoid` | ADOM OID |

| Column | Type | Description |
|---|---|---|
| **`dvid`** | Int32 | Device ID (join to `devtable_ext.dvid` for device name) |
| **`itime`** | DateTime | Time the FAZ received the row (seconds after the event) — `$filter` filters on this. `toString`/`toDate`/`toHour` of it give UTC unless you pass `timezone()` |
| **`dtime`** | DateTime | Device timestamp (when the event occurred) on the device's own clock and time zone — use `from_dtime(dtime)` for display; don't compare it across devices |
| **`euid`** | Int32 | End-user ID — join to `$ADOM_ENDUSER.euid`; values <1024 are system |
| **`epid`** | Int32 | Endpoint ID — join to `$ADOM_ENDPOINT.epid`; values <1024 are system |
| `dsteuid` | Int32 | Destination end-user ID |
| `dstepid` | Int32 | Destination endpoint ID — use `CASE WHEN direction='incoming' THEN epid ELSE dstepid END` for victim in attack queries |
| `sfsid` | Nullable(Int64) | FortiSandbox session ID |
| **`logflag`** | Int32 | Bitmask — see logflag section in faz-sql-reference.md |
| **`type`** | LowCardinality(String) | Log type: `traffic`, `utm`, `event`, etc. |
| **`subtype`** | LowCardinality(String) | Log subtype: `forward`, `webfilter`, `attack`, etc. |
| **`level`** | LowCardinality(String) | Severity: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `information`, `debug` |
| **`action`** | LowCardinality(String) | Action taken — see values below |
| **`logid`** | LowCardinality(String) | Log ID string — use `logid_to_int(logid)` for numeric compare |

## `action` Values

| Value | Context |
|---|---|
| `accept` | Traffic allowed by policy |
| `deny` | Traffic denied by policy |
| `block` / `blocked` | UTM block action |
| `pass` / `pass_session` | Passed/monitored without blocking |
| `detected` | IPS/AV detected but not blocked |
| `dropped` | Packet dropped |
| `reset` / `reset_client` / `reset_server` | TCP reset sent |
| `close` | Session closed normally |
| `clear_session` | Session cleared |
| `timeout` | Session timed out |
| `redirect` | Traffic redirected (e.g. captive portal) |
| `log-only` | Logged only, no enforcement |
| `exempt` | Exempted from inspection |
| `tunnel-up` / `tunnel-down` | VPN tunnel state change |
| `tunnel-stats` | VPN tunnel periodic stats |
| `perf-stats` | Performance statistics log |
| `ssl-login-fail` / `ipsec-login-fail` | VPN login failure |
| `assoc-req` / `reassoc-req` | WiFi association request |
| `login` / `logout` | Admin/user authentication events |
| `set` / `add` / `delete` / `edit` / `clear` | Config change operations |

## Real Values Discovered from FAZ Instance

### `level` (Severity)

Observed across all log types:

| Value | Most Common In |
|---|---|
| `information` | traffic, event |
| `notice` | dns |
| `warning` | traffic, attack |
| `critical` | event |

### `subtype` (Log Subtype)

Observed event subtypes:

| Value | Notes |
|---|---|
| `system` | System events |
| `config` | Config changes |
| `dhcp` | DHCP events |
| `device` | Device events |
| `event` | Generic events |
| `firewall` | Firewall events |
| `login` | Login events |
| `update` | Update events |
| `user` | User events |

### `eventtype` (Event Type)

Observed across event logs:

| Value | Notes |
|---|---|
| `AD` | Active Directory |
| `AntiVirus` / `AV` | Antivirus |
| `Config` | Config events |
| `DHCP` | DHCP |
| `DNS` | DNS |
| `Device` | Device |
| `Event` | Generic |
| `Firewall` | Firewall |
| `FortiGuard` | FortiGuard |
| `IDS` | IDS |
| `License` | License |
| `Login` | Login |
| `NAT` | NAT |
| `NTP` | NTP |
| `PKI` | PKI |
| `Policy` | Policy |
| `Proxy` | Proxy |
| `System` | System |
| `Threat` | Threat |
| `Tunnel` | Tunnel |
| `Update` | Update |
| `User` | User |
| `Web` | Web |
| `WiFi` | WiFi |


### `policytype` (Policy Type)

| Value | Notes |
|---|---|
| `policy` | Standard firewall policy |
| `local-in-policy` | Local-in policy (FAZ appliance-facing) |

### `policymode` (Policy Mode)

| Value | Notes |
|---|---|
| `flow` | Flow-based inspection |
| `proxy` | Proxy-based inspection |

### `vlanid` (VLAN ID)

| Value | Notes |
|---|---|
| `{NUM}` | VLAN identifier |

### `srcvrf` / `dstvrf` (VRF)

| Value | Notes |
|---|---|
| `N/A` | No VRF (most common) |
| `{VRF-NAME}` | VRF name |

### `srcgw` / `dstgw` (Gateway)

| Value | Notes |
|---|---|
| `203.0.113.77` | Gateway IP |
| `N/A` | No gateway |

### `srcnatip` / `dstnatip` (NAT IP)

| Value | Notes |
|---|---|
| `198.51.100.143` | NAT translated IP |
| `N/A` | No NAT |

### `srcnatport` / `dstnatport` (NAT Port)

| Value | Notes |
|---|---|
| `{PORT}` | NAT translated port |
| `N/A` | No NAT port |

## Common Column Details

| Column | Type | Description |
|---|---|---|
| **`srcip`** | Nullable(IPv6) | Source IP — always use `ipstr()` for display |
| **`dstip`** | Nullable(IPv6) | Destination IP — always use `ipstr()` for display |
| **`srcport`** | Nullable(UInt16) | Source port |
| **`dstport`** | Nullable(UInt16) | Destination port |
| `proto` | Nullable(UInt8) | IP protocol: 1=ICMP, 6=TCP, 17=UDP, 47=GRE, 50=ESP |
| **`user`** | LowCardinality(String) | Authenticated username — may be `"N/A"`, use `nullifna()` |
| `unauthuser` | LowCardinality(String) | Unauthenticated username — may be `"N/A"`, use `nullifna()` |
| `group` | LowCardinality(String) | User group |
| **`service`** | LowCardinality(String) | Service name (e.g. `"HTTPS"`, `"DNS"`) |
| **`srcintf`** | LowCardinality(String) | Source interface |
| **`dstintf`** | LowCardinality(String) | Destination interface |
| `srcintfrole` | LowCardinality(String) | Source interface role: `lan`, `wan`, `dmz` |
| `dstintfrole` | LowCardinality(String) | Destination interface role |
| **`srccountry`** | LowCardinality(String) | Source country name. Private IPs are `Reserved` (tested); exclude with `!= 'Reserved'` |
| **`dstcountry`** | LowCardinality(String) | Destination country name. Private IPs are `Reserved` (tested) |
| `srccity` / `dstcity` | LowCardinality(String) | Source/destination city |
| `srcgeoid` / `dstgeoid` | Nullable(UInt32) | GeoIP ID |
| `srcname` / `dstname` | LowCardinality(String) | Source/destination hostname/device name |
| `policyid` | Nullable(UInt32) | Firewall policy ID |
| `poluuid` | Nullable(UUID) | Policy UUID — join to `$ADOMTBL_PLHD_POLINFO` on `uuid` |
| `policytype` | LowCardinality(String) | Policy type: `policy`, `local-in`, `DoS` |
| `policymode` | LowCardinality(String) | `flow`, `proxy` |
| `profile` | Nullable(String) | UTM profile name |
| `sessionid` | Nullable(UInt32) | Session ID |
| `fctuid` | Nullable(UUID) | FortiClient UUID |
| `direction` | LowCardinality(String) | Traffic direction: `incoming`, `outgoing` |
| `hostname` | LowCardinality(String) | Destination hostname |
| `url` | Nullable(String) | URL |
| `msg` | Nullable(String) | Human-readable log message |
| `agent` | LowCardinality(String) | HTTP user agent |
| `srczone` / `dstzone` | Nullable(String) | Source/destination zone |
| `srcdomain` | Nullable(String) | Source domain |
| `vsn` | Nullable(String) | Virtual serial number (VDOM) |
| `eventtime` | Nullable(UInt64) | Event timestamp in microseconds |
