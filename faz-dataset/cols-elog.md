# `$log-event` — System/Device Events

Event logs cover many subtypes with ~200 columns. All common columns apply (see cols-common.md).

## Universal Event Columns

| Column | Type | Description |
|---|---|---|
| **`subtype`** | String | `system`, `router`, `vpn`, `user`, `endpoint`, `ha`, `compliance`, `connector`, `wad`, `wanopt`, `wireless`, `netscan`, `security-rating` |
| **`logid`** | String | Specific event ID — use `logid_to_int(logid)` for numeric compare |
| **`logdesc`** | LowCardinality(String) | Log description |
| **`msg`** | Nullable(String) | Human-readable event message |
| **`user`** | LowCardinality(String) | User who triggered event |
| **`ui`** | Nullable(String) | UI method: `ssh`, `https`, `console`, `jsconsole` |
| **`action`** | LowCardinality(String) | `login`, `logout`, `set`, `add`, `delete`, `edit`, `clear`, `tunnel-up`, `tunnel-down`, `tunnel-stats`, `perf-stats`, `ssl-login-fail`, `ipsec-login-fail`, `assoc-req`, `reassoc-req` |
| `status` | Nullable(String) | Event status: `success`, `failed` / `failure` (both occur — match with `status IN ('failed','failure')`), `down`, `DOWN`, `end`, `closed`, `traffic-count` |
| `result` | LowCardinality(String) | Operation result |
| `reason` | LowCardinality(String) | Reason for event |
| `error` | Nullable(String) | Error message |

## Config Change (logid 44547, or `cfgtid > 0`)

| Column | Type | Description |
|---|---|---|
| **`cfgtid`** | Nullable(UInt32) | Config transaction ID — `cfgtid > 0` filters config change events |
| `cfgpath` | Nullable(String) | Config object path (e.g. `firewall policy`) |
| `cfgobj` | Nullable(String) | Config object name |
| `cfgattr` | Nullable(String) | Attribute changed |
| `cfgcomment` | Nullable(String) | Change comment |
| `old_value` / `new_value` | Nullable(String) | Before/after values |

```sql
-- All config changes
SELECT from_dtime(dtime) AS ts, `user`, ui, cfgpath, cfgobj, cfgattr, old_value, new_value
FROM $log-event
WHERE $filter AND cfgtid > 0
ORDER BY dtime DESC
```

## Authentication Events

| Column | Type | Description |
|---|---|---|
| **`user`** | LowCardinality(String) | Username |
| **`srcip`** | Nullable(IPv6) | Client IP |
| `method` | LowCardinality(String) | Auth method |
| `authserver` | Nullable(String) | Auth server |
| `adgroup` | Nullable(String) | AD group |
| `reason` | LowCardinality(String) | Failure reason |

## VPN Events

| Column | Type | Description |
|---|---|---|
| **`vpntunnel`** | LowCardinality(String) | VPN tunnel name |
| `tunneltype` | Nullable(String) | `ipsec`, `ssl`, `ssl-tunnel`, `ssl-web`, `pptp` |
| `tunnelid` | Nullable(UInt32) | Tunnel ID |
| `remip` | Nullable(IPv6) | Remote IP |
| `locip` | Nullable(IPv6) | Local IP |
| `tunnelip` | Nullable(IPv6) | Tunnel IP (assigned) |
| `assignip` | Nullable(IPv6) | Assigned IP |
| `sentbyte` / `rcvdbyte` | — | Tunnel bytes |
| `duration` | Nullable(UInt32) | Session duration |
| `init` | Nullable(String) | IKE initiator |
| `mode` / `exch` | Nullable(String) | IKE mode / exchange type |

## System Health

| Column | Type | Description |
|---|---|---|
| `cpu` | Nullable(UInt8) | CPU usage % |
| `mem` | Nullable(UInt8) | Memory usage % |
| `disk` | Nullable(UInt8) | Disk usage % |
| `totalsession` | Nullable(UInt32) | Total active sessions |
| `setuprate` | Nullable(UInt64) | Session setup rate |

## WiFi Events

| Column | Type | Description |
|---|---|---|
| `ap` | Nullable(String) | Access point name |
| `ssid` | Nullable(String) | SSID |
| `bssid` | Nullable(String) | BSSID |
| `mac` | Nullable(String) | Client MAC address |
| `stamac` | Nullable(String) | Station MAC |
| `channel` | Nullable(UInt8) | Radio channel |
| `rssi` / `signal` / `noise` | Nullable | RSSI / signal / noise |
| `radioband` | Nullable(String) | `2.4GHz`, `5GHz` |
| `security` | Nullable(String) | Security mode |
| `vap` | Nullable(String) | Virtual AP |

## SD-WAN Health Events

| Column | Type | Description |
|---|---|---|
| `healthcheck` | Nullable(String) | Health check name |
| `slamap` | Nullable(String) | SLA map |
| `latency` / `jitter` / `packetloss` | Nullable(String) | Performance metrics |
| `inbandwidthavailable` / `outbandwidthavailable` | Nullable(String) | Bandwidth available |
| `serviceid` / `slatargetid` | Nullable(UInt32) | SD-WAN service / SLA target ID |

## HA Events

| Column | Type | Description |
|---|---|---|
| `ha_role` | Nullable(String) | `master`, `slave` |
| `ha_group` | Nullable(Int16) | HA group |
| `vcluster` | Nullable(UInt32) | Virtual cluster ID |

## DHCP Events (logid 26001)

| Column | Type | Description |
|---|---|---|
| `mac` | Nullable(String) | Client MAC address |
| `interface` | Nullable(String) | Interface name |
| `devid` | String | Device ID |

```sql
-- DHCP MAC tracking pattern
concat(interface, '.', devid) AS devintf   -- unique interface key
WHERE logid_to_int(logid) = 26001
```

## logid Reference

`logid` is a 10-digit string such as `0100032001`: two digits log type (`01` event, `02` antivirus, `15` DNS), two digits subtype, then the message ID. `logid_to_int(logid)` returns the message ID (`32001`), so `logid = '32001'` matches nothing; prefer the full string. This is a **selection**, not a complete list: the meanings follow the FortiOS 7.6.4 Log Message Reference, with notes from real logs added, and the last column says whether the logid occurred in real logs on two FAZ 7.6 instances. For the complete list of your version, see the FortiOS Log Message Reference ("Log ID numbers"); for what your FAZ logs, group `$log-event` by `logid, logdesc`. The full map by topic is in [fortigate-logmodel.md](fortigate-logmodel.md).

| logid | Short | Category | Meaning | Seen in logs |
|---|---|---|---|---|
| `0100032001` / `0100032002` / `0100032003` | `32001` / `32002` / `32003` | Admin | Admin login successful / failed / logout | yes |
| `0100032021` | `32021` | Admin | Admin login disabled after failed attempts (source IP only in `msg`) | yes |
| `0100044547` / `0100044546` | `44547` / `44546` | Config | Object attribute / attribute configured: any config change, by an admin or FortiManager | yes |
| `0100026001` / `0100026002` / `0100026003` | `26001` / `26002` / `26003` | DHCP | DHCP ack / release / statistics | yes |
| `0100020099` | `20099` | Interface | Interface status changed (interface name only in `msg`) | yes |
| `0100022105` / `0100022107` / `0100022108` / `0100022109` | `22105` / `22107` / `22108` / `22109` | Hardware | Power supply failed / voltage anomaly / fan anomaly / temperature too high | no |
| `0100022106` | `22106` | Hardware | Optional power supply not detected | yes |
| `0108037892` | `37892` | HA | Virtual cluster member state moved (failover) | yes |
| `0108035011` / `0108035012` / `0108035013` | `35011` / `35012` / `35013` | HA | HA secondary synchronization failed / secondary sync failed / HA failover failed | no |
| `0113022933` / `0113022925` | `22933` / `22925` | SD-WAN | SLA notification (state change) / SLA information (measurements) | yes |
| `0113022936` / `0113022938` | `22936` / `22938` | SD-WAN | Internet service passive quality information / bandwidth monitoring result | no |
| `0101039424` / `0101039947` | `39424` / `39947` | VPN | SSL VPN tunnel up, `ssl-web` / `ssl-tunnel` (one tunnel-mode login writes both) | yes |
| `0101037138` | `37138` | VPN | IPsec connection status changed (tunnel up/down) | yes |
| `0104043551` | `43551` | WiFi | Physical AP join | yes |
| `0104043630` / `0104043629` | `43630` / `43629` | WiFi | Client RADIUS authentication success / failure | yes |
| `0201009233` | `9233` | Antivirus log | File submitted to Sandbox (`$log-virus`, not event) | yes |
| `1501054200` | `54200` | DNS log | DNS resolution error (`$log-dns`, not event) | yes |

## Real Values Discovered from FAZ Instance

### `level` (Severity)

Observed values from FAZ event logs:

| Value | Notes |
|---|---|
| `information` | Most common |
| `notice` | Routine events |
| `warning` | Warnings |
| `error` | Errors |
| `critical` | Critical events |
| `alert` | Alerts |

### `subtype` (Event Subtype)

Observed from FAZ event logs:

| Value | Notes |
|---|---|
| `system` | System events |
| `router` | Routing events |
| `vpn` | VPN events |
| `user` | User events |
| `endpoint` | Endpoint events |
| `ha` | HA events |
| `compliance` | Compliance events |
| `connector` | Connector events |
| `wad` | Web/app descriptor |
| `wanopt` | WAN optimization |
| `wireless` | Wireless events |
| `netscan` | Network scan |
| `security-rating` | Security rating |

### `eventtype` (Event Type)

Observed from FAZ event logs:

| Value | Notes |
|---|---|
| `AD` | Active Directory |
| `AntiVirus` / `AV` | Antivirus |
| `Config` | Config events |
| `DHCP` | DHCP |
| `DNS` | DNS |
| `Device` | Device |
| `Event` | Generic |
| `FIPS` | FIPS events |
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

### `logdesc` (Log Description)

Observed log descriptions from FAZ event logs:

| Value | Notes |
|---|---|
| `SDWAN SLA information` | SLA health check status — very frequent |
| `EMS WebSocket notification` | FortiManager EMS notifications |
| `Negotiate IPsec phase 1` | VPN tunnel negotiation |
| `IPsec phase 1 error` | VPN tunnel failure |
| `DHCP server sent DHCP ACK` | DHCP lease assignment |
| `DHCP Ack log` | DHCP acknowledgment |
| `Wireless station sent DHCP REQUEST` | DHCP request |
| `Wireless client IP assigned` | Client got IP |
| `Wireless client authenticated` | 802.1X/auth success |
| `Wireless client deauthenticated` | Client disconnected |
| `Wireless client sent 2/4 message of 4 way handshake` | WPA2 handshake |
| `Wireless client sent 4/4 message of 4 way handshake` | WPA2 handshake complete |
| `AP sent 1/4 message of 4 way handshake to wireless client` | WPA2 handshake step 1 |
| `AP sent 3/4 message of 4 way handshake to wireless client` | WPA2 handshake step 3 |
| `Authentication request from wireless station` | Auth request |
| `Authentication response to wireless station` | Auth response |
| `Reassociation request from wireless station` | Roaming |
| `Reassociation response to wireless station` | Roaming response |
| `AP sent deauthentication frame to wireless client` | Client kicked |
| `Rogue AP off air` | Rogue AP detected offline |
| `Rogue AP change detected` | Rogue AP status change |
| `FortiSandbox AV database updated` | AV DB update |
| `Scanunit reloaded AV Database` | AV DB reload |
| `SSL connection failed` | TLS/SSL error |
| `System performance statistics` | CPU/memory stats |
| `Wireless station DNS process failed due to non-existing domain` | DNS failure |

### `reason` (Reason)

Observed reasons from FAZ event logs:

| Value | Notes |
|---|---|
| `ike negotiation timeout` | IPsec tunnel failed to negotiate |
| `different CRL scope` | Certificate revocation list mismatch |
| `Reserved 0` | WiFi event reason field |
| `N/A` | Not applicable |


### `vpntunnel` (VPN Tunnel)

Custom VPN tunnel names observed:

| Value | Notes |
|---|---|
| `EDGE-ISP1-{NUM}` | Edge ISP1 tunnel |
| `SITE-ISP1-{NUM}` | Site ISP1 tunnel |

> **Custom name pattern:** Tunnels follow `{SITE}-{ISP}-{NUM}` — match with `vpntunnel LIKE '%ISP1%'`.

### `ap` (Access Point)

Custom AP names observed:


| Value | Notes |
|---|---|
| `B{N}F{N}AP{NUM}` | AP in building B{N}, floor F{N} |
| `B{N}F{N}AP{NUM}` | AP in building B{N}, floor F{N} |
| `B{N}F{N}AP{NUM}` | AP in building B{N}, floor F{N} |

> **Custom name pattern:** APs follow `{BUILDING}{FLOOR}AP{NUM}` — match with `ap LIKE '%AP%'`.

### `ssid` (SSID)

Custom SSIDs observed:

| Value | Notes |
|---|---|
| `{CORP} Mobility` | Corporate mobile network |
| `IOT-Devices` | IoT devices |
| `GUEST-Network` | Guest network |
| `RoomCast-{NUM}` | Conference room AP |
| `RoomCast-{NUM}` | Conference room AP |

### `healthcheck` (SD-WAN health check name)

| Value | Notes |
|---|---|
| `Ping Google` | ICMP ping to Google DNS |
| `HUB` | HUB-based health check |

### `slamap` (SLA Map)

| Value | Notes |
|---|---|
| `0x1` | SLA map value |

### `latency` (Latency)

| Value | Notes |
|---|---|
| `{FLOAT}` | Latency in milliseconds |

### `jitter` (Jitter)

| Value | Notes |
|---|---|
| `{FLOAT}` | Jitter in milliseconds |

### `packetloss` (Packet Loss)

| Value | Notes |
|---|---|
| `{FLOAT}` | Packet loss percentage |

### `inbandwidthavailable` (Inbound Bandwidth)

| Value | Notes |
|---|---|
| `{VALUE}Gbps` | Available inbound bandwidth |
| `{VALUE}Mbps` | Available inbound bandwidth |

### `outbandwidthavailable` (Outbound Bandwidth)

| Value | Notes |
|---|---|
| `{VALUE}Gbps` | Available outbound bandwidth |
| `{VALUE}Mbps` | Available outbound bandwidth |

### `ha_role` (HA Role)

| Value | Notes |
|---|---|
| `N/A` | No HA |
| `primary` | Primary HA node |
| `secondary` | Secondary HA node |

### `ha_group` (HA Group)

| Value | Notes |
|---|---|
| `N/A` | No HA |
| `{GROUP-NAME}` | HA group name |

### `vcluster` (Virtual Cluster)

| Value | Notes |
|---|---|
| `N/A` | No cluster |
| `{CLUSTER-NAME}` | Cluster name |

### `devid` (Device ID)

| Value | Notes |
|---|---|
| `FGT{SERIAL}` | FortiGate serial number |

### `interface` (Interface)

| Value | Notes |
|---|---|
| `wan1` / `wan2` | WAN interfaces |
| `{SITE}_ISP1_{N}` / `{SITE}_ISP1_{N}_{N}` | ISP1 tunnel interfaces (IPsec dial-up instances get a `_{N}` suffix) |
| `{SITE}_ISP2_{N}` | ISP2 tunnel interface |
| `{ISPNAME}_root` | ISP interfaces (VDOM-link / zone names) |
| `lan1` / `lan2` / `lan3` / `lan4` | LAN interfaces |

### `cpu` / `mem` / `disk` (System Resources)

| Value | Notes |
|---|---|
| `{PERCENT}` | CPU/memory/disk usage percentage |
| `0` | Not used in this log entry |

### `totalsession` (Total Sessions)

| Value | Notes |
|---|---|
| `{NUM}` | Current total sessions |

### `setuprate` (Setup Rate)

| Value | Notes |
|---|---|
| `{NUM}` | New sessions per second |

### `bssid` (BSSID)

| Value | Notes |
|---|---|
| `XX:XX:XX:XX:XX:XX` | WiFi BSSID |

### `channel` (WiFi Channel)

| Value | Notes |
|---|---|
| `{NUM}` | WiFi channel number |

### `stamac` (Station MAC)

| Value | Notes |
|---|---|
| `N/A` | No station MAC |

### `devid` (Device ID)

Observed device IDs from FAZ event logs:

| Value | Notes |
|---|---|
| `FGT70G{SERIAL}` | FortiGate 70G serial (prefix = model, then a unique number) |
| `FG120G{SERIAL}` | FortiGate 120G serial |

> **Pattern:** `FG{MODEL}{YEAR}{SERIAL}` — match with `devid LIKE '%GTK%'`.

### `interface` (Interface)

Observed interface names from FAZ event logs:

| Value | Notes |
|---|---|
| `Guests` | Guest WiFi SSID/interface |
| `VLAN{NUM}` | VLAN-tagged interface |

> **Pattern:** WiFi interfaces often match SSID names; VLAN interfaces use `VLAN{NUM}` format.

### `channel` (WiFi Channel)

Observed channels from FAZ event logs:

| Value | Notes |
|---|---|
| `1` | 2.4 GHz channel 1 |
| `52` | 5 GHz channel 52 |

> **Pattern:** Channels vary by band — `1`, `6`, `11` for 2.4 GHz; `36`–`165` for 5 GHz.

### `stamac` (Station MAC)

Observed station MACs from FAZ event logs:

| Pattern | Notes |
|---|---|
| `XX:XX:XX:XX:XX:XX` | Station MAC address |

### `bssid` (BSSID)

Observed BSSIDs from FAZ event logs:

| Pattern | Notes |
|---|---|
| `XX:XX:XX:XX:XX:XX` | Access point MAC |

### `status` (Event Status)

Observed status values from FAZ event logs:

| Value | Notes |
|---|---|
| `success` | Successful event |
| `failure` | Failed event |
| `negotiate_error` | VPN negotiation error |
| `clash` | IP/MAC conflict |

### `result` (Operation Result)

Observed result values from FAZ event logs:

| Value | Notes |
|---|---|
| `DONE` | Operation completed |
| `OK` | Operation successful |
| `XAUTH authentication successful` | XAuth success |

### `ui` (UI Method)

Observed UI methods from FAZ event logs:

| Value | Notes |
|---|---|
| `ssh` | SSH interface |
| `https` | Web UI |
| `console` | Console |
| `jsconsole` | JavaScript console |
| `ssl-vpn` | SSL VPN |

### `healthcheck` (SD-WAN health check name)

Observed health check names from FAZ event logs:

| Value | Notes |
|---|---|
| `Ping 8.8.8.8` | Google DNS ping |
| `Ping 8.8.4.4` | Google DNS ping |
| `Ping 1.1.1.1` | Cloudflare DNS ping |

### `ha_role` (HA Role)

Observed HA roles from FAZ event logs:

| Value | Notes |
|---|---|
| `primary` | Primary node |
| `secondary` | Secondary node |
