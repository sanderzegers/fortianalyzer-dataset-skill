# `$log-protocol` — Protocol Log

| Column | Type | Description |
|---|---|---|
| **`subtype`** | LowCardinality(String) | Protocol sub-type (e.g. `icmp`, `gre`, `esp`) |
| **`eventtype`** | LowCardinality(String) | Protocol event category |
| **`srcip`** | Nullable(IPv6) | Source IP — always use `ipstr()` for display |
| **`dstip`** | Nullable(IPv6) | Destination IP — always use `ipstr()` for display |
| **`action`** | LowCardinality(String) | Action taken — see common action values |
| **`proto`** | Nullable(UInt8) | IP protocol number: 1=ICMP, 6=TCP, 17=UDP, 47=GRE, 50=ESP, 51=AH, 89=OSPF |
| **`srcport`** | Nullable(UInt16) | Source port |
| **`dstport`** | Nullable(UInt16) | Destination port |
| `vd` | LowCardinality(String) | VDOM name |
| `service` | Nullable(String) | Service name |
| `policyid` | Nullable(UInt32) | Firewall policy ID |
| `profile` | Nullable(String) | Protocol inspection profile name |
| `url` | Nullable(String) | URL (if applicable) |
| `srcintf` | LowCardinality(String) | Source interface |
| `srcintfrole` | LowCardinality(String) | Source interface role: `lan`, `wan`, `dmz` |
| `dstintf` | LowCardinality(String) | Destination interface |
| `dstintfrole` | LowCardinality(String) | Destination interface role |
| `sessionid` | Nullable(UInt32) | Session ID |
| `vrf` | Nullable(UInt32) | VRF ID |
| `srcuuid` | Nullable(UUID) | Source address object UUID |
| `dstuuid` | Nullable(UUID) | Destination address object UUID |
| `infection` | Nullable(String) | Infection/virus name if detected |
| `virusid` | Nullable(String) | Virus identifier |
| `policymode` | LowCardinality(String) | Policy mode: `flow`, `proxy` |
| `ppid` | Nullable(UInt32) | Parent policy ID |
| `policytype` | LowCardinality(String) | Policy type: `policy`, `local-in-policy` |
| `srccountry` | LowCardinality(String) | Source country name |
| `dstcountry` | LowCardinality(String) | Destination country name |
| `violations` | Nullable(String) | Protocol violations |
| `reason` | Nullable(String) | Disposition reason |
| `vsn` | Nullable(String) | Virtual serial number (VDOM) |
| `srcname` | LowCardinality(String) | Source hostname / device name |
| `srcmac` | LowCardinality(String) | Source MAC address |
| `transid` | Nullable(UInt32) | Transaction ID |
| `srccity` | LowCardinality(String) | Source city |
| `dstcity` | LowCardinality(String) | Destination city |
| `srcgeoid` | Nullable(UInt32) | Source GeoIP ID |
| `dstgeoid` | Nullable(UInt32) | Destination GeoIP ID |
| `poluuid` | Nullable(UUID) | Policy UUID — join to `$ADOMTBL_PLHD_POLINFO` on `uuid` |
| `slot` | Nullable(UInt32) | Hardware slot |
| `srczone` | Nullable(String) | Source zone |
| `dstzone` | Nullable(String) | Destination zone |
| `profilegroup` | Nullable(String) | Profile group name |
| `eventtime` | Nullable(UInt64) | Event timestamp in microseconds |
| `tz` | LowCardinality(String) | Timezone |
| `custom_field1` | Nullable(String) | Custom field 1 |
| `msg` | Nullable(String) | Human-readable log message |

## Zero Data in Last Hour

No protocol log rows were found in the last hour. All fields are documented from the FortiAnalyzer schema only. No real enum values are available — expected values will emerge when protocol logging becomes active.
