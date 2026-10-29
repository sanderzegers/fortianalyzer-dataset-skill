# Cross-device keys

Which columns of different device types hold the same value, and how to compare them. Read this when a question involves two device types or a FAZ UEBA table. Examples: "was this attachment analysed by FortiSandbox?", "who received it?", "which host or user is behind this MAC or FortiClient ID?", "which FortiGate submitted this file?".

Every pair below was checked on two production FAZes. The check compared up to 300 distinct values of one column with the other after the normalisation shown. **Confirmed**: most values matched. **Partial**: a clear link, but only part of the values match, for the reason given. One query covers one device type: query each side and carry the keys across (investigating.md "Correlate across device types").

## Normalise before comparing

Compared with plain `=`, most of these pairs match nothing. Normalise both sides the same way:

| Value | Expression | Why |
|---|---|---|
| Mail address | `arrayJoin(extractAll(lower(ifNull(x, '')), '[a-z0-9._%+=-]+@[a-z0-9.-]+\\.[a-z]+'))` | FortiSandbox `suser` is a comma-separated list, other fields hold `"Name" <a@b>` |
| User name | `replaceRegexpAll(lower(trim(ifNull(x, ''))), '^.*\\\\|@.*$', '')` | `DOMAIN\user`, `user@domain` and `user` are the same user. Skip `''`, `n/a`, `none`, `unknown` |
| MAC address | `replaceRegexpAll(lower(ifNull(x, '')), '[^0-9a-f]', '')` | Separators and case differ per device. Skip `000000000000` |
| Host name | `splitByChar('.', lower(trim(ifNull(x, ''))))[1]` | `pc1` and `pc1.example.com` are the same host. Skip names that are IP addresses |
| Domain | `lower(if(position(x, '://') > 0, domain(x), splitByChar(':', trim(x))[1]))` | `url` holds a full URL on some devices and a host on others |
| Hash, UUID, serial | `lower(trim(toString(x)))` | Case differs; FortiGate `fctuid` is a UUID type |

To compare without returning the values, turn the normalised value into a number: `toUInt64(CRC32(v)) * 4294967296 + CRC32(concat('#', v))`. FAZ rejects every function with "Hash" in its name (`cityHash64`, `xxHash64`, "SQL query is forbidden"); `CRC32` is allowed.

## Keys by identifier

| Identifier | Columns (device type / log type . column) | Match | Notes |
|---|---|---|---|
| File SHA-256 | FortiMail `virus.checksum` ↔ FortiSandbox `malware.sha256` | Confirmed | The SHA-256 is also in FortiMail `msg` (`checksum: ...`) |
| | FortiGate `virus.analyticscksum` ↔ FortiSandbox `malware.sha256` | Confirmed | Only for FortiGates that submit to this FortiSandbox |
| Mail recipient | FortiSandbox `malware.suser` ↔ FortiMail `emailfilter.to`, `history.to` | Confirmed | `suser` is a list: split it (table above). `history` has one row per recipient |
| | FortiNAC `asset.email` ↔ FortiMail `to`, FortiSandbox `suser` | Confirmed | FortiNAC (device type 17) knows the owner's address of an asset |
| | `$ADOM_ENDUSER.email` ↔ FortiMail `to` | Partial | Only users FAZ identified with an address |
| FortiClient endpoint | FortiClient `fct-traffic.uid`, `fct-event.uid` ↔ FortiGate `traffic.fctuid`, `event.fctuid` ↔ `$ADOM_ENDPOINT.fctuid` | Confirmed | `$ADOM_ENDUSER.fctuid` partial. FortiGate `event.uuid` is an object UUID, never a FortiClient ID |
| Endpoint name | FortiGate `webfilter.epname` ↔ `$ADOM_ENDPOINT.epname` | Confirmed | `epname` on log rows is FAZ's name for the endpoint (cols-adom-tables.md) |
| | FortiClient `fct-traffic.hostname`, `fct-event.hostname` ↔ `$ADOM_ENDPOINT.epname`, FortiGate `traffic.srcname` | Confirmed | Short names: normalise |
| | FortiNAC `asset.hostname` ↔ `$ADOM_ENDPOINT.epname`, FortiGate `traffic.srcname` | Confirmed | |
| | FortiGate `traffic.srcname` ↔ `$ADOM_ENDPOINT.epname` | Partial | `srcname` is the name the FortiGate detected, often a device type instead of a host name |
| | FortiGate `traffic.hostname` | — | **Not a client**: the website the client requested (see Domain) |
| User | FortiGate `traffic.user`, `traffic.dstuser`, `traffic.unauthuser`, `event.xauthuser` ↔ `$ADOM_ENDUSER.euname` | Confirmed | Normalise. FAZ strips the domain in `euname` |
| | FortiClient `fct-traffic.user`, `fct-event.user` ↔ FortiGate `traffic.user` **or** `traffic.unauthuser` | Confirmed | Which column the FortiGate fills depends on how it learned the user: check both |
| | FortiClient `user` ↔ `$ADOM_ENDPOINT.ownereuname` | Confirmed | Owner as EMS reports it |
| | FortiAuthenticator `event.user` ↔ FortiGate `event.user` | Partial | Confirmed on one FAZ, few matches on the other: only logins the FortiGate authenticates through FortiAuthenticator. FortiGate `event.user` also holds admins and VPN users |
| MAC address | FortiGate `traffic.srcmac`, `traffic.dstmac` ↔ `$ADOM_ENDPOINT.mac`, `$ADOM_EPEU_DEVMAP.srcmac` | Confirmed | `srcmac` identifies a host only in a subnet attached to the FortiGate |
| | FortiClient `fct-traffic.devicemac` ↔ FortiNAC `asset.mac`, `$ADOM_EPEU_DEVMAP.srcmac` | Confirmed | Only a few match FortiGate `traffic.srcmac`, probably because most FortiClient hosts aren't in a subnet attached to that FortiGate. Link FortiClient to FortiGate by `uid` = `fctuid` instead |
| | FortiGate `event.stamac` (Wi-Fi client), `event.mac` ↔ FortiNAC `asset.mac` | Confirmed | |
| Domain | FortiGate `dns.qname` ↔ `ssl.sni` ↔ `traffic.hostname` | Confirmed | Same device type: one query each, or a join within FortiGate |
| | FortiClient `fct-traffic.url`, `fct-traffic.remotename` ↔ FortiGate `traffic.hostname` | Confirmed | Normalise `url` to the domain |
| | FortiMail `virus.url` ↔ FortiSandbox `malware.url` | Confirmed | URLs from mails that FortiMail submitted |
| Device serial | FortiSandbox `malware.clientdev` ↔ FortiMail `device_id`, FortiGate `devid` | Confirmed | Which device submitted the file |
| | FortiManager `event.serial` ↔ FortiGate `devid` | Confirmed | The managed FortiGate an event is about |
| | FortiClient `emsserial` ↔ `$ADOM_EPEU_DEVMAP.devid` | Confirmed | The EMS serial |

## Overlaps that are not keys

- **`event.user` on FortiManager, FortiWeb, FortiADC, FortiSandbox and FortiMail with each other or with FortiGate**: shared admin names (`admin`, ...), not the same person.
- **FortiMail `from` ↔ recipients** (`to`, `suser`): internal senders are also recipients.
- **FortiWeb/FortiADC `http_host` ↔ FortiGate domains**: the same site, not the same request. Link FortiWeb to FortiGate by client IP and port (investigating.md).

## Device type `fortifirewall`

FAZ offers a device type `fortifirewall` (21) next to `fortigate`. On both FAZes checked it returned the FortiGate logs again: the same serials, MACs and users, with identical counts. Query FortiGates as `fortigate` only. Adding the two counts every FortiGate log twice.
