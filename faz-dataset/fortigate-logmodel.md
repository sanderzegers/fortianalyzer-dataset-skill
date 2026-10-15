# FortiGate Log Model

Where FortiGate events are logged, what one row stands for, and how records link. Column details are in the `cols-*.md` files. Mapped on two FAZ 7.6 instances (a production estate and a lab, FortiOS 7.2–7.6, October 2026). Counts below come from those two; check them on yours before relying on them.

## What one row stands for

| Table | One row per | Notes |
|---|---|---|
| `$log-traffic` | session, **plus interim rows** for long sessions | Count sessions with `bitAnd(logflag,1)>0`, bytes with `bitOr(1,32)` (faz-sql-reference.md) |
| `$log-webfilter`, `$log-app-ctrl`, `$log-attack`, `$log-virus`, `$log-dns`, ... | detection or event within a session | Several rows per session are normal. Link to the session by `sessionid` (below) |
| `$log-event` | event | Identify it by **`logid`** (10 digits, e.g. `0100032001`) or `logdesc`, not by `msg`. `subtype` groups the logids |

Some logids belong to other tables: `0201009233` "File submitted to Sandbox", `0201009238` "File verdict returned from FortiSandbox" (`fsaverdict`: `clean`, `low risk`, `medium risk`, `high risk`) and `0211009234` "File reported infected by FortiSandbox" (`FSA/RISK_HIGH`, `action=blocked`) are in `$log-virus`, `1501054200` "DNS resolution error" in `$log-dns`. The submitted file's SHA-256 is in `analyticscksum`. The first two digits of `logid` give the log type (`01` event, `02` antivirus, `15` DNS), the next two the subtype, and `logid_to_int()` returns the rest.

`wireless` and `switch-controller` events dominate `$log-event` by volume (millions of rows a week in a large estate: FortiSwitch status, Wi-Fi association and 4-way-handshake steps). Filter on `logid` or `subtype` before counting anything else.

## Where is it logged? (`$log-event`)

**This is a selection, not a complete list.** It covers the events behind common questions, and nearly all were seen in real logs; the few marked *not seen* come from Fortinet's reference only. FortiOS documents about 1,430 logids per version, and the list changes between versions (30 logids of 7.2.4 are gone in 7.6.4). To find others:

- **What does my FAZ log?** List a whole subtype by `logid` and `logdesc` and read through it:
  ```sql
  SELECT subtype, logid, logdesc, count(*) AS n
  FROM $log-event
  WHERE $filter AND subtype = 'ha'
  GROUP BY subtype, logid, logdesc
  ORDER BY n DESC
  ```
  Searching `logdesc` by keyword can miss: the HA failover event reads "Virtual cluster member state moved", without the word "failover".
- **Which logid stands for an event that hasn't happened yet?** Grep [fortigate-logids.tsv](fortigate-logids.tsv): every logid documented in FortiOS 7.2.13, 7.4.12, 7.6.7 and 8.0.1, built from Fortinet's Log Message Reference (`scripts/build-fortigate-logids.py`). All 328 logids seen in real logs on both FAZes are in it with the same 10-digit value. For another FortiOS version, rebuild the file or use the [FortiOS Log Message Reference](https://docs.fortinet.com/product/fortigate) online. The reference lists the fields an event *can* carry; real logs show which are filled (`0100032021` lists `user`, but it is always empty).
- Never conclude that a logid doesn't exist because it isn't in your logs.

Always filter on the full `logid`. `logdesc` text can change between FortiOS versions (`0100022222` is "Threat feed loaded" on one FAZ and "External resource loaded" on the other), and some `logdesc` values occur under two logids (see VPN).

### Admin access

| logid | logdesc | Key columns | Notes |
|---|---|---|---|
| `0100032001` | Admin login successful | `user`, `ui`, `srcip` | `ui` is the channel with IP: `https(<ip>)`, `ssh(<ip>)` |
| `0100032002` | Admin login failed | `user`, `ui`, `srcip` | Reason only in `msg`: `... because of invalid password` / `invalid user name` |
| `0100032021` | Admin login disabled | `ui` | Lockout after repeated failures. **No `user` or `srcip`**: the IP is only in `msg` (`Login disabled from IP <ip> for N seconds because of N bad attempts`) |
| `0100032003` | Admin logout successful | `user`, `ui` | |
| `0100032006` / `0100032007` | Super admin entered / left VDOM | `user` | |
| `0100032095` | Admin performed an action from GUI | `user`, `action` (`download`) | |

### Configuration

| logid | logdesc | Key columns | Notes |
|---|---|---|---|
| `0100044547` | Object attribute configured | `user`, `ui`, `action` (`Add`, `Edit`, `Delete`, `Move`, `Rename`), `cfgpath`, `cfgobj`, `cfgattr` | Any change to a table entry, by an admin or by FortiManager. `user` is empty on some changes made by the system itself (about 30 % on the lab FAZ). **Source:** FortiManager installs have `user = '<admin>@FortiManager'` and `ui` `fgfm_tunnel` or `fgfm_fmg(<ip>)`; the HA secondary repeats every change with `ui = 'ha_daemon'` (on both FAZes the largest share of rows), so count on the primary or exclude `ha_daemon` |
| `0100044546` | Attribute configured | as above | Changes to global settings (`system.settings`, `system.sdwan`, ...) |
| `0100032102` | Configuration changed | `user`, `ui` | One summary row per admin session that changed something |
| `0100036882` | Configuration manually saved | | |
| `0100032142` / `0100032143` | System configuration backed up / backed up by SCP | | |

`cfgtid > 0` also selects config-change rows (cols-elog.md).

### Remote access VPN

| logid | logdesc | Key columns | Notes |
|---|---|---|---|
| `0101039424` / `0101039425` | SSL VPN tunnel up / down | `user`, `remip`, `tunnelid`, `tunneltype='ssl-web'` | The portal session. **Logged for every SSL VPN login**, also tunnel-mode ones |
| `0101039947` / `0101039948` | SSL VPN tunnel up / down | `user`, `remip`, `tunnelid`, `tunneltype='ssl-tunnel'` | Tunnel mode. Same `tunnelid` as the `ssl-web` row of the same login. Bytes and `duration` only on `0101039948` |
| `0101039426` | SSL VPN login fail | `user`, `remip`, `reason` | Far more failures than logins (58,494 vs 3,703 in a week on one FAZ) points to password guessing from the internet |
| `0101039943` | SSL VPN new connection | `remip` | Connection before authentication, no `user` |
| `0101039946` / `0101039944` / `0101039949` | SSL VPN exit error / alert / statistics | | |
| `0101037138` | IPsec connection status changed | `action` (`tunnel-up`, `tunnel-down`), `user` / `xauthuser`, `remip`, `tunnelid`, `vpntunnel` | Site-to-site and dial-up tunnels. `duration` and bytes on `tunnel-down` |
| `0101037139` | IPsec phase 2 status changed | `action` (`phase2-up`, `phase2-down`) | |
| `0101037127` / `0101037128` / `0101037124` | Progress IPsec phase 1 success / failure, phase 1 error | `remip` | High volume. Failures from unknown `remip`s are typically scans |
| `0101037136` | IPsec DPD failed | | Peer stopped answering |
| `0101037141` | IPsec tunnel statistics | | Periodic, not an event |

**Count each SSL VPN login once.** Every tunnel-mode login writes both an `ssl-web` and an `ssl-tunnel` row with the same `tunnelid` (3,689 of 3,689 on one FAZ). Count logins with `0101039424`, tunnel-mode logins with `0101039947`, and traffic with `0101039948`. Where SSL VPN isn't in use (the lab FAZ), remote access shows only as IPsec.

**IPsec user.** On dial-up tunnels the login name is in `xauthuser` (XAuth) or `user`. On site-to-site tunnels `user` can hold the peer ID instead of a person. Separate them by `vpntunnel` (the phase 1 name).

### User authentication

| logid | logdesc | Key columns | Notes |
|---|---|---|---|
| `0102043039` / `0102043040` | Authentication logon / logout | `user`, `srcip`, `action` (`auth-logon`, `auth-logout`) | An entry added to or removed from the firewall's authenticated-user list (`msg`: `User <name> added to auth logon`). `method` stays empty. On one FAZ all entries were machine accounts (`host/<computer>`) |
| `0102043056` | Auth server reachability update | | |

Wi-Fi 802.1X results are under `wireless`: `0104043630` RADIUS authentication success, `0104043629` failure.

### HA

| logid | logdesc | Notes |
|---|---|---|
| `0108037892` | Virtual cluster member state moved | **Failover**. `ha_role` is filled |
| `0108037911` | Device set as HA master information | |
| `0108037901` / `0108037902` | Heartbeat device interface down / up | |
| `0108037897` / `0108037898` | HA device interface ready / failed | |
| `0108037903` | Synchronization status with primary | Periodic |
| `0108035011` / `0108035012` | HA secondary synchronization failed / Secondary sync failed | *Not seen*; from the reference |
| `0108035013` / `0108035016` | HA failover failed / HA failover success | *Not seen*; from the reference. The failovers on both FAZes were logged as `0108037892` |
| `0108035001`–`0108035004` | HA secondary synchronized (Virus, Extended, FLDB) database | After signature updates |

### SD-WAN, interfaces, routing

| logid | logdesc | Key columns | Notes |
|---|---|---|---|
| `0113022933` | SDWAN SLA notification | `interface`, `healthcheck`, `status` (`up`, `down`) | SLA state change. The failed metric is only in `msg` (`... threshold[packetloss]`) |
| `0113022925` | SDWAN SLA information | `interface`, `healthcheck`, `latency`, `jitter`, `packetloss` | Periodic measurements |
| `0113022923` / `0113022934` | SDWAN status / status information | | |
| `0113022930` / `0113022931` | SDWAN status warning / SLA information warning | | |
| `0113022936` / `0113022938` | SD-WAN internet service passive quality information / bandwidth monitoring result | | *Not seen*; from the reference |
| `0100020099` | Interface status changed | `status` (`UP`, `DOWN`) | **Interface name only in `msg`** (`Link monitor: Interface <name> was turned down`) |
| `0103020300` / `0103020302` | BGP / OSPF neighbor status changed | | |
| `0100022921` | Routing information changed | `status` (`up`, `down`) | |

### System

| logid | logdesc |
|---|---|
| `0100032009` | FortiGate started |
| `0100032200` | Device shutdown (`msg`: unexpected power off) |
| `0100032546` | Application crashed |
| `0100022106` | Optional power supply not detected |
| `0100022105` / `0100022107` / `0100022108` / `0100022109` | Power supply failed / voltage anomaly / fan anomaly / temperature too high (*not seen*; from the reference) |
| `0100041000` / `0100041001` | FortiGate update succeeded / failed (FortiGuard) |
| `0100022901` / `0100022902` / `0100022903` | FortiAnalyzer connection up / down / failed |
| `0100053400` / `0100053401` | Central Management connectivity active / inactive |
| `0100022207` | Certificate will expire soon |
| `0100026001` / `0100026002` / `0100026003` | DHCP ack / release / statistics |

## Linking records

| From | To | Key | Notes |
|---|---|---|---|
| security logs (`webfilter`, `app-ctrl`, `attack`, ...) | `traffic` | `devid` + `vd` + `sessionid` | 81–96 % of rows found their session within the same hour. Long or open sessions have no closing traffic row yet, and policies without traffic logging have none at all, so widen the traffic window and expect gaps |
| SSL VPN `ssl-web` row | `ssl-tunnel` row | `devid` + `tunnelid` | Same login (see above) |
| VPN tunnel up | tunnel down | `devid` + `tunnelid` | Duration and bytes are on the down row |
| sandbox submission `0201009233` (`$log-virus`) | sandbox verdict `0201009238` / `0211009234` (`$log-virus`) | `devid` + `lower(analyticscksum)` (SHA-256) | 119 of 119 and 8 of 8 submissions had a verdict, on average 3–4 minutes later. Works whatever sandbox the FortiGate uses (on-premises or cloud), and in a single query |
| sandbox submission | FortiSandbox `$log-malware` | `lower(analyticscksum)` ↔ `lower(sha256)` | Two queries (one per device type). 100 % for a FortiGate submitting to a FortiSandbox that logs to the same FAZ; 0 % for one submitting elsewhere (cloud). FortiSandbox adds `mcate`, `ftype`, VM run |
| FortiGate session | FortiWeb behind it (VIP) | client `srcip` + `srcport` ↔ FortiWeb `src` + `src_port`, FortiWeb time within the session (`dtime - duration` … `dtime`) | Two queries. 99.5 % and 92.3 % of FortiWeb attack rows found their FortiGate session. Needs the client IP passed through to FortiWeb (no source NAT) |
| config change by FortiManager (`0100044547`, `user` `...@FortiManager`) | FortiManager install `0012021015` (device type FortiManager) | `lower(devname)` = `lower(device)`, user without `@FortiManager`, install row 7–79 s after (compare `itime`) | Two queries. 167 of 180 rows on one deployment; fortimanager-fortianalyzer.md |
| any log | user identity | `coalesce(nullifna(user), nullifna(unauthuser), ipstr(srcip))` | faz-sql-reference.md |

## Patterns

```sql
-- Remote-access logins per user: SSL VPN logins, failures, IPsec tunnels
SELECT coalesce(nullifna(xauthuser), nullifna(`user`)) AS vpn_user,
       countIf(logid = '0101039424') AS ssl_logins,
       countIf(logid = '0101039426') AS ssl_failed,
       countIf(logid = '0101037138' AND action = 'tunnel-up') AS ipsec_tunnels_up
FROM $log-event
WHERE $filter AND logid IN ('0101039424', '0101039426', '0101037138')
GROUP BY vpn_user
HAVING vpn_user IS NOT NULL
ORDER BY ssl_failed DESC

-- Admin logins per account, with failures and source addresses
SELECT `user` AS admin_user,
       countIf(logid = '0100032001') AS logins,
       countIf(logid = '0100032002') AS failed,
       uniqExact(ipstr(srcip)) AS source_ips
FROM $log-event
WHERE $filter AND logid IN ('0100032001', '0100032002')
GROUP BY admin_user
ORDER BY failed DESC

-- Admin lockouts per source IP (the IP is only in msg)
SELECT extract(msg, 'from IP (\\S+) for') AS source_ip, count(*) AS lockouts
FROM $log-event
WHERE $filter AND logid = '0100032021'
GROUP BY source_ip
ORDER BY lockouts DESC

-- Configuration changes per admin and object type
SELECT devname, `user` AS admin_user, cfgpath, action, count(*) AS changes
FROM $log-event
WHERE $filter AND logid IN ('0100044547', '0100044546')
GROUP BY devname, admin_user, cfgpath, action
ORDER BY changes DESC

-- SD-WAN SLA state changes over time per member and health check
SELECT $flex_timestamp AS timestamp, devname, `interface`, healthcheck,
       countIf(status = 'down') AS sla_down, countIf(status = 'up') AS sla_up
FROM $log-event
WHERE $filter AND logid = '0113022933'
GROUP BY timestamp, devname, `interface`, healthcheck
ORDER BY timestamp

-- HA failovers and heartbeat problems per device
SELECT devname, logdesc, count(*) AS events
FROM $log-event
WHERE $filter AND logid IN ('0108037892', '0108037911', '0108037901', '0108037898')
GROUP BY devname, logdesc
ORDER BY events DESC

-- Sandbox verdict per submitted file (submission and verdict are both in $log-virus)
SELECT s.devname, s.sha, s.filename, v.verdict, v.action, v.t - s.t AS seconds_to_verdict
FROM (SELECT devid, devname, lower(analyticscksum) AS sha, any(filename) AS filename, min(dtime) AS t
      FROM $log-virus
      WHERE $filter AND logid = '0201009233' AND length(ifNull(analyticscksum, '')) = 64
      GROUP BY devid, devname, sha) s
LEFT JOIN (SELECT devid, lower(analyticscksum) AS sha, any(ifNull(fsaverdict, '')) AS verdict,
                  any(action) AS action, min(dtime) AS t
           FROM $log-virus
           WHERE $filter AND logid IN ('0201009238', '0211009234') AND length(ifNull(analyticscksum, '')) = 64
           GROUP BY devid, sha) v ON s.devid = v.devid AND s.sha = v.sha
ORDER BY v.verdict DESC
```
