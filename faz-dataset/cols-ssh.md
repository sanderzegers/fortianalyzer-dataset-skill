# `$log-ssh` — SSH Inspection Log

SSH logs are FortiGate UTM logs (`type=utm`, `subtype=ssh`, log category 16) written by SSH deep inspection in an SSL/SSH inspection profile. The FortiOS 7.6 Log Message Reference lists four event types: `ssh-command` (61000 SSH_COMMAND_BLOCK, 61001 SSH_COMMAND_BLOCK_ALERT, 61002 SSH_COMMAND_PASS, 61003 SSH_COMMAND_PASS_ALERT), `ssh-channel` (61010 SSH_CHANNEL_BLOCK, 61011 SSH_CHANNEL_PASS), `ssh-hostkey` (61012 SSH_HOST_KEY_WARNING, 61013 SSH_HOST_KEY_NOTIF) and `ssh-unsupport-proto` (61014/61015 SSH_UNSUPPORT_PROTO_BLOCK/PASS). Full logid example: `1600061002`. These are proxied SSH sessions through the firewall, not admin logins to the FortiGate (those are in `$log-event`). All common columns apply (see cols-common.md).

> Names like `sshaction`, `sshversion`, `sshauthmethod`, `sshauthstatus` and `sshserver` **don't exist** and fail with "Missing columns". There is no authentication-result field in SSH logs.

## Columns

| Column | Type | Description |
|---|---|---|
| **`eventtype`** | — | `ssh-command`, `ssh-channel`, `ssh-hostkey`, `ssh-unsupport-proto` |
| **`action`** | — | Channel status: `passthrough` or `blocked` (per log reference) |
| **`channeltype`** | — | Channel type: `x11`, `shell`, `exec`, `tcp-forward`, `tun-forward`, `sftp`, `scp` (per log reference) |
| **`command`** | — | Shell command (ssh-command events) |
| **`login`** | — | SSH login name |
| `severity` | — | Severity of the shell command |
| `hostkeystatus` | — | Host-key status (ssh-hostkey events) |
| `profile` / `profilegroup` | — | SSH inspection profile / profile group |
| **`user`** / `group` | — | Authenticated firewall user / group |
| `unauthuser` / `unauthusersource` | — | Unauthenticated user name / its source |
| `dstuser` | — | Destination user |
| `fctuid` | — | FortiClient UID |
| **`srcip`** / `srcport` / **`dstip`** / **`dstport`** | — | Session endpoints |
| `proto` / `direction` / `sessionid` | — | Protocol number / session direction / session ID |
| `srcintf` / `srcintfrole` / `dstintf` / `dstintfrole` | — | Interfaces and their roles |
| `srczone` / `dstzone` | — | Zones |
| `srccountry` / `dstcountry` / `srcdomain` | — | GeoIP country / source domain |
| `srcuuid` / `dstuuid` | — | Address object UUIDs |
| **`policyid`** / `poluuid` / `policytype` | — | Firewall policy ID / UUID / type |
| `eventtime` / `tz` | — | Device event time / time zone |
| `logid` / `type` / `subtype` / `level` | — | Log identification |

## Key Patterns

```sql
-- Blocked SSH commands/channels by user and command
SELECT coalesce(nullifna(`user`), nullifna(login), ipstr(srcip)) AS who,
       eventtype, channeltype, command, count(*) AS hits
FROM $log-ssh
WHERE $filter AND action = 'blocked'
GROUP BY who, eventtype, channeltype, command
ORDER BY hits DESC
LIMIT 50

-- SSH channel types per destination
SELECT ipstr(dstip) AS server, channeltype, count(*) AS cnt
FROM $log-ssh
WHERE $filter AND eventtype = 'ssh-channel'
GROUP BY server, channeltype
ORDER BY cnt DESC
```

Schema verified on FAZ 7.6 (column names exist). No log data was available, so values are unverified — run `SELECT <col>, count(*) ... GROUP BY <col>` first.
