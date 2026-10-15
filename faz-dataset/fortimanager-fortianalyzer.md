# FortiManager and FortiAnalyzer Logs (device types 1 and 7)

FortiManager (device type 1) and FortiAnalyzer (device type 7) send `event` logs (admin, configuration, system) and `appevent` logs (FortiAnalyzer incidents, playbooks, reports). Both device types use **the same `event` table schema**: same 200+ column names and types on FAZ 7.6 (October 2026). Values below come from one production FortiManager (about 14,600 rows over 30 days, 44 managed FortiGates); numbers from it are marked as single-deployment. FortiAnalyzer `event` and both `appevent` tables had no rows, so FortiAnalyzer values and subtypes are from Fortinet's log reference.

Where FortiAnalyzer logs appear depends on the setup (a collector forwarding to an analyzer, or a FAZ's own logs, typically in the root ADOM). In the tested Fabric ADOMs there were none.

**All log IDs:** [fortimanager-logids.tsv](fortimanager-logids.tsv) lists the 446 messages of the FortiManager & FortiAnalyzer Log Reference 7.2.12, 7.4.11, 7.6.7 and 8.0.0 (`log_id`, message ID, `LOG_ID_*` name, table, subtype, severity, the `desc` text seen in real logs, versions). The reference gives only the name, no meaning text; the `desc` column of real logs is the readable one. All 18 `log_id`s seen in real logs are in it with matching subtype and severity. **Grep it, don't read it whole:** `grep -i 'install' fortimanager-logids.tsv`.

## Differences from FortiGate tables

| FortiGate name | Name here | Notes |
|---|---|---|
| `logid` | **`log_id`** in `event`, **`logid`** in `appevent` | String: 10 digits with leading zeros, `00` + 2-digit subtype number + 6-digit message ID, e.g. `0012021015` = `dm` (12), message `21015`. `logid_to_int()` doesn't apply; compare as string |
| `logdesc` | **`desc`** | Fixed text per `log_id`, e.g. `Install configuration`. Backtick it: `` `desc` `` |
| `level` | **`level`** | `notice`, `warning`, `error`, `alert`, ... Fortinet's log reference calls it `pri` |
| `devid` / `devname` | `devid` / `devname` | The FortiManager / FortiAnalyzer **itself**, not the managed device. The managed device is `device` or `dev=` in `performed_on` |
| `action` / `status` | Empty on all FortiManager rows seen | Use `operation`, `result` and `subtype` instead |

- **The same `log_id` can mean different things in different versions.** Subtype numbers moved between releases (`incident` is 41 in 7.2 and 40 from 7.4 on; `fazfabric` is 42 in 7.6 and 44 in 8.0, where `fortism` takes 42). So `0040049002` is `aid` "status" on 7.2 and `incident` "attachment deleted" on 7.4+. Filter on `subtype` + `log_id` together, or on `subtype` + `` `desc` ``. The FortiManager subtypes (1–27) didn't move.
- Columns are Nullable. Text needs `ifNull(col, '')`; numeric columns need `ifNull(col, 0)` or `toString(col)`. Mixing them fails with "There is no supertype". **Numeric here although they look like text:** `session_id` (UInt32), `user_type` (UInt16), `state`, `revision`.
- **Real column names can't be aliases.** The table has columns named `timestamp`, `changes`, `result`, `state`, `device`, `object`, ... An alias with such a name makes FAZ read the column instead: `$flex_timestamp AS timestamp` fails with "Column `itime` is not under aggregate function", `count(*) AS changes` with "Column `changes` is not under aggregate function". Use `time_bucket`, `cnt`, `n_changes`.
- Column names such as `desc`, `function`, `when` and `version` are SQL keywords: backtick them (`` `desc` ``).

## Severity filter: what may be missing

FortiManager sends only what its local log filter allows (`config system locallog fortianalyzer setting`, `severity`). In the deployment examined, **no Information-level message arrived at all**: the lowest level seen was `notice`. That drops, among others, successful admin logins and logouts (`0001010018` `LOG_ID_login_info`, Information), ADOM locks (`0001010032`) and JSON API calls (`0001010105`). Failed logins (`0001010019`, Alert) and SSH failures (`0001010014`, Alert) do arrive. Before reporting that something didn't happen, look up its severity in fortimanager-logids.tsv and check the lowest `level` that arrives:

```sql
SELECT level, count(*) AS cnt FROM $log-event WHERE $filter GROUP BY level
```

## Where is it logged? (`$log-event`)

Seen in real logs; the `desc` text is fixed per `log_id`. Other IDs: grep fortimanager-logids.tsv.

| What | `subtype` | `log_id` (`desc`) | One row is | Key columns |
|---|---|---|---|---|
| Object change in a device DB or ADOM DB | `objcfg` | `0021030002` (cdb event log for object changed) | One changed object. A bulk edit writes one row per object, often identical | `user`, `session_id`, `operation` (`edit`, `add`, `delete`, `move`, `purge`), `performed_on`, `changes`, `adom` |
| Install preview | `dm` | `0012021025` (Install preview successful) | One device per preview | `device`, `result`, `changes` (`dbstatus=`, `confstatus=`) |
| **Install to a device** | `dm` | `0012021015` (Install configuration) | One device per install | `device`, `user`, `session_id`, **`result`** (`successfully` or `failed(<reason>)`), `changes` (`dbstatus=modified\|not modified confstatus=insync\|outofsync (revision:N)`) |
| Revision saved after install | `dm` | `0012021009` (Save configuration) | One device per install | `device`, `changes` (`Config checkin (revision:N)`) |
| Policy package install failed | `dm` | `0012021024` (Policy package install failed) | One package + device | **No `device`**: package and target only in `changes` (`... policy package <pkg> on <dev>[<vdom>] failed.`) |
| Device DB update failed | `dm` | `0012021002` (Device updates its device db and cache db) | One failed update | `device`, `changes` (the CLI line that failed) |
| HA config retrieve | `dm` | `0012021026` (Retrieve nonhasync config) | One device | `device`, `changes` (serial and checksum) |
| Device manager changes | `dvm` | `0022031009` (Device Manager dvm log at notice level) | One device action | `operation` (`Modify device`, `Reload device`, `Update device`), `performed_on`, `changes` |
| Device DB metafield change | `system` | `0001010015` (Device manager DB metafield operation) | One change | `user`, `session_id`, `adom`. **`userfrom` holds the user name here, not the access channel** |
| Admin login failed | `system` | `0001010019` (User login/logout failed) | One attempt | `user`, `operation` (`login failed`, `admin lockout`), `changes` |
| SSH login failed | `system` | `0001010014` (User login from SSH failed) | One attempt | `user`, `changes` |
| SSH protocol error | `system` | `0001010075` (SSH server protocol error) | One connection | No `user`; usually scanners. 582 rows in 30 days in the deployment examined |
| FGFM tunnel to a device down | `fgfm` | `0002011003` (fgfm connection down) | One tunnel | `device`, `operation` (`cleanup fgfm session`) |
| Security console task failed | `scply` | `0008017005`, `0008017002` | One task | `operation` (`Install ips sensor entries`, `Device copy`), `adom` |
| Log connection to FAZ changed | `logd` | `0025035004` (Status of the reliable connection changed) | One state change | `changes` |
| Disk full | `system` | `0001010070` (Disk full) | One warning | `operation` (`system log`), `changes` |

`performed_on` is `dev=<device>,vdom=<vdom>` (device DB) or `dev=<device>,adom=<adom>` (ADOM DB); extract the device with `extract(performed_on, 'dev=([^,]+)')`.

### Who made a change: admin or auto-update

`objcfg` rows come from two sources, told apart by `session_id`:

- **Admin change in FortiManager:** `session_id` filled (the admin's GUI session) and `user` is the admin.
- **FortiManager auto-update:** `session_id` empty and `user = 'admin'`. FortiManager writes these when it pulls a change that was made **directly on the FortiGate** into its device DB. In the deployment examined, every minute with a direct (GUI/CLI) FortiGate change on a device FortiManager manages had such rows within ±2 minutes (47 of 47). They were 70 % of all `objcfg` rows, so counting `objcfg` per `user` without this split credits a user `admin` with every change made on the devices.

### One install, several rows

An install writes a preview (`0012021025`), the install (`0012021015`) and a checkin (`0012021009`), one row each per device, all with the same `session_id`. The admin's object edits from that session (`objcfg`) carry the same `session_id`, so `session_id` links "what was changed" to "where it was installed". Count installs as `0012021015` rows, not `dm` rows.

## Linking records

| From | To | Key | Notes |
|---|---|---|---|
| `objcfg` change | install of that change | `session_id` | Same admin session; only admin changes have one (see above) |
| install `0012021015` | preview / checkin rows | `session_id` + `device` | One each per device |
| install `0012021015` (FortiManager) | the config change rows it causes on the FortiGate (`$log-event` `0100044547` / `0100044546`, device type FortiGate) | `lower(device)` = `lower(devname)`, FortiGate `user` = FortiManager `user` + `@FortiManager`, FortiGate rows **7–79 s before** the install row (median 12 s; compare on `itime`, since `dtime` is in each device's own time zone) | Two queries. 167 of 180 FortiManager-sourced FortiGate change rows had their install; the other 13 came from one device whose `devname` doesn't match the FortiManager device name (probably HA member vs. cluster name). Installs that push nothing leave no FortiGate rows (53 of 87 had some). Same user set on both sides (6 of 6). Single deployment |
| `objcfg` auto-update (`user = 'admin'`, no `session_id`) | the direct change on the FortiGate (`0100044547`, `user` not `...@FortiManager`, `ui` not `ha_daemon`) | device name + `itime` within ±2 min | 47 of 47 change minutes; single deployment |

On the FortiGate side, FortiManager installs show up as `user = '<admin>@FortiManager'` with `ui` = `fgfm_tunnel` or `fgfm_fmg(<ip>)` (both seen, on two estates). The HA secondary repeats each change with `ui = 'ha_daemon'`; count changes on the primary only (fortigate-logmodel.md).

## `$log-event` columns

| Column | Type | Description |
|---|---|---|
| **`subtype`** | String | Area that logged (see below) |
| `level` | String | Severity |
| **`` `desc` ``** | String | Fixed event name per `log_id` |
| **`user`** | String | Admin who did it: local name or `user@domain` (remote admin). `admin` without `session_id` on `objcfg` = auto-update (see above) |
| `userfrom` | String | Admin's access channel, e.g. `GUI(<ip>)`. Mostly empty; on `0001010015` it holds the user name |
| **`operation`** | String | What happened (see values below) |
| **`performed_on`** | String | Target. For `objcfg`: `dev=<device>,vdom=<vdom>` or `dev=<device>,adom=<adom>`; for `fgfm`: `dev=<device>` |
| **`changes`** | String | Free-text detail: `attr=value,...` lists for object changes, a sentence for device and install actions |
| `result` | String | `successfully` or `failed(<reason>)` on install and preview rows, else empty |
| `adom` | String | ADOM the action belongs to |
| `device` | String | Managed device name (`dm`, `fgfm` rows) |
| `session_id` | UInt32 | Admin session. Not a String: `ifNull(session_id, 0)` |
| `msg` | String | Readable text |
| `pkgname`, `objname`, `objtype`, `script`, `revision`, `state`, `serial`, ... | | Subtype-specific. Empty on most rows |
| `cpuusage`, `memusage`, `diskusage`, `lograte`, `msgrate`, `logratelimit`, `gbdayusage`, `gbdaylimit` | Int8–Int64 | Resource and license values (FortiAnalyzer `fazsys`/`logging` rows, per log reference) |
| `logdev_id`, `logdev_name`, `logdev_offline_duration`, `logdev_last_logging` | | FortiAnalyzer: logging device that went offline / came back |

### `subtype` values

FortiManager (seen, with the 4-digit `log_id` prefix): `objcfg` (`0021`, object changes, ~70 % of rows), `dvm` (`0022`, device manager), `dm` (`0012`, deployment: install, checkin, retrieve), `system` (`0001`), `scply` (`0008`, security console), `fgfm` (`0002`, FGFM tunnel to managed devices), `logd` (`0025`). The reference lists more (`devcfg`, `glbcfg`, `scrmgr`, `ha`, `fmwmgr`, `fgd`, `fmgws`, `devops`, ...): grep fortimanager-logids.tsv.

FortiAnalyzer (log reference, no data): `fazsys`, `logdev`, `logging`, `logfile`, `report`, `eventmgmt`, `logdb`, `hcache`, `diskquota`, `ediscovery`, `fazha`, `incident`, `fazfabric`, plus shared ones such as `system`.

### `operation` values seen (FortiManager)

| `subtype` | `operation` |
|---|---|
| `objcfg` | `edit`, `add`, `delete`, `move`, `purge` (lowercase) |
| `dvm` | `Modify device`, `Reload device`, `Update device` |
| `dm` | `Device config install`, `Device config install preview`, `Device config checkin`, `Device config edit`, `Policy package install`, `Retrieve nonhasync data`, `Update and export db` |
| `scply` | `Install ips sensor entries`, `Device copy` |
| `fgfm` | `cleanup fgfm session` |
| `system` | `admin lockout`, `login failed`, `system log`, or empty |
| `logd` | `Logd connection` |

Mixed case: match exactly or use `ILIKE`.

One bulk change (the same edit applied to several objects) can produce identical `objcfg` rows; about half of the auto-update rows in the sample were exact repeats. `count(*)` counts change events, not distinct changes.

## `$log-appevent`

FortiAnalyzer incidents, playbooks, reports and disk quota (subtypes `incident`, `playbook`, `report`, `logdev`, `diskquota`, `system` per log reference; message IDs in fortimanager-logids.tsv with table `appevent`, without a computed `logid` since no real row confirmed the format). Columns (all `Nullable(String)` unless noted): `logid`, `type`, `subtype`, `eventtype`, `action`, `level`, `user`, `user_type`, `user_from`, `desc`, `msg`, `status`, `error`, `start_time`, `end_time`, `playbook_name`, `playbook_id`, `job_id`, `trigger_type`, `trigger_name`, `task_name`, `task_id`, `connector_name`, `incident_id`, `incident_severity`, `incident_assigned_analyst`, `incident_other_attrs`, `attachment_type`, `attachment`, `note`, `affected_assets`, `parser_name`, `data_src`, `data_src_id`, `data_src_type`, `event_id`, `report_source`, `report_source_id`, `attach_source`, `attach_source_id`, `logdev_id`, `logdev_name`, `logdev_offline_duration` (Int64), `logdev_last_logging` (Int64), `adom`, `operation`, `lograte` (Int32), `diskusage` (Int8), `logratelimit` (Int32), `performed_on`, `changes`. No data in the test set, so values are unverified.

For incident and event reporting on the receiving FAZ itself, `$incident` / `$event` (cols-soc-tables.md) are usually what the user wants.

## Key Patterns

Device type FortiManager unless noted. None of the aliases may be a column name (see above).

```sql
-- Configuration changes per admin, split from FortiManager's auto-updates
SELECT if(ifNull(session_id, 0) = 0 AND `user` = 'admin',
          'auto-update (change made on the device)', `user`) AS changed_by,
       operation, count(*) AS cnt
FROM $log-event
WHERE $filter AND log_id = '0021030002'
GROUP BY changed_by, operation
ORDER BY cnt DESC

-- Object changes per managed device (device name parsed from performed_on)
SELECT extract(ifNull(performed_on, ''), 'dev=([^,]+)') AS managed_device,
       operation, count(*) AS cnt
FROM $log-event
WHERE $filter AND subtype = 'objcfg'
GROUP BY managed_device, operation
ORDER BY cnt DESC

-- Install results per device: failures and out-of-sync devices
SELECT device,
       if(ifNull(`result`, '') = 'successfully', 'success', 'failed') AS outcome,
       extract(ifNull(changes, ''), 'confstatus=(\\w+)') AS conf_status,
       count(*) AS installs
FROM $log-event
WHERE $filter AND log_id = '0012021015'
GROUP BY device, outcome, conf_status
ORDER BY outcome, installs DESC

-- Installs over time
SELECT $flex_timestamp AS time_bucket, count(*) AS installs
FROM $log-event
WHERE $filter AND log_id = '0012021015'
GROUP BY time_bucket
ORDER BY time_bucket

-- Admin lockouts and failed logins (Alert level, so they pass the usual severity filter)
SELECT operation, count(*) AS cnt
FROM $log-event
WHERE $filter AND log_id IN ('0001010019', '0001010014')
GROUP BY operation

-- Device type FortiGate: who changed the FortiGates (FortiManager, HA sync, local)
SELECT multiIf(ifNull(`user`, '') LIKE '%@FortiManager', 'FortiManager install',
               ifNull(ui, '') LIKE 'ha_daemon%', 'HA sync',
               'local admin or system') AS source,
       count(*) AS cnt, uniqExact(devid) AS devices
FROM $log-event
WHERE $filter AND logid IN ('0100044546', '0100044547', '0100044548')
GROUP BY source
ORDER BY cnt DESC
```
