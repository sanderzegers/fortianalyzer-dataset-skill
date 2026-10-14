# FortiManager and FortiAnalyzer Logs (device types 1 and 7)

FortiManager (device type 1) and FortiAnalyzer (device type 7) send `event` logs (admin, configuration, system) and `appevent` logs (FortiAnalyzer incidents, playbooks, reports). Both device types use **the same `event` table schema**: same 200+ column names and types on FAZ 7.6 (October 2026). Values below come from FortiManager logs; FortiAnalyzer `event` and both `appevent` tables had no rows, so FortiAnalyzer values and subtypes are from Fortinet's log message reference.

Where FortiAnalyzer logs appear depends on the setup (a collector forwarding to an analyzer, or a FAZ's own logs, typically in the root ADOM). In the tested Fabric ADOM there were none.

## Differences from FortiGate tables

| FortiGate name | Name here | Notes |
|---|---|---|
| `logid` | **`log_id`** in `event`, **`logid`** in `appevent` | String: 10 digits with leading zeros, e.g. `0022xxxxxx`. Digits 1–2 = log type (`00` event), 3–4 = subtype code, 5–10 = message ID. `logid_to_int()` doesn't apply; compare as string or use `subtype` |
| `level` | **`level`** | `notice`, `warning`, `error`, `alert`, ... Fortinet's log reference calls it `pri` |
| `devid` / `devname` | `devid` / `devname` | The FortiManager / FortiAnalyzer **itself**, not the managed device. There's no `vd` column |
| `action` / `status` | Mostly empty | Use `operation` and `subtype` instead |

- Columns are Nullable. Text needs `ifNull(col, '')`; numeric columns (`state`, `revision`, ...) need `ifNull(col, 0)` or `toString(col)`. Mixing them (`ifNull(state, '')`) fails with "There is no supertype".
- **The table has a column named `timestamp`.** The usual `$flex_timestamp AS timestamp` from the FortiGate patterns fails here with "Column `itime` is not under aggregate function". Use another alias, e.g. `$flex_timestamp AS time_bucket`.
- Column names such as `desc`, `function`, `when` and `version` are SQL keywords: backtick them (`` `desc` ``).

## `$log-event`

| Column | Type | Description |
|---|---|---|
| **`subtype`** | String | Area that logged (see below) |
| `level` | String | Severity |
| **`user`** | String | Admin who did it: local name or `user@domain` (remote admin). Empty on system-triggered rows |
| `userfrom` | String | Admin's access channel, e.g. `GUI(<ip>)`. Mostly empty |
| **`operation`** | String | What happened (see values below) |
| **`performed_on`** | String | Target. For `objcfg`: `dev=<device>,vdom=<vdom>` or `dev=<device>,adom=<adom>`; for `fgfm`: `dev=<device>` |
| **`changes`** | String | Free-text detail: `attr=value,...` lists for object changes, a sentence for device and install actions |
| `adom` | String | ADOM the action belongs to |
| `device` | String | Managed device name (`dm` rows) |
| `result` | String | `successfully` or empty (`dm` install rows) |
| `session_id` | String | Admin session |
| `msg` | String | Readable text |
| `pkgname`, `objname`, `objtype`, `script`, `revision`, `state`, `serial`, ... | | Subtype-specific. Empty on most rows |
| `cpuusage`, `memusage`, `diskusage`, `lograte`, `msgrate`, `logratelimit`, `gbdayusage`, `gbdaylimit` | Int8–Int64 | Resource and license values (FortiAnalyzer `fazsys`/`logging` rows, per log reference) |
| `logdev_id`, `logdev_name`, `logdev_offline_duration`, `logdev_last_logging` | | FortiAnalyzer: logging device that went offline / came back |

### `subtype` values

FortiManager (seen, with the 4-digit `log_id` prefix): `objcfg` (`0021`, object changes, ~70 % of rows), `dvm` (`0022`, device manager), `dm` (`0012`, deployment: install, checkin, retrieve), `system` (`0001`), `scply` (`0008`, script/policy copy), `fgfm` (`0002`, FGFM tunnel to managed devices), `logd` (`0025`).

FortiAnalyzer (log reference, no data): `fazsys`, `logdev`, `logging`, `logfile`, `report`, `eventmgmt`, `logdb`, `hcache`, `diskquota`, `ediscovery`, `fazha`, `incident`, plus shared ones such as `system`.

### `operation` values seen (FortiManager)

| `subtype` | `operation` |
|---|---|
| `objcfg` | `edit`, `add`, `delete`, `move` (lowercase) |
| `dvm` | `Modify device` |
| `dm` | `Device config install`, `Device config install preview`, `Device config checkin`, `Device config edit`, `Policy package install`, `Retrieve nonhasync data`, `Update and export db` |
| `scply` | `Install ips sensor entries`, `Device copy` |
| `fgfm` | `cleanup fgfm session` |
| `system` | `admin lockout`, `login failed`, `system log`, or empty |
| `logd` | `Logd connection` |

Mixed case: match exactly or use `ILIKE`.

One bulk change (the same edit applied to several objects) can produce identical `objcfg` rows; ~17 % of `objcfg` rows in the sample were exact repeats. `count(*)` counts change events, not distinct changes.

## `$log-appevent`

FortiAnalyzer incidents, playbooks, reports and disk quota (subtypes `incident`, `playbook`, `report`, `diskquota` per log reference). Columns (all `Nullable(String)` unless noted): `logid`, `type`, `subtype`, `eventtype`, `action`, `level`, `user`, `user_type`, `user_from`, `desc`, `msg`, `status`, `error`, `start_time`, `end_time`, `playbook_name`, `playbook_id`, `job_id`, `trigger_type`, `trigger_name`, `task_name`, `task_id`, `connector_name`, `incident_id`, `incident_severity`, `incident_assigned_analyst`, `incident_other_attrs`, `attachment_type`, `attachment`, `note`, `affected_assets`, `parser_name`, `data_src`, `data_src_id`, `data_src_type`, `event_id`, `report_source`, `report_source_id`, `attach_source`, `attach_source_id`, `logdev_id`, `logdev_name`, `logdev_offline_duration` (Int64), `logdev_last_logging` (Int64), `adom`, `operation`, `lograte` (Int32), `diskusage` (Int8), `logratelimit` (Int32), `performed_on`, `changes`. No data in the test set, so values are unverified.

For incident and event reporting on the receiving FAZ itself, `$incident` / `$event` (cols-soc-tables.md) are usually what the user wants.

## Key Patterns

```sql
-- Configuration changes per admin and operation
SELECT `user`, subtype, operation, count(*) AS changes
FROM $log-event
WHERE $filter AND ifNull(`user`, '') != ''
GROUP BY `user`, subtype, operation
ORDER BY changes DESC

-- Object changes per managed device (device name parsed from performed_on)
SELECT extract(ifNull(performed_on, ''), 'dev=([^,]+)') AS managed_device,
       operation, count(*) AS changes
FROM $log-event
WHERE $filter AND subtype = 'objcfg'
GROUP BY managed_device, operation
ORDER BY changes DESC

-- Installs to devices over time
-- (alias must not be `timestamp`: that is a real column in this table)
SELECT $flex_timestamp AS time_bucket, count(*) AS installs
FROM $log-event
WHERE $filter AND subtype = 'dm' AND operation IN ('Device config install', 'Policy package install')
GROUP BY time_bucket
ORDER BY time_bucket

-- Admin lockouts and failed logins
SELECT operation, count(*) AS cnt
FROM $log-event
WHERE $filter AND subtype = 'system' AND operation IN ('admin lockout', 'login failed')
GROUP BY operation
```
