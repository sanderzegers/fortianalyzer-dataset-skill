# FortiSandbox Logs (device type 10)

FortiSandbox log types: `malware` (one row per scan job), `netalert` (network alerts from sniffer mode), `event` (system). Columns verified on FAZ 7.6 with FortiSandbox logs (October 2026). `netalert` had no rows, so its values are unverified.

Use the macros `$log-malware`, `$log-netalert` and `$log-event` with the FortiSandbox device type. FAZ resolves them. Some query tools only know the FortiGate log-type list and reject `malware`/`netalert` by name; in FAZ itself they work. With another device type selected (FortiMail, for example), `$log-malware` resolves to that device's own table, so FortiSandbox data can't be joined into another device's query.

## Differences from other device types

FortiSandbox uses FortiOS-style names, unlike FortiMail, FortiWeb and FortiADC:

- **`devid`** (not `device_id`), **`level`** (not `pri`), **`logid`** (not `log_id`)
- `malware`: `srcip` / `dstip` (IPv6), `srcport` / `dstport` (Int32)
- `event`: `ip`, `cip` / `sip`, `cport` / `sport` instead
- Columns are Nullable. Use `ifNull(col, '')` before string functions.

## `$log-malware` — one row per scan job

| Column | Type | Description |
|---|---|---|
| `type` / `subtype` | String | Always `malware` / `malware` |
| `level` | String | Always **`alert`**, even for clean files. Don't use it for severity; use `risk` |
| **`risk`** | String | Verdict: `Clean`, `Low Risk`, `Medium Risk`, `High Risk`, `Malicious` (rarely `''`) |
| **`stype`** | String | Submission source: `Device` (file from a FortiGate/FortiMail/...), `URL via Device`, `On-Demand` (manual upload), `URL` |
| **`ftype`** | String | File type: `WEBLink` for URLs, else extension (`pdf`, `exe`, `docx`, `zip`, `js`, ...), `Unknown`, `UserDefined` |
| `mcate` | String | Malware category: `Riskware`, `Downloader`, `Dropper`, `Trojan`, `Ransomware`, `Exploit`, `Phishing`, `Unknown`, `NotApplicable` |
| `mname` | String | AV/sandbox malware name (`W32/...!tr`, `Malware_Generic.P0`), `N/A` when none |
| `fname` / `url` | String | File name (also set for `WEBLink` jobs) / URL: the submitted URL, or the download source of a file. Mostly `http(s)://...` |
| `md5` / `sha256` | String | Hashes (32 / 64 hex characters), filled on every job including URL jobs. `sha1` was always empty |
| `jobid` | Int64 | Scan job ID. **Not always unique per row**: in a FortiSandbox cluster several members log the same job (seen: 3 rows per job, from 3 different `devid`s within a second, on one 6-unit cluster). Check with `SELECT rows_per_job, count(*) AS jobs FROM (SELECT jobid, count(*) AS rows_per_job FROM $log-malware WHERE $filter GROUP BY jobid) t GROUP BY rows_per_job`, and count jobs with `uniqExact(jobid)` and files with `uniqExact(sha256)`. A new scan of the same file is a new `jobid` |
| `clientdev` / `clientvd` | String | Serial / VDOM of the device that submitted the file. Empty on `On-Demand` |
| `devhost` | String | Host name of the FortiSandbox itself (not the submitter) |
| `srcip` / `dstip`, `srcport` / `dstport`, `proto` | IPv6 / Int32 / String | Connection the file came from |
| `suser` | String | User(s) behind the submission. For mail submissions a **comma-separated list** of recipient addresses (`a@example.com,b@example.com`), cut off when long. Use `has(splitByChar(',', ifNull(suser, '')), '<address>')` or `LIKE`, not `=` |
| `vmos` | String | Sandbox VM image. Filled only when the file ran in a VM (<1 % of jobs in the sample) |
| `scanstart` / `scanend` | UInt32 | Scan start / end as Unix time |
| `subtime` | DateTime64(9) | Submission time |
| `scantime` | DateTime | Empty in the sample |
| `rating`, `jstatus` | String | Empty in the sample |
| `msg` | String | Readable description |

Most rows are clean URL and file checks. Filter `risk NOT IN ('Clean', '')` for detection reports.

## `$log-netalert`

Columns: `virusid` (Int32), `attackid` (UInt32), `attackname`, `botnetname`, `srcipport`, `dstipport`, `host`, `url`, `category`, `risklevel`, `msg`, `devhost` (all String unless noted). `srcipport`/`dstipport` combine IP and port in one string. No data in the test set.

## `$log-event`

| Column | Description |
|---|---|
| `type` / `subtype` | `event` / `system` (seen) |
| `level` | `information`, `warning`, `error` |
| `action` | Mixed case: `update`, `monitor`, `SNMP`, `Scan`, `Rescan`, `controller`, `cluster`, `FDN`, `Login`, `Logout`, `Uploading`, `upload`, `White/Black`, `log`, `oftpd_file`, `netshare`, `Job`, `VM`, `connector`, `Kernel`, `Firmware` |
| `status` | `success`, `failure` |
| `user`, `ui`, `msg`, `reason`, `error` | Admin and system details |
| Also | Per-job columns, but in one 6-unit cluster `sha256`, `risk` and `mname` were empty on all ~189,000 event rows of 30 days (`jobid` set on 10, `fname` on 157): scan results go to `$log-malware`. Here `jobid` is a String, not Int64. Columns: `jobid`, `md5`, `sha1`, `sha256`, `fname`, `url`, `risk`, `mname`, `mcate`, `vmname`, `vmos`, `clientdev`, `devhost`, `email`, `emlsndr`, `emlrcvr`, `subject`, `quarantine`, `sharename`, `harole`, `serial`, `version`, ... (filled per action) |

## Key Patterns

```sql
-- Verdicts by submission source
SELECT stype, risk, uniqExact(jobid) AS jobs, uniqExact(sha256) AS files
FROM $log-malware
WHERE $filter
GROUP BY stype, risk
ORDER BY jobs DESC

-- Detections by malware category and file type
SELECT risk, mcate, ftype, uniqExact(jobid) AS jobs, uniqExact(sha256) AS files
FROM $log-malware
WHERE $filter AND risk NOT IN ('Clean', '')
GROUP BY risk, mcate, ftype
ORDER BY jobs DESC

-- Which devices submit the most (and how many detections)
SELECT clientdev, clientvd, uniqExact(jobid) AS jobs,
       uniqExactIf(jobid, risk IN ('High Risk', 'Malicious')) AS high_or_malicious
FROM $log-malware
WHERE $filter AND stype != 'On-Demand'
GROUP BY clientdev, clientvd
ORDER BY jobs DESC

-- Average scan duration per file type (seconds)
SELECT ftype, uniqExact(jobid) AS jobs, avg(scanend - scanstart) AS avg_scan_s
FROM $log-malware
WHERE $filter AND scanend >= scanstart AND scanstart > 0
GROUP BY ftype
ORDER BY jobs DESC
```
