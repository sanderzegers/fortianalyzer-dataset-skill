# Changelog

All notable changes to the faz-dataset skill. Versions follow [semantic versioning](https://semver.org/); 0.x means the skill is usable but not yet extensively tested in practice.

## 0.15.0 — 2026-10-28

Driven by 58 pi-agent sessions with a small model (qwen36-35b-a3b, thinking off). It read the right files in only some sessions, read the wrong product files in others, and lost the skill after context compactions. When it did read the device's files first, it answered with almost no failed queries.

### Added
- `SKILL.md` "Before the first query": a checklist with a table from question type to device type and the exact files to read; read nothing else up front; re-read after a context compaction; without a query tool, write the query instead of looking for credentials. Don't claim to have read the skill before step 2.
- `SKILL.md` "Mistakes that keep happening": the errors behind most failed queries in those sessions, with the fix for each (alias named like a column, `GROUP BY`, `HAVING`, `OR` beside `$filter`, IP comparison with `ipstr()`, hours and days in FAZ time, functions from other dialects, Nullable strings, FortiMail/FortiWeb column names, epoch dates, the reported window). Apply a tool's `hint:` line; don't retry the same query more than twice.
- `investigating.md` "Verify before you claim": check the files before reporting that something isn't logged; check totals against their parts; only queried numbers in reports and exports; know today's date and read dates as day.month.year.
- `fortimail-logmodel.md`: count each release once (only one of the two release rows carries the original session ID), and report how many releases linked to their quarantine row.
- `fortigate-logmodel.md`: the VPN client address is `remip`, also on failed logins.

### Changed
- `SKILL.md` description: names everyday questions (VPN logins, configuration changes, quarantine, blocked traffic) so the skill is picked for questions that don't mention datasets.
- `fortisandbox.md`: how to query `malware` with fortianalyzer-sql-mcp; a tool rejecting the name doesn't mean the logs are missing.
- `investigating.md` "Query tools": the checks and `hint:` lines of fortianalyzer-sql-mcp.

## 0.14.0 — 2026-10-16

### Added
- `investigating.md` "When a result hits the row cap": a truncated result is a partial, order-dependent subset, so never count it or infer absence from it; pick the query the question needs (one-row aggregate, `GROUP BY`, top N, tighter filters, or paging with a stable `ORDER BY` plus `OFFSET`, tested on both FAZes) and say when an answer rests on a top N. Weaker models used to take the 100 rows as the full answer.
- `SKILL.md`: the Investigating routing line points to it.

### Changed
- `investigating.md` "Query tools": row caps are no longer left to the tool's own instructions.

## 0.13.0 — 2026-10-15

### Added
- `investigating.md` "FortiGate: start with the traffic log": for traffic questions, start with `$log-traffic`, also when the question names DNS, web filter, antivirus or IPS. Includes:
  - match rates of security rows to their traffic session (production FAZ: 99.998 % webfilter, all DNS, IPS signature, antivirus, file-filter and SSL rows with a session ID; lab about 98 %);
  - the rows without a session by design (DoS anomaly, sandbox verdicts);
  - when the traffic log is silent;
  - what each `action` means for a failing flow;
  - an order of work (traffic outcome per hour → event log → security log);
  - a tested "is this flow working, and what changed?" pattern.
- `SKILL.md`: the same rule in the Investigating routing line.

### Fixed
- Traffic `action` values: added `dns` ("DNS query return error") and `start`; `ip-conn` means failed connection attempts (FortiOS Log Reference).
- `fortigate-logmodel.md`: the security log ↔ traffic link now gives the rates with a 7-hour traffic window instead of 81–96 % within the same hour.

## 0.12.0 — 2026-10-15

### Added
- `faz-sql-reference.md` "Time zones": which clock each value uses, tested on two FAZ 7.6 instances. Periods, `$flex_timescale()`, `$hour_of_day` and `from_itime()` use the FAZ time zone. `toString/toDate/toHour(itime)` are UTC unless given `timezone()`. `dtime` is each device's own clock (devices from UTC−4 to UTC+11 on one estate). FortiGate logs reach the FAZ within seconds (99th percentile 3–39 s), so devices are compared on `itime` with about 60 s of slack. Includes a query showing each device's UTC offset.
- "Report periods" now covers every period type: weeks start on Sunday, `last-n-weeks` is whole past weeks, and a custom end is inclusive only up to `hh:mm:00`. Also how to report the window a result covers (fortianalyzer-sql-mcp now returns it as `window` and accepts `start='-24h'`).
- Common Mistake #18: per-day counts with `toDate(itime)` split days at UTC midnight; matching devices on `dtime` is off by their time zone difference.

### Fixed
- Cross-device links that compare times now say which clock to use: FortiWeb ↔ FortiGate on `dtime` only when both devices share a time zone, otherwise on `itime`; FortiMail ↔ FortiSandbox and FortiAuthenticator ↔ FortiGate on `itime`.
- `cols-common.md`: `itime` and `dtime` descriptions now name their time zones.

## 0.11.0 — 2026-10-15

### Added
- `fortimanager-logids.tsv`: all 446 messages of the FortiManager & FortiAnalyzer Log Reference 7.2.12, 7.4.11, 7.6.7 and 8.0.0 (`log_id`, message ID, `LOG_ID_*` name, table, subtype, severity, the `desc` text seen in real logs, versions), extracted from the reference PDFs. All 18 `log_id`s seen in real logs are in it with matching subtype and severity.
- `fortimanager-fortianalyzer.md`:
  - a where-is-it-logged table with the row grain per `log_id` (installs, previews, checkins, object changes, device manager, logins, FGFM, security console);
  - admin change vs. FortiManager auto-update: `objcfg` rows without `session_id` and with `user = 'admin'` follow a change made directly on the FortiGate (47 of 47 change minutes, single deployment), 70 % of `objcfg` rows;
  - one install = preview + install + checkin per device, linked to the admin's object edits by `session_id`;
  - install outcome in `result` (`successfully` / `failed(<reason>)`) and `confstatus` in `changes`;
  - severity filter: no Information-level message arrived in the deployment examined, so successful admin logins are missing;
  - the same `log_id` can mean different things per version (subtype numbers moved, e.g. `0040049002`).
- Cross-device link FortiManager install ↔ FortiGate config change (`user = '<admin>@FortiManager'`, `ui` `fgfm_tunnel` / `fgfm_fmg(<ip>)`) by device name + `itime`: 167 of 180 FortiGate rows, FortiGate rows 7–79 s before the install row; in `investigating.md` and `fortigate-logmodel.md`. FortiGate HA secondaries repeat every change as `ha_daemon`.
- Patterns: changes per admin split from auto-updates, install results per device, who changed the FortiGates (FortiManager, HA sync, local).

### Fixed
- Two FortiManager patterns used `count(*) AS changes`; `changes` is a column, so they failed with "not under aggregate function". Documented that no alias may share a column name (`changes`, `timestamp`, `result`, ...).
- `session_id` is UInt32 and `user_type` UInt16, not String; `objcfg` also has `purge`, `dvm` also `Reload device` / `Update device`; `action` and `status` are empty on all FortiManager rows.

## 0.10.0 — 2026-10-15

### Added
- `cols-adom-tables.md`: what FAZ's UEBA is and how it fills `epid`/`euid`, based on Fortinet's admin guide and measured on two FAZ instances:
  - derived from logs, with data sources configured per ADOM (FortiMail and the EMS connector off by default);
  - one endpoint per interface without FortiClient;
  - reason codes below 1024 (documented list, plus `105` and `109` seen but undocumented);
  - fill rates per device type: FortiGate, FortiClient and FortiAuthenticator (users) are covered, FortiMail and FortiWeb are not;
  - consistency across device types: `epid` 78/78 and 48/48, `euid` 9/9.
- Provenance per attribute (`attrdatasrc`: `FGT`, `FGTAPI`, `EMS`), `detecttype`, and the finding that `euname` is FAZ's normalised name rather than the log value (97 % agree after normalising).
- Patterns: where an endpoint's identity came from, why rows have no ID, sessions per user preferring the log's own user field.
- `investigating.md`: UEBA IDs as the first-choice cross-device key for FortiGate/FortiClient/FortiAuthenticator, to be confirmed against device fields.

### Fixed
- Real columns of `$ADOM_ENDPOINT` (`mac`, `epdevtype`, `fctuid`, `osversion`, `ownereuname`, ... instead of `epmac`, `eptype`, `dvid`), `$ADOM_ENDUSER` (no `euip`; adds directory attributes and a personal-data warning) and `$ADOM_EPEU_DEVMAP` (`devid`, not `dvid`).

### Notes
- FAZ sometimes rejects queries on the ADOM and FortiClient tables with "SQL query is forbidden" (e.g. scalar subqueries); simple single-table queries worked.

## 0.9.0 — 2026-10-15

### Added
- Cross-device links, tested on two FAZ instances, in `investigating.md`, `fortigate-logmodel.md`, `fortiweb-logmodel.md` and `fortisandbox.md`:
  - FortiGate sandbox submission (`0201009233`, `analyticscksum`) ↔ FortiSandbox `malware` (`sha256`): 100 % for a FortiGate submitting to the FortiSandbox that logs to the same FAZ, 0 % for one submitting elsewhere.
  - FortiGate sandbox submission ↔ FortiGate's own verdict log (`0201009238` / `0211009234`, `fsaverdict`) by `devid` + SHA-256: 119/119 and 8/8, in a single query, whatever sandbox is used.
  - FortiWeb attack ↔ FortiGate session in front of FortiWeb by client IP + port within the session: 99.5 % / 92.3 %; needs the client IP passed through (no source NAT).
- Pattern: sandbox verdict per submitted file (FortiGate `$log-virus`).
  - FortiMail `virus` ↔ FortiSandbox `malware` by SHA-256: 1,464 of 1,468 files (99.7 %), on both units of a FortiMail cluster.
  - FortiClient `uid` ↔ FortiGate `fctuid`: exact identity; 98 % / 32 % of endpoints present in FortiGate traffic (only endpoints on the network). Session-level match 22 of 30 where the FortiGate saw the source IP.
  - FortiMail ↔ FortiGate: untested (inbound mail didn't pass a FortiGate logging to the same FAZ).
- Report periods documented: FAZ's "last N days" periods exclude today and "last N hours" exclude the current hour. Comparisons need the same period on both sides (a misaligned window turned 99.7 % into 8.7 %).

### Fixed
- FortiClient logs need device type FortiClient (3); with FortiGate selected, `$log-fct-*` resolves to empty tables. FortiClient traffic has its own schema (not FortiGate's, as `SKILL.md` claimed). In FortiClient logs `devid`/`devname` is the EMS server; count endpoints by `uid`.
- Common Mistake #17 confirmed for `fct-event` with real data (`WHERE logid IN` 0 rows vs `countIf` 193,281).

## 0.8.0 — 2026-10-15

### Added
- `fortiauthenticator-logids.tsv`: all 238 log types of FortiAuthenticator 6.6.9 (ID, name, sub category, FAZ `subtype`, description, `logdesc` constant where seen, seen in logs). Taken from the device's Logging > Log Access > Log Types page, since Fortinet publishes no FortiAuthenticator log reference. All 53 logids seen on two FAZ instances are in it, with matching categories.
- `scripts/build-fortiauthenticator-logids.py`: rebuilds the file from the saved Log Types pages and keeps the `logdesc`/seen columns.
- `fortiauthenticator.md`: log type ranges per category, the missing logids in the `logdesc` table, log types never seen (accounting, HA, hardware), the FortiGate VPN correlation method (marked untested), and three patterns (admin access, second-factor failures, authentications by method).
- Common Mistake #17: filtering on a numeric `logid`. Where `logid` is a number (FortiAuthenticator, FortiClient `fct-event`), FAZ handles a `logid` filter in `WHERE`/`HAVING` as a string: `WHERE logid IN (...)` silently returns 0 rows or errors, while the same condition inside `countIf` counts correctly. String `logid` (FortiGate, FortiSandbox, FortiManager) and FortiWeb's numeric `log_id` aren't affected. Warnings added to `cols-fct-event.md` and `SKILL.md`.
- `investigating.md`: the 100-row cap applies to the FAZ API itself; pack larger sets into one row and compare locally. Hash `LowCardinality` columns via `CAST(... AS String)`.

## 0.7.0 — 2026-10-15

### Added
- `fortiweb-logmodel.md`: every `log_id` seen from five FortiWeb 7.6+ VMs on two FAZ instances (26 event, 10 attack, 2 traffic), with subtype, `action`/`status`, meaning and whether the reference documents it. Also the attack `main_type` table, what one row stands for, the attack ↔ traffic link (`device_id` + `src` + `src_port` + `http_url`, within 2 s; 98.7–100 %), and seven patterns tested on both FAZes (admin logins, lockouts, config changes, blocked attacks per site, block responses, server pool changes, update failures).
- `fortiweb.md`, `SKILL.md` and `investigating.md` point to the log model.

### Notes
- The FortiWeb Log Message Reference (7.6.0, 8.0.7) doesn't match the IDs FortiWeb 7.6+ sends: configuration changes are all `9000001`, and several frequent events are undocumented ([issue #10](https://github.com/sanderzegers/fortianalyzer-dataset-skill/issues/10)). Unlike FortiGate, there is therefore no full FortiWeb ID index.
- `msg_id` is a running record number; it does not link attack and traffic rows.

## 0.6.0 — 2026-10-15

### Added
- `fortigate-logids.tsv`: every FortiGate logid documented in FortiOS 7.2.13, 7.4.12, 7.6.7 and 8.0.1 (1,549 rows: 10-digit logid, message ID, name, meaning, type, subtype, severity, versions). Claude searches it with grep, so it costs a few lines per lookup, not the whole file. All 328 distinct logids seen in real logs on two FAZ instances match exactly.
- `scripts/build-fortigate-logids.py`: rebuilds the file from Fortinet's Log Reference PDFs for any list of versions. It computes the 10-digit logid from the reference's own type and subtype codes, repairs page breaks inside entries, and keeps the best-spaced meaning when PDF extraction glued words together (four 8.0.1-only meanings stay glued).

### Changed
- `SKILL.md`, `fortigate-logmodel.md`, `investigating.md` and the `logid` tables point to the file for logids not listed. HA failover success (`0108035016`) added to the log model.

## 0.5.0 — 2026-10-15

### Added
- `fortigate-logmodel.md`: which `logid` holds which event (admin access, configuration, SSL VPN and IPsec, user authentication, HA, SD-WAN, interfaces, routing, system), key columns per event, what one row stands for, the `sessionid` and `tunnelid` links, and six patterns (VPN logins, admin logins, admin lockouts, config changes, SD-WAN SLA changes, HA events). Mapped and tested on two FAZ instances.
- `investigating.md` and `SKILL.md`: logids not in your logs can still exist; use the Log Message Reference for the device's version, and list a subtype rather than searching `logdesc` by keyword.
- Common Mistake #16: an alias that matches a real column name (`admin` in FortiGate event logs) breaks `GROUP BY`.

### Changed
- `logid` tables in `faz-sql-reference.md`, `cols-elog.md` and the query guide rebuilt against the FortiOS 7.6.4 Log Message Reference, with a column for whether each logid occurred in real logs. Several old descriptions were wrong: `44547` is any config change (not only FortiManager's), `35011`–`35013` are HA sync and failover *failures* (not failover / split-brain), `22107` is a voltage anomaly, `22936`/`22938` are SD-WAN internet-service quality and bandwidth-monitoring results, `43551` is AP *join*, and `9233`/`54200` belong to the antivirus and DNS logs, not the event log. `logid` is a 10-digit string, so the 5-digit form only works through `logid_to_int()`. The tables are marked as a selection, with pointers to the reference and to a discovery query.

## 0.4.0 — 2026-10-14

### Added
- Investigation mode: `investigating.md` covers answering questions directly from FAZ logs through a SQL tool. It covers finding where an event is logged, exploring with counts, `msg` templates and hashed identities, data minimisation, correlating across tables and device types, and verifying time-based matches.
- `fortimail-logmodel.md`: where each kind of FortiMail event is logged (quarantine release, open and download, history-log release, admin log access, config changes), `session_id` links across all four tables and to FortiSandbox by SHA-256, delivery status from the SMTP event lines, and patterns for release auditing, newsletter-flood detection (with threshold calibration) and delivery status.
- `fortimail.md`: row grain per table, `msg` families, long `msg` values split over several rows, `LowCardinality` cast, classifier caveats.
- FortiSandbox: archive contents scanned as separate jobs, static vs VM verdicts, verdicts that change between scans, and the link to FortiMail.

### Notes
- The log model was mapped on one production deployment. Counts and thresholds from it are marked as such, with queries to check them on another FAZ.

## 0.3.1 — 2026-10-14

### Changed
- Common Mistake #11 corrected: ClickHouse regex functions (`extract`, `regexpExtract`, `replaceRegexpOne`, `replaceRegexpAll`, `match`) work in FAZ datasets alongside the snake_case helpers. Only `regexExtract` doesn't exist.
- FortiSandbox patterns count `uniqExact(jobid)` / `uniqExact(sha256)` instead of rows: in a cluster several members log the same job, so `count(*)` overcounted (3× on one 6-unit cluster).

### Added
- Common Mistakes #13–15: `WITH TOTALS` fails with `unimplemented 7`; grouping by a `LIKE`/`match()` result on a `LowCardinality` column fails; `$log-<type>` resolves within the selected device type, with aliases (FortiMail's `$log-malware` is its `virus` table), so one dataset can't join two device types.
- Tested-features note in the grammar section; FortiSandbox `event` per-job columns documented as empty on a cluster.

## 0.3.0 — 2026-10-14

### Added
- Support for logs from other Fortinet devices, one file per product, loaded only when the dataset is for that device:
  - FortiMail (`history`, `emailfilter`, `virus`, `event`): `fortimail.md`
  - FortiWeb (`attack`, `traffic`, `event`): `fortiweb.md`
  - FortiADC (`traffic`, `event`, `attack`): `fortiadc.md`
  - FortiSandbox (`malware`, `netalert`, `event`): `fortisandbox.md`
  - FortiManager and FortiAnalyzer (`event`, `appevent`): `fortimanager-fortianalyzer.md`
  - FortiAuthenticator (`event`): `fortiauthenticator.md`
- `SKILL.md` routes to the product files and asks which device a dataset is for when the request doesn't say.

### Notes
- FortiAnalyzer tables, FortiADC `attack`, FortiSandbox `netalert` and `appevent` are verified by schema only (no logs available).

## 0.2.0 — 2026-10-14

### Changed
- FortiOS version claims corrected: FAZ defines the schema, so "Missing columns" is never caused by the FortiOS version. Version-gated fields documented in `version-differences.md`, tested against FortiOS 7.2.10, 7.4.12 and 7.6.7.
- `$log-attack` queries always filter on `subtype` (IPS and DoS anomaly rows share the table).

### Removed
- Unverified "FAZ 8.0" content, invented columns and values, and broken example queries.
- Column files for `netscan` (FortiOS 5.x scanner) and `siem` (FAZ-internal, empty for FortiGate logs).

## 0.1.0 — 2026-10-09

First published state: FAZ SQL reference (macros, hcache, helper functions, query patterns), column files for the FortiGate and FortiClient log types, ADOM, SOC and `fv_*` tables, macro status tested on FAZ 7.6, and the dataset query writing guide.
