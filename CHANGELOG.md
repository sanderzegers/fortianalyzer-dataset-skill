# Changelog

All notable changes to the faz-dataset skill. Versions follow [semantic versioning](https://semver.org/); 0.x means the skill is usable but not yet extensively tested in practice.

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
