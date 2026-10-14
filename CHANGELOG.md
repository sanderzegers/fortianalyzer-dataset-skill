# Changelog

All notable changes to the faz-dataset skill. Versions follow [semantic versioning](https://semver.org/); 0.x means the skill is usable but not yet extensively tested in practice.

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
