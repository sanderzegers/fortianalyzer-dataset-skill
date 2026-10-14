# FortiOS Version Differences: Test Method and Evidence

This document explains how the version rules in [`faz-dataset/version-differences.md`](../faz-dataset/version-differences.md) were established. The skill file holds only the rules Claude needs for writing queries; the evidence lives here.

## Test setup

Two FAZ 7.6 instances, compared side by side in October 2026:

| Instance | FortiOS on the logging FortiGates |
|---|---|
| Lab A | 7.6.7 build 3704 |
| Lab B | 7.4.12 build 2902, plus a few devices on 7.2.10 build 1706 |

FortiOS versions were read from `logver` on every log row. The decoding (`MmmppBBBB`) matches Fortinet's release notes: FortiOS 7.2.10 is build 1706, 7.4.12 is build 2902, 7.6.7 is build 3704.

## Method

1. **Schema comparison.** For dns, ssl, voip, attack, app-ctrl, virus, webfilter, dlp, file-filter and traffic, one column list was checked on both instances:

   ```sql
   SELECT * EXCEPT (<list>) FROM $log-<type> WHERE $filter AND NOT ignore(<list>) LIMIT 1
   ```

   Both returned "Empty list of columns": every listed column exists, and there are no extra ones. As a control, leaving one column out of the list returned exactly that column. Event logs (540 columns) have identical column lists on both instances, but this strict check was blocked there by the query tool's keyword filter.
2. **Population per version.** For every column, the rows holding a real value (not NULL, `''`, `0`, `N/A`, `::`, `[]`) were counted per `logver`. Windows: 24 h, or 6 h for traffic. Samples ranged from a few thousand rows up to tens of millions.
3. **Official field lists.** Each candidate difference was checked against Fortinet's per-version FortiOS Log Message Reference.

A field counts as version-gated only if it's absent from the older version's log reference **and** absent from that version's data. Everything else that differed between sites turned out to follow configuration.

## Evidence for the version-gated fields

| Fields | First FortiOS | Log reference | Data |
|---|---|---|---|
| traffic `durationdelta`, `sentpktdelta`, `rcvdpktdelta` | 7.4 | Log ID 13: absent in 7.2.10, present in 7.4.12 | 0 % of 21.6 M rows from 7.2.10 (`sentpktdelta` NULL on 100 % of rows, including ~400 k long-lived interim rows); ~20–25 % of rows from 7.4.12 and 7.6.7 |
| traffic `srczone`, `dstzone`, `emstag`, `emstag2`, `vipincomingip`, TCP metrics (`tcpnrt` …), tunnel fields (`tunnelsessionid` …) | 7.6 | Log ID 13: absent in 7.4.12, present in 7.6.6 | `emstag` and `vipincomingip` only on 7.6.7. Zone and TCP metric fields empty even on 7.6.7 (feature not configured) |
| app-ctrl GenAI fields (`aiuser`, `cloudgenai`, `dcgeo`, `model`, `prompt`, `usecase`), `srczone`, `dstzone` | 7.6.4 | Log ID 28704: absent in 7.4.12, 7.6.1 and 7.6.3; present in 7.6.4 | `dcgeo` and `usecase` only on 7.6.7 |
| app-ctrl `messageid`, `transid` | 7.6.1 or earlier 7.6 | Log ID 28704: absent in 7.4.12, present in 7.6.1 | — |
| ssl `srcmac`, `srcname`, `transid` | 7.6 | Log ID 62101: absent in 7.4.4, present in 7.6.1 | Empty on all versions in the sample |

## Evidence for what is *not* version-dependent

- **`utmevent` (traffic):** NULL on every row of ~160 M across 7.2.10, 7.4.12 and 7.6.7. Absent from the log ID 13 field list in 7.2.10, 7.4.12 and 7.6.6.
- **`utmaction` (traffic):** only `''`, `allow` and `block` on all three versions.
- **SSL columns:** `tlsver`, `cipher` and `sni` on all versions and in the 7.4 and 7.6 references. The `ssl*` names fail with "Missing columns" on both instances.
- **Macros:** identical behaviour on both instances; FAZ expands them.
- **Identity columns** (`fctuid`, `unauthuser`, `srcdomain`, `group`): 0 % on some sites and 20–60 % on others, independent of version (FSSO/EMS configuration).
- **ZTNA columns** (`accessproxy`, `gatewayid`, `clientdevice*`, `emsconnection`, `clientcert`): documented since 7.2.10 or 7.4.12, filled only where ZTNA is in use.
- **Attack `threat`, `threatlevel`, `count`:** filled only on `subtype='anomaly'` rows (DoS policies). IPS signature rows have them empty on every version.

## Known gaps

- Values for log types with no data on either instance (emailfilter, ssh, waf, content, protocol, security, gtp, fct-*) are unverified; only their column names were checked against the schema.
- The exact FAZ 7.6 patch level couldn't be read through the query tool.
