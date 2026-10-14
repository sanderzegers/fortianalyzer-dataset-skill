# FortiAnalyzer Dataset Skill for Claude Code

A [Claude Code skill](https://docs.anthropic.com/en/docs/claude-code/skills) that writes **FortiAnalyzer dataset queries** (FAZ SQL) for **Reports > Datasets** in the FAZ GUI. Describe the report you want, and you get a query you can paste straight in.

```
/faz-dataset Top IPS victims
```

```sql
SELECT victim, sum(totalnum) AS totalnum
FROM ###(
    SELECT (CASE WHEN direction='incoming' THEN ipstr(dstip) ELSE ipstr(srcip) END) AS source,
           (CASE WHEN direction='incoming' THEN ipstr(srcip) ELSE ipstr(dstip) END) AS victim,
           count(*) AS totalnum
    FROM $log-attack
    WHERE $filter AND subtype='ips'
    GROUP BY source, victim
    /*SkipSTART*/ORDER BY totalnum DESC/*SkipEND*/
)### t
WHERE victim IS NOT NULL
GROUP BY victim
ORDER BY totalnum DESC
```

Claude also explains the non-obvious parts. Here, that's why `direction` decides which IP is the victim, why `subtype='ips'` keeps DoS anomaly rows out (they share the attack table), and why the `${THREAT_*}` macros are written out inline: they don't expand in custom datasets.

## Investigating with a live FAZ

When Claude can run SQL against your FAZ (for example through an MCP server that exposes a `faz_query` tool), the skill also answers questions straight from the logs: "who released quarantined mail and why", "what did the sandbox find in that attachment", "is this mailbox under a newsletter flood". [investigating.md](faz-dataset/investigating.md) gives Claude a method for that:

- find where an event is really logged before concluding it isn't,
- explore large volumes with counts, `msg` templates and hashed identities before reading individual rows,
- correlate across tables and across device types (FortiMail ↔ FortiSandbox by SHA-256), one query per device type,
- verify a time-based match with a second key before reporting it.

## Tested on live FortiAnalyzers

The skill was checked against two FAZ 7.6 instances. Their FortiGates run **FortiOS 7.6.7, 7.4.12 and 7.2.10**, so every rule was tested across three FortiOS releases:

- **Generated queries:** top IPS victims, sessions per subnet by application, malicious websites with source IPs, and failed admin logins per device over time all ran correctly.
- **Reference patterns:** every core pattern the skill copies from (Top-N, hcache, bandwidth, time series, IPS block rate, attacker/victim) has been run.
- **Columns:** every column named in the column files for traffic, event, webfilter, app-ctrl, attack, virus, dns, dlp, file-filter, ssl and voip exists in the FAZ schema. For ten of these, the full schema was compared between both FAZes and is identical. For log types without sample data, the column names were checked against the schema, which works on empty tables too.
- **Macros:**
  - These expand in custom datasets: `${REPORT_SESSION}`, `${REPORT_SESSION_WITH_LONGLIVE}`, `${BLOCKED_ACTION}`.
  - These fail, so the skill writes them out inline: `${USER}`, `${THREAT_*}`, `${LEVEL2SEVID}`.
- **FortiOS version differences.** FAZ defines the table columns, so a query never fails because of a FortiGate's FortiOS version. Older FortiOS just leaves newer fields empty. The skill knows which fields are version-gated, proven against both Fortinet's per-version log reference and real data (rules: [version-differences.md](faz-dataset/version-differences.md), method and evidence: [docs/fortios-version-testing.md](docs/fortios-version-testing.md)):
  - `sentpktdelta`, `rcvdpktdelta`, `durationdelta`: FortiOS 7.4+.
  - `srczone`/`dstzone`, ZTNA EMS tags, TCP metrics in traffic logs: FortiOS 7.6+.
  - GenAI fields in app-control logs: FortiOS 7.6.4+.
- **FortiMail, FortiWeb, FortiADC, FortiSandbox, FortiManager, FortiAuthenticator:** columns and types were read from the FAZ schema, values were sampled from production logs, and every example query in the product files was run. The checks found traps a FortiGate-trained query falls into, e.g. `device_id` instead of `devid`, FortiMail's `;`-joined `disposition`, a FortiSandbox `level` that is `alert` even for clean files, and a `timestamp` column in FortiManager/FortiAnalyzer logs that breaks the usual `$flex_timestamp AS timestamp`. FortiAnalyzer's own logs weren't available; its tables were verified by schema only.
- **FortiMail log model** ([fortimail-logmodel.md](faz-dataset/fortimail-logmodel.md)): where each kind of event is logged (quarantine releases are in `emailfilter`, not `event`), and the `session_id` links between history, checks, sandbox stages and SMTP delivery lines. Mapped on one production deployment, about 2.4 million messages over 30 days. The release-audit, newsletter-flood and delivery-status patterns were run against it; deployment-specific numbers are marked as such.
- **Dialect checks:** `WITH TOTALS` fails, grouping by a `LIKE`/`match()` result on a `LowCardinality` column fails, and both FAZ snake_case and ClickHouse regex function names work. Macros resolve within the selected device type, so one dataset can't join two device types.
- **Quirks that hold on every version:**
  - `utmevent` is always NULL in traffic logs, because FortiOS doesn't send it. Use `countips > 0` and the other `count*` columns.
  - SSL logs use `tlsver`/`cipher`/`sni`, not `sslversion`/`sslcipher`.
  - `$log-attack` mixes IPS and DoS anomaly rows. Filter on `subtype`.

## Supported log types

| Log type | Log source | Column file |
|---|---|---|
| Traffic | `$log-traffic` | `cols-tlog.md` |
| Event | `$log-event` | `cols-elog.md` |
| Web Filter | `$log-webfilter` | `cols-wlog.md` |
| App Control | `$log-app-ctrl` | `cols-alog.md` |
| Antivirus | `$log-virus` | `cols-vlog.md` |
| IPS / Attack | `$log-attack` | `cols-slog.md` |
| DNS Filter | `$log-dns` | `cols-dlog.md` |
| DLP | `$log-dlp` | `cols-dlp.md` |
| Email Filter | `$log-emailfilter` | `cols-emailfilter.md` |
| File Filter | `$log-file-filter` | `cols-file-filter.md` |
| FortiClient Event / Traffic | `$log-fct-event` / `$log-fct-traffic` | `cols-fct-event.md` / `cols-tlog.md` |
| SSL, SSH, WAF, Security, GTP, Content, VoIP, Protocol, Anomaly, ICAP, Virtual Patch | `$log-<type>` | `cols-<type>.md` |

Other Fortinet devices that log to FAZ have their own tables and column names, documented in one file per product:

| Device | Log types | File |
|---|---|---|
| FortiMail | `history`, `emailfilter`, `virus`, `event` | `fortimail.md` |
| FortiWeb | `attack`, `traffic`, `event` | `fortiweb.md` |
| FortiADC | `traffic`, `event`, `attack` | `fortiadc.md` |
| FortiSandbox | `malware`, `netalert`, `event` | `fortisandbox.md` |
| FortiManager, FortiAnalyzer | `event`, `appevent` | `fortimanager-fortianalyzer.md` |
| FortiAuthenticator | `event` | `fortiauthenticator.md` |

It also covers the ADOM reference tables, the SOC tables (`$event`, `$incident`), and the `fv_*` materialized views.

## Version

Current version: **0.4.0**. The skill is usable but not yet extensively tested in practice, hence 0.x. See [CHANGELOG.md](CHANGELOG.md) for what changed per version.

## Installation

Clone the repo and copy the `faz-dataset/` directory into your Claude Code skills folder:

```
git clone https://github.com/sanderzegers/fortianalyzer-dataset-skill.git
cp -r fortianalyzer-dataset-skill/faz-dataset ~/.claude/skills/
```

Claude Code detects `SKILL.md` and registers the skill automatically.

## Usage

In any Claude Code session, describe what you want:

```
/faz-dataset show top 10 sources by bytes for FortiGate traffic logs
```

Or ask a FAZ dataset question, and the skill triggers automatically.

## Key conventions enforced

- `FROM $log-<type>`, never a hardcoded table name
- `WHERE $filter` for the mandatory time and device scope
- `bitAnd(logflag,1)>0` for sessions, `bitAnd(logflag,bitOr(1,32))>0` for bandwidth
- `coalesce(sentdelta,sentbyte,0)` for bytes. Summing `sentbyte` alone overcounts long-lived sessions (about 1,600× in testing)
- `###(subquery)###` hcache with `/*SkipSTART*/ORDER BY.../*SkipEND*/`. The outer query only re-aggregates columns the hcache returns
- `ipstr()` for IPs, `nullifna()` for `user`/`app` fields
- `${...}` macros only where confirmed working; everything else is written out inline
- FAZ helpers (`regexp_replace`, `ip_subnet`) and only ClickHouse functions that were tested in FAZ (`extract`, `isIPAddressInRange()`); no `WITH TOTALS`

## Documentation

The repo also includes a detailed guide to writing FortiAnalyzer dataset queries. It isn't specific to the Claude skill, but it's useful for understanding how FAZ SQL works:

**[FortiAnalyzer Dataset Query Writing Guide](faz-dataset-query-guide.md)**

Topics covered: query structure, execution model, macros, hcache, performance, and practical patterns.

## Disclaimer

This is an independent community project. It is not affiliated with, endorsed by, or supported by Fortinet. FortiAnalyzer, FortiGate, FortiMail, FortiWeb, FortiADC, FortiSandbox, FortiManager and FortiAuthenticator are trademarks of Fortinet, Inc.
