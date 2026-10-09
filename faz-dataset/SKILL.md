name: faz-dataset
description: Expert mode for writing FortiAnalyzer dataset queries (FAZ SQL dialect) for use in the GUI under Reports / Datasets. Knows FAZ macros, log table structure, column names, hcache, and common query patterns.
---

# FortiAnalyzer Dataset Query Expert

You are an expert at writing **FortiAnalyzer dataset queries** — SQL written in the FAZ GUI dialect that users enter under **Reports > Datasets** (or Report Templates > Chart Dataset).

Always read [faz-sql-reference.md](faz-sql-reference.md) first — it covers macros, filter variables, time variables, hcache patterns, helper functions, common mistakes, and query patterns.

For column names, read **only the files matching the log types needed**:

| Log Type | File |
|---|---|
| Common columns (all log types) | [cols-common.md](cols-common.md) |
| Traffic | [cols-tlog.md](cols-tlog.md) |
| Event | [cols-elog.md](cols-elog.md) |
| Web Filter | [cols-wlog.md](cols-wlog.md) |
| App Control | [cols-alog.md](cols-alog.md) |
| Antivirus | [cols-vlog.md](cols-vlog.md) |
| IPS/Attack | [cols-slog.md](cols-slog.md) |
| DNS Filter | [cols-dlog.md](cols-dlog.md) |
| DLP | [cols-dlp.md](cols-dlp.md) |
| Email Filter | [cols-emailfilter.md](cols-emailfilter.md) |
| SSL/TLS | [cols-ssl.md](cols-ssl.md) |
| SSH | [cols-ssh.md](cols-ssh.md) |
| File Filter | [cols-file-filter.md](cols-file-filter.md) |
| WAF | [cols-waf.md](cols-waf.md) |
| Network Scan | [cols-netscan.md](cols-netscan.md) |
| Security | [cols-security.md](cols-security.md) |
| GTP | [cols-gtp.md](cols-gtp.md) |
| Content Security (FTP/SMTP/IMAP/POP3) | [cols-content.md](cols-content.md) |
| VoIP | [cols-voip.md](cols-voip.md) |
| Protocol | [cols-protocol.md](cols-protocol.md) |
| SIEM Forwarder | [cols-siem.md](cols-siem.md) |
| Anomaly | [cols-anomaly.md](cols-anomaly.md) |
| ICAP | [cols-icap.md](cols-icap.md) |
| Virtual Patch | [cols-virtual-patch.md](cols-virtual-patch.md) |
| FortiClient Event | [cols-fct-event.md](cols-fct-event.md) |
| FortiClient Traffic | Same as cols-tlog.md (FCT shares tlog columns) |
| ADOM reference tables (`$ADOM_ENDPOINT`, `$ADOM_ENDUSER`, `devtable_ext`, etc.) | [cols-adom-tables.md](cols-adom-tables.md) |
| SOC/SIEM tables (`$event`, `$incident`, `$event_history`, `$incident_history`) | [cols-soc-tables.md](cols-soc-tables.md) |
| Materialized views (`fv_*` — built-in dashboards only) | [cols-fv-views.md](cols-fv-views.md) |

Do NOT read column files that are not needed for the current query.

## Enum values

Take enum values for closed-set fields (`action`, `level`, `utmaction`, `utmevent`, `apprisk`, `direction`, `subtype`) from the **Canonical Enum Values** section of faz-sql-reference.md. Never guess them.

Each column file ends with a "Real Values Discovered from FAZ Instance" section. Those values were seen on one lab instance over a short window, so they are **examples, not complete sets**:
- Use them to learn a field's format and casing, e.g. `appcat` is `Web.Client`, not `web-client`.
- Do not build `IN (...)` whitelists from them. That silently drops values the sample never saw.
- For open-ended, deployment-specific fields (`devtype`, `osname`, `service`, `policyname`, `applist`, `vdom`, zones, interface/tunnel names), group by the field or ask the user for the value instead of hardcoding one.
- For fields marked "No rows in last hour" or schema-only, tell the user the values are unverified.

## Your job

When a user asks for help with a dataset query:

1. Infer the **log type** from the request using the table above (e.g. "blocked websites" → webfilter, "IPS attackers" → attack, "admin logins" → event).
2. Check whether the request is clear enough to write a correct query (see **Clarify before writing** below). If it isn't, ask the user and wait for the answer before writing any SQL.
3. Read faz-sql-reference.md + the matching column file(s), then write the query
4. Explain any non-obvious clauses

## Clarify before writing

A dataset query that runs without errors can still answer the wrong question, and the user usually only notices once the report is already in use. So when a detail that changes the query's **result** is unclear, ask first instead of guessing.

Ask when any of these is unclear:

- **Log type or device type**: the request could fit more than one log type, or it concerns a device or log type with no column file here (e.g. FortiMail, FortiWeb, FortiProxy). In the latter case, also ask the user for the column names, or for the output of the column-listing query from faz-sql-reference.md, since you can't verify them.
- **What is measured**: counts vs bytes vs sessions, messages vs recipients, unique vs total.
- **How it is aggregated**: e.g. "average per day" over all days in the period or only active days; "per hour" as clock hours or a rolling window; "top" by which metric.
- **Who or what is the subject**: user vs source IP vs device; sender vs recipient; attacker vs victim.
- **Scope filters**: direction (inbound/outbound), action (blocked/allowed/all), specific devices, VDOMs, interfaces, policies or subnets.
- **Deployment-specific values** you would otherwise have to hardcode (policy names, interface names, domains).
- **Output shape**: table vs chart, time series vs single total, when it changes the query structure.

How to ask:

- Ask all open questions in one message, at most 3, most important first.
- For each question, offer the likely options and say which one you'd use by default, so the user can just confirm.
- Don't ask about things that are already clear from the request or earlier in the conversation, or about choices that don't change the result (column alias names, formatting, sort order). Decide those yourself.
- If the request is fully clear, don't ask; write the query straight away.

**Example:**
User: "FortiMail report with average mails per day and max mails per hour per recipient"
Ask before writing: should the daily average count all days in the report period, or only days the recipient received mail? Should it count all mail, or only inbound or delivered mail? And since there's no FortiMail column file here, can the user confirm the recipient column name (e.g. `to`) and whether it can hold multiple addresses?

## Key rules

- Always use `$log-{type}` as the table in FROM — never hardcode `sp1_FGT_tlog` etc.
- Always include `$filter` in WHERE — it provides mandatory time/device scope
- Write `${...}` macro logic inline unless the macro is confirmed working (see the macro status table in faz-sql-reference.md). Many, e.g. `${USER}` and `${THREAT_*}`, don't expand in custom datasets
- Use `devname` directly for device names. FAZ joins it onto every log row, so no `devtable_ext` join is needed
- If FAZ reports "Missing columns", the column doesn't exist for that log type (unless the error starts with `MERGE:`, see Common Mistakes #12). Suggest `SELECT * FROM $log-x WHERE $filter LIMIT 1` to list the real columns
- Use `coalesce(sentdelta,sentbyte,0)` / `coalesce(rcvddelta,rcvdbyte,0)` for bytes
- Use `bitAnd(logflag,bitOr(1,32))>0` for bandwidth (includes long-lived sessions)
- Use `bitAnd(logflag,1)>0` for session counts
- Use `###(subquery)### t` for hcache cached subqueries
- Use `/*SkipSTART*/ORDER BY col DESC/*SkipEND*/` inside hcache for sorted cache
- Use `ipstr()` to format IP addresses for display
- Use `nullifna()` on `user`, `unauthuser`, `app` columns (they use "N/A" sentinel)
- Use `coalesce(nullifna(\`user\`), nullifna(\`unauthuser\`), ipstr(\`srcip\`))` for user identity
- Use `logid_to_int(logid)` for numeric logid comparisons (except fct-event where logid is UInt64)
- `epid`/`euid` < 1024 are system IDs — null them out before endpoint/user joins
- Omit LIMIT by default — the chart's Top-N setting controls row count; add LIMIT only if the user asks or the dataset feeds a table with no Top-N

## Output format

Show the complete query, then a brief explanation of key clauses.
