---
name: faz-dataset
description: Expert mode for writing FortiAnalyzer dataset queries (FAZ SQL dialect) for use in the GUI under Reports / Datasets, and for investigating questions directly in FAZ logs through a SQL tool such as the faz_query MCP. Use it for ANY question answered from FortiAnalyzer logs, before the first query, for example traffic, blocked or failing connections, DNS, VPN logins, admin logins, configuration changes and FortiManager installs, attacks, mail quarantine and releases, sandbox verdicts. Knows FAZ macros, log table structure, column names, hcache, where events are logged, how records link across tables and devices, and common query patterns for FortiGate, FortiMail, FortiWeb, FortiADC, FortiSandbox, FortiManager, FortiAnalyzer and FortiAuthenticator logs.
---

# FortiAnalyzer Dataset Query Expert

You are an expert at writing **FortiAnalyzer dataset queries** — SQL written in the FAZ GUI dialect that users enter under **Reports > Datasets** (or Report Templates > Chart Dataset).

## Before the first query

Do these steps for every new question, before you write or run any SQL, **also for the second and later questions in a session**: a new question about another device type or another kind of problem needs its own files. Don't tell the user you have read or understood the skill until you have read the files in step 2.

1. **Pick the device type** from the question. Ask if it isn't clear (FortiGate and FortiMail both have an `emailfilter` log, for example).
2. **Read these files completely** with the read tool. They are short enough to read whole; the reference file is about 800 lines.

   | Question about | Device type (`dev`) | Read |
   |---|---|---|
   | FortiGate traffic: can't reach, blocked, bandwidth, sessions, DNS, web filter, antivirus, IPS | `fortigate` | [faz-sql-reference.md](faz-sql-reference.md), [cols-common.md](cols-common.md), [cols-tlog.md](cols-tlog.md), plus the column file of any security log you query (table below). For "it stopped working" or "what changed", also [fortigate-logmodel.md](fortigate-logmodel.md) and [cols-elog.md](cols-elog.md), and follow investigating.md "Order of work": the configuration changes around the flip are a required step |
   | FortiGate events: admin logins, configuration changes, FortiManager installs, VPN (SSL and IPsec), HA, SD-WAN, wireless | `fortigate` | [faz-sql-reference.md](faz-sql-reference.md), [fortigate-logmodel.md](fortigate-logmodel.md), [cols-elog.md](cols-elog.md) |
   | FortiMail: mail flow, quarantine, releases, spam, newsletters, attachments | `fortimail` | [faz-sql-reference.md](faz-sql-reference.md), [fortimail.md](fortimail.md), [fortimail-logmodel.md](fortimail-logmodel.md). Not cols-emailfilter.md or cols-common.md: those are FortiGate's |
   | FortiWeb | `fortiweb` | [faz-sql-reference.md](faz-sql-reference.md), [fortiweb.md](fortiweb.md), [fortiweb-logmodel.md](fortiweb-logmodel.md) |
   | FortiSandbox | `fortisandbox` | [faz-sql-reference.md](faz-sql-reference.md), [fortisandbox.md](fortisandbox.md) |
   | FortiManager, FortiAnalyzer | `fortimanager`, `fortianalyzer` | [faz-sql-reference.md](faz-sql-reference.md), [fortimanager-fortianalyzer.md](fortimanager-fortianalyzer.md) |
   | FortiADC, FortiAuthenticator | `fortiadc`, `fortiauthenticator` | [faz-sql-reference.md](faz-sql-reference.md), [fortiadc.md](fortiadc.md) or [fortiauthenticator.md](fortiauthenticator.md) |
   | Endpoints, users, MAC addresses across devices (UEBA) | | [faz-sql-reference.md](faz-sql-reference.md), [cols-adom-tables.md](cols-adom-tables.md), [cross-device-keys.md](cross-device-keys.md) |
   | Two device types: a file, recipient, user, host, MAC or FortiClient ID seen on one device and looked up on another | both | Both device rows, plus [cross-device-keys.md](cross-device-keys.md): which columns hold the same value and how to normalise them |

   When you answer from live logs through a query tool, also read [investigating.md](investigating.md). A question about two device types needs both rows and cross-device-keys.md.
3. **Read nothing else up front.** Open other files when the question leads there, not in advance. Grep the `.tsv` log-ID lists, never read them whole.
4. **After a context compaction**, when the files above are only summarised in your context, read them again before the next query. A compaction summary never carries the skill's rules, so treat every file you read before it as unread.
5. **If no FortiAnalyzer query tool is available** (no `faz_query` or similar), write the query for the user to run and say so. Don't look for credentials, environment variables or another tool's configuration.

The skill has two modes:

- **Writing a dataset**: the user wants a query for a report or chart. Follow "Your job" below.
- **Investigating**: the user wants a question answered from the logs, and a tool that runs SQL against FAZ is available (e.g. the `faz_query` MCP tool). Also read [investigating.md](investigating.md): it covers finding where an event is logged, exploring large volumes with templates and hashes, correlating across tables and device types, what to do when a result hits the tool's row cap (a truncated result is never the answer), and verifying a finding before reporting it. For traffic through a FortiGate ("can't reach", "blocked", "what changed"), start with `$log-traffic`, also when the question names DNS, web filter, antivirus or IPS: the traffic log has every logged session and its outcome, while a security log only has what its profile logged.

[faz-sql-reference.md](faz-sql-reference.md) is always part of step 2 — it covers macros, filter variables, time variables, hcache patterns, helper functions, common mistakes, and query patterns.

For column names, read **only the files matching the log types needed**:

| Log Type | File |
|---|---|
| Common columns (all log types) | [cols-common.md](cols-common.md) |
| Traffic | [cols-tlog.md](cols-tlog.md) |
| Event | [cols-elog.md](cols-elog.md); which `logid` holds which event (admin, config, VPN, HA, SD-WAN, ...): [fortigate-logmodel.md](fortigate-logmodel.md) |
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
| Security table (virtual patch, CASB, FortiSwitch flow) | [cols-security.md](cols-security.md) |
| GTP | [cols-gtp.md](cols-gtp.md) |
| Content Security (FTP/SMTP/IMAP/POP3) | [cols-content.md](cols-content.md) |
| VoIP | [cols-voip.md](cols-voip.md) |
| Protocol | [cols-protocol.md](cols-protocol.md) |
| Anomaly (same table as IPS/Attack — filter `subtype='anomaly'`) | [cols-anomaly.md](cols-anomaly.md) |
| ICAP (no own table — stored in the protocol table) | [cols-icap.md](cols-icap.md) |
| Virtual Patch (no own table — stored in the security table) | [cols-virtual-patch.md](cols-virtual-patch.md) |
| FortiClient Event | [cols-fct-event.md](cols-fct-event.md). **Device type FortiClient (3)**: with FortiGate selected, `$log-fct-*` returns an empty table |
| FortiClient Traffic | Own schema, not FortiGate's: `uid` (FortiClient UID = FortiGate `fctuid`), `hostname`, `srcip`/`srcport`, `dstip`/`dstport`, `remotename`, `url`, `utmaction` (`passthrough`, `blocked`, `userbrowsed`), `browsetime`, `devicemac`, `emsserial`, `fctver`, `os`. Device type FortiClient (3) |
| ADOM reference tables (`$ADOM_ENDPOINT`, `$ADOM_ENDUSER`, `devtable_ext`, etc.) and FAZ's UEBA endpoint/user identification (`epid`/`euid` on log rows) | [cols-adom-tables.md](cols-adom-tables.md) |
| SOC/SIEM tables (`$event`, `$incident`, `$event_history`, `$incident_history`) | [cols-soc-tables.md](cols-soc-tables.md) |
| Materialized views (`fv_*` — built-in dashboards only) | [cols-fv-views.md](cols-fv-views.md) |

Do NOT read column files that are not needed for the current query.

For FortiGate, [fortigate-logmodel.md](fortigate-logmodel.md) maps which `logid` holds which event, what one row stands for, and the `sessionid`/`tunnelid` links. Read it for event-log reports (admin, configuration, VPN, HA, SD-WAN) and before joining security logs to traffic. For FortiWeb, [fortiweb-logmodel.md](fortiweb-logmodel.md) lists the `log_id`s FortiWeb 7.6+ actually sends: its Log Message Reference doesn't match them, so never take FortiWeb event IDs from the reference. For FortiManager, [fortimanager-fortianalyzer.md](fortimanager-fortianalyzer.md) maps which `log_id` holds installs, object changes and logins, and how to tell an admin's change from FortiManager's auto-update; its severity filter often drops Information-level events such as successful logins. For FortiMail, [fortimail-logmodel.md](fortimail-logmodel.md) maps where each kind of event is logged (quarantine releases are in `emailfilter`, not `event`) and which keys link records. Read it when a report or question involves admin or quarantine actions, delivery status, or more than one table. The other product files list columns and values only, so for them, search every log type as investigating.md describes before concluding that something isn't logged.

### Other Fortinet devices

FortiMail, FortiWeb, FortiADC, FortiSandbox, FortiManager, FortiAnalyzer and FortiAuthenticator logs have their own tables and their own column names. The FortiGate files above and cols-common.md don't apply to them; read only the product file:

| Device (type number) | Log types | File |
|---|---|---|
| FortiMail (4) | `history`, `emailfilter`, `virus`, `event` | [fortimail.md](fortimail.md), plus [fortimail-logmodel.md](fortimail-logmodel.md) for events, links and cross-table patterns |
| FortiWeb (5) | `attack`, `traffic`, `event` | [fortiweb.md](fortiweb.md), plus [fortiweb-logmodel.md](fortiweb-logmodel.md) for event IDs, attack ↔ traffic links and patterns |
| FortiADC (20) | `traffic`, `event`, `attack` | [fortiadc.md](fortiadc.md) |
| FortiSandbox (10) | `malware`, `netalert`, `event` | [fortisandbox.md](fortisandbox.md) |
| FortiManager (1), FortiAnalyzer (7) | `event`, `appevent` | [fortimanager-fortianalyzer.md](fortimanager-fortianalyzer.md): where installs, object changes and logins are logged, admin vs. auto-update changes, the link to FortiGate config changes; all 446 log IDs of 7.2–8.0: [fortimanager-logids.tsv](fortimanager-logids.tsv) (grep it). Aliases must not be column names (`changes`, `timestamp`, `result`) |
| FortiAuthenticator (12) | `event` | [fortiauthenticator.md](fortiauthenticator.md); all 238 log types of 6.6.9: [fortiauthenticator-logids.tsv](fortiauthenticator-logids.tsv) (grep it). Never filter on `logid` (Common Mistake #17) |

The same `$log-<type>` macro means a different table per device type: FortiWeb's `$log-attack` is not FortiGate's, and with FortiMail selected `$log-malware` is FortiMail's own `virus` table. One query or dataset reads one device type; to correlate two devices, query each and carry the keys across (investigating.md). The device type comes from the report or dataset settings in FAZ, not from the SQL, so ask which device the dataset is for when the request doesn't say. FortiMail, FortiWeb and FortiADC name the device column `device_id` (not `devid`) and the severity `pri` (not `level`); FortiSandbox, FortiManager, FortiAnalyzer and FortiAuthenticator use `devid` and `level`.

`$log-netscan` belongs to the FortiGate network vulnerability scanner of FortiOS 5.x, which current FortiOS no longer has, so it has no column file. For endpoint vulnerability reports, use FortiClient logs (`$log-fct-event`, `$log-fct-netscan`); ask the user for the columns or run the column-listing query from faz-sql-reference.md.

`$log-siem` is a FAZ-internal table that FortiGate logs don't fill (empty, without the usual log fields), so it has no column file. For SIEM/SOC reports on events and incidents, use `$event` / `$incident` (cols-soc-tables.md).

Also read [version-differences.md](version-differences.md) when the user mentions FortiOS versions or a mixed-version estate, when a column comes back empty, or when the query uses packet/duration deltas, `srczone`/`dstzone` or GenAI app-control fields.

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

- **Log type or device type**: the request could fit more than one log type or device, or it concerns a device or log type with no column file here (e.g. FortiProxy, FortiDDoS). In the latter case, also ask the user for the column names, or for the output of the column-listing query from faz-sql-reference.md, since you can't verify them.
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
- If a tool for tappable multiple-choice questions is available (e.g. `ask_user_input_v0` on claude.ai, `AskUserQuestion` in Claude Code), ask through it instead of in prose: one tool question per open question, 2–4 short options each, with your default option first and marked "(default)". For answers that can't be buttons (column names, domains), offer an option such as "I'll paste the column list" and ask for the text once it's picked. After calling the tool, stop and wait for the answer.


**Example:**
User: "FortiMail report with average mails per day and max mails per hour per recipient"
Ask before writing: should the daily average count all days in the report period, or only days the recipient received mail? Should it count all mail, or only inbound mail that wasn't rejected? (fortimail.md has the columns: `$log-history`, recipient in `` `to` ``, one recipient per row.)

## Mistakes that keep happening

These caused most failed queries in real sessions. Check every query against them before running it.

| Don't | Do instead |
|---|---|
| Give an alias the name of a real column: `count(*) AS total`, `toDate(itime) AS itime`, `... AS domain` | Use a name no table has (`total_n`, `day_faz`). Otherwise `GROUP BY`, `ORDER BY` and `HAVING` take the column and fail with "not under aggregate function" (Common Mistake #16) |
| Select a column that is neither aggregated nor in `GROUP BY` | Add it to `GROUP BY` or wrap it (`any()`, `min()`, `max()`) |
| Filter an aggregate in `WHERE` (`WHERE cnt > 100`) | `HAVING cnt > 100`, or an outer query |
| `WHERE $filter AND a OR b` | `WHERE $filter AND (a OR b)`. Without parentheses, b escapes the period and the query scans every log |
| Compare or `LIKE` an IP column as text (`srcip = '10.1.2.3'`) | `ipstr(srcip) = '10.1.2.3'`. IP columns are IPv6 values (`::ffff:10.1.2.3`) |
| `toHour(from_itime(itime))`, `toDate(itime)` for FAZ days | `toHour(toDateTime(itime, timezone()))`, `toDate(itime, timezone())`. `from_itime()` returns text; plain `toDate(itime)` is UTC |
| Filter an hour or day on `dtime` (`toHour(toDateTime(dtime, timezone())) = 11`) | Filter on `itime` as above, or set the window with a custom period. `dtime` is the device's own clock: on a FortiGate in another time zone (one in the US, for example) "11:00" on `dtime` is a different hour, and the event you look for isn't in the result |
| Functions from other SQL dialects: `splitPart`, `toUTF8`, `upperCase`, `from_unix_timestamp`, `percentile...` | `splitByString(sep, s)[n]`, nothing, `upper()`, `toDateTime(n)`, `quantile(0.95)(x)` |
| String functions on Nullable columns (`splitByChar('@', to)`) | `splitByChar('@', ifNull(to, ''))` |
| FortiGate names on other devices: `devid`, `level` on FortiMail, FortiWeb, FortiADC | `device_id`, `pri`. Columns differ per device type: take them from the device's file |
| Unquoted `to` / `from` on FortiMail | `` `to` ``, `` `from` `` |
| Read a date column as a date: `toDate()` and `dtime` come back as Unix epoch numbers | `toString(...)` around them |
| Name a cause from traffic counts alone: "a policy is missing", "the host was offline", "the server didn't answer" | Find the minute the outcome flipped, then the configuration changes on that device around it: the policies on both sides of the flip, their zones, interfaces and services, and nearby address changes (investigating.md "Order of work"). Name the change that broke or fixed it, or say that none was logged |
| Query device type `fortifirewall` next to `fortigate`, or add their counts | Use `fortigate` only. On FAZ, `fortifirewall` returned the FortiGate logs again, so every count doubles |
| `cityHash64()` / `xxHash64()`, or the alias `endpoints` / `endusers` (`count(*) AS endpoints`) | "SQL query is forbidden" on patched FAZ builds, whatever the table. Use `CRC32` and another alias (`n_ep`, `n_eu`). Don't retry the same query with small changes |
| Compare a key across devices with plain `=` (`suser = to`, `user = euname`, `srcmac = mac`) | Normalise both sides first: split lists, strip `DOMAIN\` and `@domain`, remove MAC separators (cross-device-keys.md) |
| Describe a window from the period's name ("30 days ending yesterday", "the week starts on Sunday") | Report the window the query covered (the tool's `window`). Whether "last N days" includes today and which day a week starts on differ between FAZes |

When a query tool returns an error with a `hint:` line, apply the hint before retrying. Don't retry the same query with small changes more than twice: read the relevant file section instead.

## Key rules

- Always use `$log-{type}` as the table in FROM — never hardcode `sp1_FGT_tlog` etc.
- Always include `$filter` in WHERE — it provides mandatory time/device scope
- Mind the clocks: periods and `$flex_timescale` use the FAZ time zone, `toDate(itime)` / `toHour(itime)` are UTC unless you pass `timezone()`, and `dtime` is each device's own clock, so filter times on `itime`. Whether "last N days" periods include today differs between FAZes. When you report a result, say which window it covers (faz-sql-reference.md "Time zones" and "Report periods")
- Write `${...}` macro logic inline unless the macro is confirmed working (see the macro status table in faz-sql-reference.md). Many, e.g. `${USER}` and `${THREAT_*}`, don't expand in custom datasets
- Use `devname` directly for device names. FAZ joins it onto every log row (all device types), so no `devtable_ext` join is needed
- If FAZ reports "Missing columns", the column doesn't exist in that FAZ log table (unless the error starts with `MERGE:`, see Common Mistakes #12). That's never caused by the FortiGate's FortiOS version, because FAZ defines the same columns for all devices. Suggest `SELECT * FROM $log-x WHERE $filter LIMIT 1` to list the real columns
- An older FortiOS leaves newer fields empty instead of failing. Packet/duration deltas need FortiOS 7.4+, and zones and GenAI fields need 7.6/7.6.4+. Warn the user when a report depends on them (see version-differences.md)
- `$log-attack` holds IPS rows (`subtype='ips'`) and DoS anomaly rows (`subtype='anomaly'`). Always filter on `subtype`
- Use `coalesce(sentdelta,sentbyte,0)` / `coalesce(rcvddelta,rcvdbyte,0)` for bytes
- Use `bitAnd(logflag,bitOr(1,32))>0` for bandwidth (includes long-lived sessions)
- Use `bitAnd(logflag,1)>0` for session counts
- Use `###(subquery)### t` for hcache cached subqueries
- Use `/*SkipSTART*/ORDER BY col DESC/*SkipEND*/` inside hcache for sorted cache
- Use `ipstr()` to format IP addresses for display
- Use `nullifna()` on `user`, `unauthuser`, `app` columns (they use "N/A" sentinel)
- Use `coalesce(nullifna(\`user\`), nullifna(\`unauthuser\`), ipstr(\`srcip\`))` for user identity
- `logid` is a 10-digit string (`0100032001`); `logid_to_int(logid)` returns the 5-digit message ID for numeric comparisons (except fct-event and FortiAuthenticator, where `logid` is UInt64; there, never filter on `logid` in `WHERE`/`HAVING`, see Common Mistake #17). [fortigate-logids.tsv](fortigate-logids.tsv) lists every FortiGate logid documented in FortiOS 7.2.13, 7.4.12, 7.6.7 and 8.0.1 (logid, message ID, name, meaning, type, subtype, severity, versions). **Search it with grep, never read it whole** (about 1,550 lines): `grep -i 'failover' fortigate-logids.tsv`, `grep '^0100032021' fortigate-logids.tsv`. It says which events exist and what they mean; real logs show which fields are filled. Never treat a logid as non-existent because it isn't in the logs
- `epid`/`euid` are FAZ's UEBA identification, derived from the logs and configured per ADOM; values below 1024 are reason codes (not IDs) — null them out before endpoint/user joins. The device log fields stay the source of truth (cols-adom-tables.md)
- Omit LIMIT by default — the chart's Top-N setting controls row count; add LIMIT only if the user asks or the dataset feeds a table with no Top-N

## Output format

Show the complete query, then a brief explanation of key clauses.
