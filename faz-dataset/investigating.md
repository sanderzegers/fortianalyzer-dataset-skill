# Investigating with a live FortiAnalyzer

Read this when the user wants a question answered from the logs ("who released quarantined mail", "why was this file blocked", "is this a flood attack") and a tool that runs SQL against FAZ is available, such as the `faz_query` MCP tool. Answering a question is a different job from writing a dataset: you explore unknown log formats, correlate across tables and devices, and each claim you report has to hold up. The SQL dialect is the same, so faz-sql-reference.md and the product files still apply.

## Workflow

1. **Find where the event is logged** before writing the real query. Don't assume from the log type's name (see below). For traffic through a FortiGate ("can't reach", "blocked", "what changed"), start with the traffic log, also for DNS, web filter, antivirus and IPS questions (see "FortiGate: start with the traffic log").
2. **Profile in aggregate**: counts per `type`/`subtype`, per enum value, per `msg` template. Look at the shape before the detail.
3. **Correlate** through a documented key (session ID, hash, message ID). Only fall back to time windows when no key exists.
4. **Verify** every link and every "nothing else" before reporting it (see "Verify before you claim").
5. **Report** with the evidence level stated: observed in the logs, inferred from correlation, or assumed.

## Data minimisation

Prefer counts, enum values and `msg` templates for the overview, and pull names, addresses, subjects or IPs when the question needs them, for the rows it needs. Keep them out of reports unless the reader needs them. This is also good analysis practice: the shape of the data first, then the detail. Whether log data may be processed by this model at all is the user's decision (contract, provider, local or cloud model), not something this skill can enforce. If the user sets a stricter rule, follow it.

## FortiGate: start with the traffic log

When a question is about traffic through a FortiGate, start with `$log-traffic`, even when the question names a security feature: "can't reach the DNS server", "the download is blocked", "what changed since it stopped working". The DNS, web filter, antivirus or IPS log comes second, for the detail.

- **The traffic log sees the session; a security log only sees what its profile logged.** Every session the policy logs gets a traffic row with the policy, interfaces, server, NAT and outcome. A security log row exists only when a profile on that policy logged something. In the lab, 6 of one client's 16,313 DNS sessions over 6 hours had a DNS log entry, while the traffic log showed every query, its server and its outcome. That was enough to see the client switch DNS servers and one server never answer.
- **Nearly every session-based security row has its traffic row.** Linked by `devid` + `vd` + `sessionid`, with the traffic window running 7 hours past the event. On a production FAZ: 1,362,249 of 1,362,270 webfilter rows, 857,612 of 857,613 DNS rows, 669 of 669 IPS signature hits, and all antivirus, file-filter and SSL rows with a session ID. On a lab FAZ about 98 %; the misses clustered in a few minutes, so probably lost traffic logs.
- **No traffic row, by design**: DoS anomaly rows (`0720018432` / `0720018433`, `subtype = 'anomaly'`, `sessionid` 0: the DoS policy acts before a session exists), FortiSandbox verdicts (`0201009238`, `sessionid` 0; link them to the submission by hash, fortigate-logmodel.md), and sessions still open (the traffic row is written when the session closes, plus interim rows for long sessions; extend the window past the event).
- **The traffic log can be silent too.** Policies with traffic logging off, denied traffic without deny logging, and traffic to the FortiGate itself (`subtype = 'local'`) without local-in logging leave no traffic row. This follows from the FortiOS logging settings and wasn't measured in either estate. If the traffic log is empty for a flow that should exist, say so and check the security and event logs.
- **The `countX` columns tell you which security log to open.** `countdns`, `countweb`, `countav`, `countips`, `countapp`, `countssl`, `countff` > 0 mark a session that a profile logged (cols-tlog.md).

What `action` says about a failing flow (definitions from the FortiOS Log Reference):

| `action` | Meaning | Typical "doesn't work" reading |
|---|---|---|
| `accept` with `rcvdpkt` 0 | Allowed UDP/ICMP session, no reply | Forwarded, but the server never answered: check the server and the path behind the FortiGate |
| `timeout` | Allowed session timed out | TCP without an answer |
| `dns` | "DNS query return error" | The DNS answer was an error |
| `ip-conn` | "Failed connection attempts" | The FortiGate couldn't connect onward |
| `deny` | Denied by policy | Look at `policyid` (0 = implicit deny) |
| `client-rst` / `server-rst` | Reset by client / server | The server refused (closed port, application) |
| `close` | TCP closed with FIN | Normal end |

Order of work for "it worked, now it doesn't":

1. **Outcome per hour** for the flow (query below). The hour where `act`, `reply`, `server`, `policyid` or `dstintf` changes is when it broke and what changed with it.
2. **Event log of that device around that hour**: configuration changes (`0100044547` / `0100044546`, including FortiManager installs), interface, routing, SD-WAN and HA events (fortigate-logmodel.md).
3. **Security log** only where `countX` > 0 or `action = 'dns'`, for the profile's verdict.

```sql
-- Is a flow working, and what changed? Outcome per hour for one client and one service
SELECT toString(toStartOfHour(itime), timezone()) AS hour_faz, devname, policyid, dstintf,
       ipstr(dstip) AS server, ifNull(action, '') AS act,
       if(ifNull(rcvdpkt, 0) > 0, 'reply', 'no_reply') AS reply,
       countIf(ifNull(countdns, 0) > 0) AS with_dns_log, count(*) AS sessions
FROM $log-traffic
WHERE $filter AND ipstr(srcip) = '192.0.2.10' AND dstport = 53
GROUP BY hour_faz, devname, policyid, dstintf, server, act, reply
ORDER BY hour_faz, sessions DESC
```

## Find where something is logged

Product logs don't always put an event where its name suggests. FortiMail logs admin quarantine releases in `emailfilter`, not in `event`, for example. Before concluding that something "isn't logged":

- Search **every** log type of that device type for the keyword, **one log type and one keyword per query**.
- Never combine a broad `OR` text filter with `ORDER BY count DESC LIMIT n`. A frequent but irrelevant match fills the page and hides the rows you want. In one case, 11,000 DMARC rows containing `p=quarantine` hid the 559 quarantine-release rows.
- Group the matches by a `msg` template (below). This shows which families of messages contain the word, instead of one sample row.
- **"Not in my logs" never means "doesn't exist".** Logs only show what happened in the period. For FortiGate, which events exist and what they mean is in fortigate-logids.tsv (grep it), built from Fortinet's Log Message Reference. Use the reference to find an event and the logs to see which fields are actually filled.
- Keywords can miss: event names don't always use the word you search for (the FortiGate HA failover event is "Virtual cluster member state moved"). List a whole subtype instead.

```sql
-- Which log types and subtypes mention a keyword at all (run once per log type)
SELECT type, subtype, count(*) AS n
FROM $log-emailfilter
WHERE $filter AND ifNull(msg, '') ILIKE '%releas%'
GROUP BY type, subtype
ORDER BY n DESC
```

## Explore with templates and hashes

These techniques show the structure of large log volumes without reading row by row:

**Template the `msg` text.** Replace addresses, URLs, hashes and digits, then group:

```sql
SELECT subtype, msg_tpl, count(*) AS n
FROM (
  SELECT ifNull(subtype, '') AS subtype,
         substring(replaceRegexpAll(replaceRegexpAll(replaceRegexpAll(replaceRegexpAll(
           ifNull(msg, ''),
           '[^\\s<>@:,;()"]+@[^\\s<>:,;()"]+', '<addr>'),
           'https?://\\S+', '<url>'),
           '[0-9a-fA-F]{32,}', '<hash>'),
           '[0-9]+', 'N'), 1, 160) AS msg_tpl
  FROM $log-emailfilter
  WHERE $filter
) t
GROUP BY subtype, msg_tpl
ORDER BY n DESC
LIMIT 50
```

For a coarser view, keep only the first few words: `arrayStringConcat(arraySlice(splitByChar(' ', <templated msg>), 1, 5), ' ')`. Free-text parts such as file names, subjects and folder names still come through. Mask them with an extra `replaceRegexpAll` once you see them.

**Hash identifiers to compare them without seeing them.** `cityHash64(lower(addr))` gives the same number in two queries, so you can check that two rows concern the same recipient without returning the address. This also works across device types, because the hash doesn't depend on the table:

```sql
SELECT cityHash64(lower(`to`)) AS rcpt_hash, count(*) AS n FROM $log-history WHERE $filter AND session_id = '<id>' GROUP BY rcpt_hash
```


## Correlate across device types

**One query, and one dataset, covers one device type.** FAZ resolves every `$log-<type>` macro within the device type of the query, and some names are aliases: with FortiMail as the device type, `$log-malware` resolves to FortiMail's own `virus` table, not to FortiSandbox. The query runs without error and returns plausible counts. So joining two devices in one SQL statement isn't possible, and a query that runs proves nothing about which table a macro hit. Check it with a column that only the intended table has, or with a direct row-count comparison.

**First choice where it applies: FAZ's own identity keys.** FAZ's UEBA stamps log rows with `epid` (endpoint) and `euid` (user), and the same endpoint or user gets the same ID across device types: FortiClient ↔ FortiGate `epid` 78 of 78 and 48 of 48, FortiAuthenticator ↔ FortiGate `euid` 9 of 9. They cover FortiGate, FortiClient and (users only) FortiAuthenticator; FortiMail and FortiWeb rows get none (codes `3`, `104`, `105`). They are FAZ's interpretation, configured per ADOM (data sources, exclusion rules), with values below 1024 as reasons instead of IDs, so confirm a finding against the device fields (`srcip`, `srcmac`, `user`, `fctuid`/`uid`). Details, codes and fill rates: cols-adom-tables.md.

Otherwise, to correlate two devices, run one query per device and carry the keys across:

1. Query device A for the keys (hashes, IDs). Filter to the cases you care about, since query tools usually cap the result size.
2. Paste them into an `IN (...)` list in the query for device B, run with B's device type.

   For larger sets, results are capped at 100 rows by the FAZ API itself (the CLI client of the MCP server too). Pack each side into **one row**, e.g. `SELECT arrayStringConcat(groupArray(concat(toString(h), ':', toString(t))), ',') FROM (...)`, write it to a file with the CLI client, and compare the two files locally. Hash identities with `cityHash64(CAST(col AS String))`: hashing a `LowCardinality` column directly can't be returned ("LowCardinality(UInt64) is not supported").
3. Where no shared key exists, match on time window plus a hashed identifier, and treat the result as a lead until it is verified.

| From | To | Key | Notes |
|---|---|---|---|
| FortiMail `virus` | FortiSandbox `malware` | SHA-256: `extract(msg, 'checksum: ([0-9a-fA-F]{64})')` ↔ `lower(sha256)` | FortiMail logs only the rating; FortiSandbox adds `mcate`, `ftype`, `vmos`. Files inside an archive get their **own** jobs and hashes, so the archive's hash shows the container's verdict only |
| FortiGate `$log-virus` submission (`0201009233`) | FortiSandbox `malware` | `lower(analyticscksum)` ↔ `lower(sha256)` | 100 % per FortiGate that submits to this FortiSandbox, 0 % for one submitting elsewhere. For the verdict alone you don't need FortiSandbox: FortiGate logs it itself (`0201009238`, `fsaverdict`; fortigate-logmodel.md) |
| FortiWeb `attack` | FortiGate `traffic` (FortiWeb behind a VIP) | client IP + client port, FortiWeb time within the FortiGate session (`dtime - duration` … `dtime`) | 99.5 % / 92.3 % on two estates. Needs the client IP passed through to FortiWeb (no source NAT). `dtime` only works when both devices run in the same time zone; otherwise use `itime` with about 60 s of slack |
| FortiMail `virus` (`File ... checksum: <sha256> ... sent to FortiSandbox`) | FortiSandbox `malware` | SHA-256 ↔ `lower(sha256)` | 1,464 of 1,468 files (99.7 %), on both units of a FortiMail cluster |
| FortiGate / FortiClient / FortiAuthenticator rows | each other | FAZ UEBA `epid` / `euid` (> 1024) | Same ID for the same endpoint/user across device types (see above); derived by FAZ, so check against device fields |
| FortiClient `fct-traffic` / `fct-event` (`uid`) | FortiGate `traffic` (`fctuid`) | `toString(fctuid) = toString(uid)` (UUID) | Exact identity. Endpoints found: 45 of 46 (98 %) in one estate, 136 of 427 (32 %) in the other: only endpoints on the network pass these FortiGates. Session level (source IP + port + destination + port, within the session) matched 22 of 30 where the FortiGate saw the source IP |
| FortiMail inbound (`client_ip`) | FortiGate traffic to FortiMail (port 25) | sending server IP + time (FortiMail logs no source port) | **Untested**: in the estate with FortiMail, inbound mail didn't pass a FortiGate logging to the same FAZ |
| FortiMail session | FortiSandbox jobs for its archive contents | time window (seconds, on `itime`) + `cityHash64` of recipient ↔ hash of each `suser` entry | No shared key. Confirm with the file names (`fname`) |
| FortiMail tables | each other | `session_id` | See fortimail-logmodel.md "Linking records" |
| FortiWeb attack | FortiWeb traffic | `device_id` + `src` + `src_port` + `http_url`, `dtime` within 2 s | 98.7–100 %; `msg_id` does **not** link them; see fortiweb-logmodel.md |
| FortiGate VPN login | FortiAuthenticator RADIUS authentication | normalised user name (`DOMAIN\\user`, `user@domain` → `user`) + FortiAuthenticator event within ~2 min before, on `itime` | **Untested**: neither estate examined used FortiAuthenticator for VPN; see fortiauthenticator.md |
| FortiGate config change (`0100044547`/`0100044546`, `user` `<admin>@FortiManager`) | FortiManager install (`0012021015`) | `lower(devname)` ↔ `lower(device)` + user without `@FortiManager` + `itime`, FortiGate rows 7–79 s before the install row | 167 of 180 FortiGate rows on one deployment; the rest from one device whose name differs in FortiManager (probably HA member vs. cluster). Compare on `itime`: `dtime` is in each device's own time zone. See fortimanager-fortianalyzer.md |
| FortiGate direct change (not `@FortiManager`, not `ha_daemon`) | FortiManager auto-update (`objcfg`, `user = 'admin'`, no `session_id`) | device name + `itime` within ±2 min | 47 of 47 change minutes on one deployment |
| FortiGate security logs | FortiGate traffic | `devid` + `vd` + `sessionid` | 81–96 % match within the same hour; see fortigate-logmodel.md "Linking records" |

## Verify before you claim

A correlation by time or by name is a lead, not a fact. Before writing it down as a finding:

- **Confirm a time-window match with a second, independent key**, for example the hashed recipient, or the file name, along with the timestamp.
- **Re-check every "nothing else" against the filter that produced it.** If the query had `risk NOT IN ('Clean')`, it can only say "no other non-clean jobs", not "nothing else was submitted".
- **Know the row grain before counting.** A FortiSandbox cluster logs each scan once per member; one FortiMail single release writes 2 rows. Count the entity (`uniqExact(sha256)`, `count(DISTINCT session_id)`), not rows.
- **Check what a verdict is based on.** A FortiSandbox High Risk rating without a VM run (`vmos` empty) and without a malware name is a static heuristic, not observed behaviour.
- **Compare devices on `itime`, not `dtime`.** `dtime` is each device's own clock; on one estate the devices spread from UTC−4 to UTC+11. `itime` is FAZ arrival time, seconds after the event (faz-sql-reference.md "Time zones").
- **Give both sides of a comparison the same period.** FAZ's "last N days" periods exclude today and "last N hours" exclude the current hour (faz-sql-reference.md). Comparing today's FortiMail rows with a FortiSandbox `last-n-days 30` window matched 8.7 %; with matching windows it matched 99.7 %.
- **Watch for features switched on mid-period.** Check the per-day counts of a classifier or category before averaging over the whole period. A detection that only starts on day 4 skews every per-day figure.

## Query tools

- A tool that submits SQL through FAZ's dataset SQL endpoint (the one behind the GUI's Dataset **Test** button) behaves like that button: a query that works there works as a dataset. The report-run merge step (Common Mistake #12 in faz-sql-reference.md) isn't exercised.
- Through that endpoint, `toDate()` and `dtime` come back as Unix epoch numbers. Wrap them in `toString()` for readable dates.
- Say which time window a result covers. fortianalyzer-sql-mcp returns it as `window` (FAZ time zone); its `period='custom', start='-24h'` covers the last 24 hours up to now, which no built-in period does.
- Concurrent-query limits, period names and which log-type names the tool accepts depend on the tool. Follow its own instructions. The SQL macro (`FROM $log-malware`) decides the table, whatever log type the tool was told.

## When a result hits the row cap

Query tools cap the rows they return. Through FAZ's dataset SQL endpoint the cap is 100 rows, whatever the SQL `LIMIT` says. fortianalyzer-sql-mcp marks such a result `truncated`, gives the size of the full result as `total_rows` (exact up to 1000) and adds a `note`. A truncated result is a partial result:

- The rows are the first ones in the query's order, so without `ORDER BY` they are an arbitrary subset. Don't count them, don't average them, and don't conclude that a value, host or event is missing because it isn't among them.
- Don't report from it. Decide what the question needs, and run a query that fits in the cap:
  1. **A number** (how many, how much): `count(*)`, `count(DISTINCT ...)`, `sum(...)` in one row.
  2. **The shape** (which values, how often): `GROUP BY` the column, with `count(*)`. If that is still over 100 groups, read `total_rows` for the number of groups and take the top N.
  3. **The top N or the latest N**: `ORDER BY ... DESC LIMIT n`.
  4. **Specific rows** (the events of one host or one session): add filters or narrow the period until the result fits.
  5. **Every row really is needed**: page with a stable order. `ORDER BY` columns that make each row unique (add a tiebreak such as `itime, sessionid`), then `LIMIT 100 OFFSET 100`, `200`, ... Each page is a separate query over the same window, so fix the window with absolute `custom` times; with a relative or open-ended period, new logs shift the pages. For large sets, pack the result into one row instead (see "Correlate across device types").
- Say it in the report when an answer rests on a top N or on a sample, not on the full result.
