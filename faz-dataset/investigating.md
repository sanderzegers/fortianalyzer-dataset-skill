# Investigating with a live FortiAnalyzer

Read this when the user wants a question answered from the logs ("who released quarantined mail", "why was this file blocked", "is this a flood attack") and a tool that runs SQL against FAZ is available, such as the `faz_query` MCP tool. Answering a question is a different job from writing a dataset: you explore unknown log formats, correlate across tables and devices, and each claim you report has to hold up. The SQL dialect is the same, so faz-sql-reference.md and the product files still apply.

## Workflow

1. **Find where the event is logged** before writing the real query. Don't assume from the log type's name (see below).
2. **Profile in aggregate**: counts per `type`/`subtype`, per enum value, per `msg` template. Look at the shape before the detail.
3. **Correlate** through a documented key (session ID, hash, message ID). Only fall back to time windows when no key exists.
4. **Verify** every link and every "nothing else" before reporting it (see "Verify before you claim").
5. **Report** with the evidence level stated: observed in the logs, inferred from correlation, or assumed.

## Data minimisation

Prefer counts, enum values and `msg` templates for the overview, and pull names, addresses, subjects or IPs when the question needs them, for the rows it needs. Keep them out of reports unless the reader needs them. This is also good analysis practice: the shape of the data first, then the detail. Whether log data may be processed by this model at all is the user's decision (contract, provider, local or cloud model), not something this skill can enforce. If the user sets a stricter rule, follow it.

## Find where something is logged

Product logs don't always put an event where its name suggests. FortiMail logs admin quarantine releases in `emailfilter`, not in `event`, for example. Before concluding that something "isn't logged":

- Search **every** log type of that device type for the keyword, **one log type and one keyword per query**.
- Never combine a broad `OR` text filter with `ORDER BY count DESC LIMIT n`. A frequent but irrelevant match fills the page and hides the rows you want. In one case, 11,000 DMARC rows containing `p=quarantine` hid the 559 quarantine-release rows.
- Group the matches by a `msg` template (below). This shows which families of messages contain the word, instead of one sample row.

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

To correlate two devices, run one query per device and carry the keys across:

1. Query device A for the keys (hashes, IDs). Filter to the cases you care about, since query tools usually cap the result size.
2. Paste them into an `IN (...)` list in the query for device B, run with B's device type.
3. Where no shared key exists, match on time window plus a hashed identifier, and treat the result as a lead until it is verified.

| From | To | Key | Notes |
|---|---|---|---|
| FortiMail `virus` | FortiSandbox `malware` | SHA-256: `extract(msg, 'checksum: ([0-9a-fA-F]{64})')` ↔ `lower(sha256)` | FortiMail logs only the rating; FortiSandbox adds `mcate`, `ftype`, `vmos`. Files inside an archive get their **own** jobs and hashes, so the archive's hash shows the container's verdict only |
| FortiMail session | FortiSandbox jobs for its archive contents | time window (seconds) + `cityHash64` of recipient ↔ hash of each `suser` entry | No shared key. Confirm with the file names (`fname`) |
| FortiMail tables | each other | `session_id` | See fortimail-logmodel.md "Linking records" |

## Verify before you claim

A correlation by time or by name is a lead, not a fact. Before writing it down as a finding:

- **Confirm a time-window match with a second, independent key**, for example the hashed recipient, or the file name, along with the timestamp.
- **Re-check every "nothing else" against the filter that produced it.** If the query had `risk NOT IN ('Clean')`, it can only say "no other non-clean jobs", not "nothing else was submitted".
- **Know the row grain before counting.** A FortiSandbox cluster logs each scan once per member; one FortiMail single release writes 2 rows. Count the entity (`uniqExact(sha256)`, `count(DISTINCT session_id)`), not rows.
- **Check what a verdict is based on.** A FortiSandbox High Risk rating without a VM run (`vmos` empty) and without a malware name is a static heuristic, not observed behaviour.
- **Watch for features switched on mid-period.** Check the per-day counts of a classifier or category before averaging over the whole period. A detection that only starts on day 4 skews every per-day figure.

## Query tools

- A tool that submits SQL through FAZ's dataset SQL endpoint (the one behind the GUI's Dataset **Test** button) behaves like that button: a query that works there works as a dataset. The report-run merge step (Common Mistake #12 in faz-sql-reference.md) isn't exercised.
- Through that endpoint, `toDate()` and `dtime` come back as Unix epoch numbers. Wrap them in `toString()` for readable dates.
- Row caps, concurrent-query limits, period names and which log-type names the tool accepts depend on the tool. Follow its own instructions. The SQL macro (`FROM $log-malware`) decides the table, whatever log type the tool was told.
