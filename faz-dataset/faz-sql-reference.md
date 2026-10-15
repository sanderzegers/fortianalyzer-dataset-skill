# FortiAnalyzer SQL Dialect Reference

> **FortiOS versions:** FAZ defines the log table columns, so every FortiGate gets the same columns whatever its FortiOS version. Older FortiOS simply leaves newer fields empty. For the fields that are version-gated, and for `logver` checks, see [version-differences.md](version-differences.md).

## Pipeline

```
GUI Dataset SQL
  ↓ FazReportSQL.parseFazKeyword()   (expands $log-*, $filter, ${MACRO}, ###...###)
  ↓ sql_rewriter (ANTLR4 Flask — dialect rewrite to ClickHouse SQL)
  ↓ ClickHouse (log data) / PostgreSQL (identity, SIEM — proxied via CH)
```

---

## Log Source Variables

| Variable | Log Category |
|---|---|
| `$log` | Same as dataset's `log_category` setting |
| `$log-traffic` | Traffic/firewall sessions |
| `$log-webfilter` | Web filter events |
| `$log-app-ctrl` | Application control |
| `$log-attack` | IPS signature events (`subtype='ips'`) **and** DoS anomaly events (`subtype='anomaly'`). Always filter on `subtype` |
| `$log-virus` | Antivirus events |
| `$log-event` | System/device events |
| `$log-dlp` | Data loss prevention |
| `$log-dns` | DNS filter events |
| `$log-emailfilter` | Email filter |
| `$log-fct-traffic` | FortiClient traffic |
| `$log-fct-event` | FortiClient events |
| `$log-file-filter` | File filter events |

**Rules:**
- Always use `$log-{type}` — never hardcode `sp1_FGT_tlog` etc.
- Set `log_category` on the dataset to match the primary log source.

---

## Filter Variables

| Variable | Use |
|---|---|
| `$filter` | **Always required** on raw log queries — injects time range + device scope |
| `$dev_filter` | Device-only filter (no time range) — for non-log table joins |
| `$last3day_period $filter` | Rolling 3-day lookback (prepend before `$filter`) |
| `$pre_period` | Period before current window — for before/after comparisons |
| `$filter-drilldown` | Drilldown filter on outer query only (built-in datasets only) |
| `$filter-exclude-var` | Seen in built-in datasets inside hcache, paired with `$filter-drilldown` on the outer query. Use `$filter` in custom datasets |
| `$cust_time_filter(col)` | Time filter for non-log tables (`$event`, `$incident`) |
| `$cust_time_filter(col, TODAY)` | Same with preset: `TODAY`, `YESTERDAY`, `LAST_N_PERIOD,1` |
| `$adom_oid` | Integer ADOM OID — rarely needed directly |

```sql
-- 3-day lookback pattern
WHERE $last3day_period $filter AND logid_to_int(logid) = 26001

-- Before/after comparison
WHERE ($pre_period OR $filter) AND (bitAnd(logflag,1)>0)
```

---

## Time Variables

| Variable | Use |
|---|---|
| `$flex_timestamp` | Groups rows into time buckets — use in inner GROUP BY |
| `$flex_timescale(col)` | Formats bucketed timestamp for display — use in outer SELECT |
| `$fv_line_timescale(col)` | Like `$flex_timescale` but for `fv_*` materialized views |
| `$hour_of_day` | Hour 0–23 bucket |
| `$hour_of_day(col)` | Hour from explicit column |
| `$day_of_week` | Day 0–6 (0=Sunday) |
| `$DAY_OF_MONTH` | Day 1–31 |
| `$calendar_time` | Calendar-aligned bucket (midnight/hour boundary) |
| `$flex_timestamp(col)` | Bucket by explicit column instead of `itime` |
| `$start_time` / `$end_time` | Report period start/end Unix timestamps |
| `$timespan` | Report period duration in seconds |
| `$days_num` | Number of days in the report period — use for daily averages: `sum(x)/$days_num` |

```sql
-- Standard time series pattern
SELECT $flex_timescale(timestamp) AS hodex, sum(bytes) AS bytes
FROM ###(
    SELECT $flex_timestamp AS timestamp, sum(coalesce(sentdelta,sentbyte,0)+coalesce(rcvddelta,rcvdbyte,0)) AS bytes
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)
    GROUP BY timestamp
)### t
GROUP BY hodex
HAVING sum(bytes) > 0
ORDER BY hodex
```

---

## ${MACRO} Expansions

> **Custom datasets:** not every `${...}` macro expands in GUI datasets. An unexpanded macro fails with a syntax error at `$`. Tested on two FAZ 7.6 instances with FortiOS 7.2, 7.4 and 7.6 logs. FAZ expands the macros, so the result doesn't depend on the FortiOS version:
>
> | Status | Macros |
> |---|---|
> | Confirmed working | `${REPORT_SESSION}`, `${REPORT_SESSION_WITH_LONGLIVE}`, `${BLOCKED_ACTION}` |
> | Confirmed failing | `${USER}`, `${THREAT_SRCIP}`, `${THREAT_DSTIP}`, `${LEVEL2SEVID}` |
> | Unverified | all others |
> | Pattern so far | The logflag macros work, while the CASE/coalesce-expression macros fail. This is a hypothesis for the untested macros, not a rule |
>
> Unless a macro is confirmed working, write its expansion from the tables below inline.

logflag bit constants (expand to numeric strings):

| Macro | Value |
|---|---|
| `${FGTLOG_F_REPORT_SESSION}` | `1` |
| `${FGTLOG_F_BLOCKED_ACTION}` | `2` |
| `${FGTLOG_F_CLOUD_APP}` | `4` |
| `${FGTLOG_F_FCT_SYSUSR}` | `8` |
| `${FGTLOG_F_BOTNET}` | `16` |
| `${FGTLOG_F_LONGLIVE_SESSION}` | `32` |

logflag condition macros:

| Macro | Expands to |
|---|---|
| `${REPORT_SESSION}` | `(bitAnd(logflag,1)>0)` |
| `${REPORT_SESSION_WITH_LONGLIVE}` | `(bitAnd(logflag,bitOr(1,32))>0)` |
| `${REPORT_BLOCK_SESSION}` | `(bitAnd(logflag,bitOr(1,2))=bitOr(1,2))` |
| `${BLOCKED_ACTION}` | `(bitAnd(logflag,2)>0)` |
| `${BLOCKED_SESSION}` | `(CASE WHEN (bitAnd(logflag,2)>0) THEN 1 ELSE 0 END)` |
| `${IS_BOTNET}` | `(bitAnd(logflag,16)>0)` |
| `${IS_FCT_ENDUSER}` | `(logflag is null or bitAnd(logflag,8)=0)` |

UTM event macros:

| Macro | Expands to |
|---|---|
| `${WEB_UTM_EVENT}` | `utmevent in ('webfilter','banned-word','web-content','command-block','script-filter')` |
| `${WEB_SESSION}` | `(countweb>0 or ((logver is null or logver<502000000) and (hostname is not null or ${WEB_UTM_EVENT})))` |
| `${AV_UTM_EVENT}` | `utmevent is not null and virus is not null` |
| `${APPCTRL_UTM_EVENT}` | `utmevent in ('app-ctrl')` |
| `${ATTACK_UTM_EVENT}` | `utmevent in ('ips')` |
| `${EMAIL_UTM_EVENT}` | `utmevent in ('general-email-log', 'spamfilter')` |

> **`utmevent` is always NULL in traffic logs.** FortiOS doesn't send it there: it's absent from the forward-traffic field list in 7.2, 7.4 and 7.6, and NULL on every row tested. So all `utmevent ...` macros, including `${AV_UTM_EVENT}`, match nothing on traffic logs. Use the counters instead: `countweb>0`, `countapp>0`, `countips>0`, `countav>0`, `countdns>0` or `countssl>0`. `${WEB_SESSION}` still works, because it checks `countweb>0` first.
| `${EMAIL_SEND_SERVICE}` | `service IN ('smtp','SMTP','25/tcp','587/tcp','smtps','SMTPS','465/tcp')` |
| `${EMAIL_RECV_SERVICE}` | `service IN ('pop3','POP3','110/tcp','imap','IMAP','143/tcp','imaps','IMAPS','993/tcp','pop3s','POP3S','995/tcp')` |

Identity macros:

| Macro | Expands to |
|---|---|
| `${USER}` | `coalesce(nullifna(\`user\`), nullifna(\`unauthuser\`))` |
| `${USER_SRC}` | `coalesce(f_user, euname, ipstr(\`srcip\`))` |
| `${EP_SRC}` | `coalesce(epname, ipstr(\`srcip\`))` |
| `${SAAS_USER}` | `coalesce(nullifna(\`user\`), nullifna(\`clouduser\`), nullifna(\`unauthuser\`), srcname, ipstr(\`srcip\`))` |
| `${DLDN_USER}` | `dldn_user` |
| `${SOC_EX_FLDS}` | `dvid, srcip, dstip, epid, euid` |

Threat direction macros (IPS):

| Macro | Expands to |
|---|---|
| `${THREAT_DSTIP}` | `(CASE WHEN direction='incoming' THEN srcip ELSE dstip END)` |
| `${THREAT_SRCIP}` | `(CASE WHEN direction='incoming' THEN dstip ELSE srcip END)` |

Severity mapping macros:

| Macro | Expands to |
|---|---|
| `${LEVEL2SEVID}` | `(CASE WHEN level IN ('critical','alert','emergency') THEN 5 WHEN level='error' THEN 4 WHEN level='warning' THEN 3 WHEN level='notice' THEN 2 ELSE 1 END)` |
| `${SEVID2SEVERITY}` | `(CASE sevid WHEN 5 THEN 'Critical' WHEN 4 THEN 'High' WHEN 3 THEN 'Medium' WHEN 2 THEN 'Info' ELSE 'Low' END)` |
| `${FCTVULNSEV2ID}` | `(CASE vulnseverity WHEN 'Critical' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3 WHEN 'Info' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END)` |
| `${EVENTSEV2STR}` | `(CASE severity WHEN 0 THEN 'Critical' WHEN 1 THEN 'High' WHEN 2 THEN 'Medium' WHEN 3 THEN 'Low' ELSE NULL END)` |

---

## logflag Bitmask (traffic log)

| Bit | Value | Meaning | Use when |
|---|---|---|---|
| 0 | 1 | `REPORT_SESSION` | Session counted in reports | Almost always |
| 1 | 2 | `BLOCKED_ACTION` | Action was blocked | Blocked-only queries |
| 2 | 4 | `CLOUD_APP` | Cloud app session | Cloud app queries |
| 3 | 8 | `FCT_SYSUSR` | FortiClient system user | Exclude for end-user only |
| 4 | 16 | `BOTNET` | Botnet session | Botnet queries |
| 5 | 32 | `LONGLIVE_SESSION` | Long-lived session | Include with bandwidth |

```sql
WHERE $filter AND (bitAnd(logflag,1)>0)              -- sessions
WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)    -- sessions + long-lived (bandwidth)
WHERE $filter AND (bitAnd(logflag,2)>0)              -- blocked only
WHERE $filter AND (bitAnd(logflag,1)>0) AND (bitAnd(logflag,8)=0)  -- exclude FCT system users
```

---

## HCache Mechanism (`###...###`)

Executes inner subquery once, caches result, outer query reads from cache. Use when:
- You need to filter on a computed/aliased column
- Two levels of aggregation needed
- Multiple datasets share the same base scan
- Time series queries (standard pattern)

**Basic syntax** (template: `col_a`/`col_b`/`col_c` are placeholders):
```sql
SELECT col_a, sum(col_b) AS total
FROM ###(
    SELECT col_a, col_b, col_c
    FROM $log
    WHERE $filter
    GROUP BY col_a, col_b, col_c
    /*SkipSTART*/ORDER BY col_b DESC/*SkipEND*/
)### t
WHERE col_c = 'some_value'
GROUP BY col_a
ORDER BY total DESC
```

The alias `t` after `###` is required.

**Named base cache (shared across datasets in same report):**
```sql
###base(/*tag:rpt_base_t_bndwdth_sess*/
    SELECT $flex_timestamp AS timestamp,
           dvid, srcip, dstip, epid, euid, appcat, apprisk,
           coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) AS user_src,
           service,
           sum(CASE WHEN (bitAnd(logflag,1)>0) THEN 1 ELSE 0 END) AS sessions,
           sum(coalesce(sentdelta,sentbyte,0)+coalesce(rcvddelta,rcvdbyte,0)) AS bandwidth,
           sum(coalesce(sentdelta,sentbyte,0)) AS traffic_out,
           sum(coalesce(rcvddelta,rcvdbyte,0)) AS traffic_in
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)
    GROUP BY timestamp, dvid, srcip, dstip, epid, euid, appcat, apprisk, user_src, service
    /*SkipSTART*/ORDER BY bandwidth DESC, sessions DESC/*SkipEND*/
)base###
```

**What goes inside vs outside hcache:**
- Inside: `FROM $log-*` with `$filter`, all columns you may need to filter/group by, `/*SkipSTART*/ORDER BY.../*SkipEND*/`
- Outside: final re-aggregation, `WHERE` on computed columns, `HAVING`, final `ORDER BY`/`LIMIT`, `$flex_timescale()`

---

## `/*SkipSTART*/`/`/*SkipEND*/` Hint

Tells the engine to include ORDER BY when populating hcache but skip it in other contexts. Always use inside `###(...)###` for sorted top-N cache:

```sql
FROM ###(
    SELECT user_src, count(*) AS sessions
    FROM $log WHERE $filter
    GROUP BY user_src
    /*SkipSTART*/ORDER BY sessions DESC/*SkipEND*/
)### t
```

---

## ADOM Reference Tables

| Variable | Contains |
|---|---|
| `$ADOM_ENDPOINT` | `faz_fabric_endpoints` — join on `epid`; filter `epid > 1024` |
| `$ADOM_ENDUSER` | `faz_fabric_endusers` — join on `euid`; filter `euid > 1024` |
| `$ADOM_EPEU_DEVMAP` | `faz_fabric_epeudevmap` — endpoint↔user device mapping |
| `$ADOM_EP_SOFTWARE` | `faz_fabric_endpoints_software` — endpoint software inventory |
| `$ADOM_EP_VULN` | `faz_fabric_endpoints_vuln_map` — endpoint vulnerability map |
| `$ADOM_INTF_INFO` | Interface information |
| `$ADOM_INTF_STATS` | Interface statistics |
| `$ADOM_SDWAN_INTF_INFO` | SD-WAN interface info |
| `$ADOMTBL_PLHD_POLINFO` | `faz_fabric_polinfo` — policy info; join via `poluuid = polinfo.uuid` |
| `$ADOMTBL_PLHD_AUDIT_HST` | `faz_fabric_audit_hst` — audit history |
| `$ADOMTBL_PLHD_IOC_VERDICT` | `faz_fabric_ioc_verdict` — IoC verdict data |

**Pattern:** `$ADOMTBL_PLHD_FOO` → `faz_fabric_foo` (lowercased suffix)

**Endpoint join pattern:**
```sql
LEFT JOIN $ADOM_ENDPOINT ep ON (CASE WHEN epid < 1024 THEN NULL ELSE epid END) = ep.epid
LEFT JOIN $ADOM_ENDUSER eu  ON (CASE WHEN euid < 1024 THEN NULL ELSE euid END) = eu.euid
```

**`devtable_ext`** — resolve `dvid` to device name. This is usually unnecessary, because `$log-*` rows already carry `devname`, `devid` and `vd`:
```sql
LEFT JOIN devtable_ext d ON e.dvid = d.dvid
-- columns: dvid, devname, devtype, devid
```

---

## SOC Event and Incident Tables

| Variable | Description | Time filter column |
|---|---|---|
| `$event` | SIEM alerts | `alerttime` |
| `$incident` | SIEM incidents | `createtime` |
| `$event_history` | Pre-aggregated alert counts | `agg_time` |
| `$incident_history` | Pre-aggregated incident counts | `agg_time` |

**`$event` key columns:** `alertid`, `alerttime`, `dvid`, `severity` (0=Critical,1=High,2=Medium,3=Low), `triggername`, `tag`, `epip`, `epname`, `euname`, `subject`, `eventtype`, `groupby1/2/3`, `logcount`, `firstlogtime`, `lastlogtime`, `assignto`

**`$incident` key columns:** `incid` (use `incid_to_str(incid)`), `severity` (String: `critical/high/medium/low`), `status` (`draft/analysis/response/closed/cancelled`), `createtime`, `category`, `endpoint`, `description`, `assigned_to`

**`$event_history` columns:** `agg_time`, `num_sev_critical`, `num_sev_high`, `num_sev_medium`, `num_sev_low`, `num_total`

**`$incident_history` columns:** `agg_time`, `num_sta_draft`, `num_sta_analysis`, `num_sta_response`, `num_sta_closed`, `num_sta_cancelled`, `num_sev_critical`, `num_sev_high`, `num_sev_medium`, `num_sev_low`, `num_endpoint`

```sql
-- Alert severity decode
CASE severity WHEN 0 THEN 'Critical' WHEN 1 THEN 'High' WHEN 2 THEN 'Medium' WHEN 3 THEN 'Low' END

-- Open incidents
SELECT incid_to_str(incid) AS incnum, from_itime(createtime) AS ts, severity, status
FROM $incident
WHERE $cust_time_filter(createtime) AND status NOT IN ('closed','cancelled')
```

---

## `/*fabricStart*/`/`/*fabricEnd*/` Hint

For SOC datasets (`log_category: ""`) that aggregate across all ADOMs. Wraps per-ADOM subquery in a UNION ALL:

```sql
SELECT status, sum(cnt) AS cnt
FROM
  /*fabricStart*/
  (SELECT status, count(*) AS cnt FROM $incident WHERE $filter-drilldown GROUP BY status)
  /*fabricEnd*/
  t
GROUP BY status
```

Do NOT use in `$log-*` datasets — those are already ADOM-scoped via `$filter`.

---

## Multi-Statement Queries (Temp Tables)

```sql
DROP TABLE IF EXISTS rpt_tmptbl_1;
DROP TABLE IF EXISTS rpt_tmptbl_2;

CREATE TEMPORARY TABLE rpt_tmptbl_1 AS
SELECT col FROM ###(...)### t GROUP BY col;

CREATE TEMPORARY TABLE rpt_tmptbl_2 AS
SELECT col FROM ###(...)### t GROUP BY col;

-- Final SELECT (no trailing semicolon)
SELECT t2.col, CASE WHEN t1.col IS NULL THEN 'New' ELSE 'Existing' END AS status
FROM rpt_tmptbl_2 t2
LEFT JOIN rpt_tmptbl_1 t1 ON t2.col = t1.col
```

Rules: always DROP before CREATE, name as `rpt_tmptbl_N`, separate with `;`, final SELECT has no `;`.

---

## Essential Helper Functions

| Function | Use |
|---|---|
| `ipstr(col)` | IPv6 col → clean IPv4/IPv6 string — **always use for display/compare** |
| `nullifna(col)` | Returns NULL if value is `"N/A"`, `"n/a"`, or `"null"` — use on `user`, `app` etc. |
| `coalesce(nullifna(\`user\`), nullifna(\`unauthuser\`), ipstr(\`srcip\`))` | Canonical user identity expression. Tested: the same user can appear in several cases (`jdoe` / `JDOE`) across auth sources, and MAC-based auth puts a MAC address in `user`. Wrapping it in `lower()` merges the case variants but lowercases every name shown. Mention the case variants and ask the user whether to add `lower()` |
| `from_itime(col)` | Unix epoch Int32 → readable datetime string |
| `from_dtime(col)` | Device time → readable datetime string |
| `logid_to_int(logid)` | logid String → Int for numeric compare |
| `root_domain(hostname)` | `mail.google.com` → `google.com` |
| `app_group_name(app)` | App to a service-style group (`DNS`, `HTTP`, `LDAP`, `SNMP`, `TCP_High_Ports`), falling back to `proto/port` such as `tcp/27001` |
| `ip_subnet(col)` | IP to its **fixed /24** as a string, e.g. `192.0.2.57` → `192.0.2.0/24`. It doesn't know the real configured subnet size |
| `isIPAddressInRange(ipstr(col), 'cidr')` | Tests whether an IP is in a CIDR range. Use it to map real subnets in a `CASE` (falling back to `ip_subnet()`) or to filter a range. Tested and working in FAZ |
| `virusid_to_str(virusid)` | Numeric virus ID → string name |
| `incid_to_str(incid)` | Numeric incident ID → `"INC-00042"` |
| `get_devtype(n)` | Numeric device type → string |
| `bandwidth_unit(bytes)` | Bytes → human-readable string (display only) |
| `string_agg(distinct col, ',')` | Concat distinct string values |
| `arrayJoin(array_col)` | Unnest array to rows |
| `has(array_col, 'value')` | Test array membership |
| `split_part(col, ',', 1)` | Nth part after split — for FCT `os` column |
| `left(col, n)` | Truncate string to n chars |
| `JSONExtractString(col, key)` | Extract string from JSON column |
| `arrayStringConcat(JSONExtractKeys(formatRowNoNewline('JSONEachRow', *)), ', ')` | Column names of a log type as one string. Use it `FROM (SELECT * FROM $log-x WHERE $filter LIMIT 1) t`, then UNION ALL several types. Tested and working. `*` hides ALIAS columns, so confirm a "missing" column by selecting it directly |
| `bitAnd(a, b)` / `bitOr(a, b)` | Bitwise operations for logflag |
| `lower(col)` | Lowercase string — use for case-insensitive compare on `utmevent`, `threat`, etc. |
| `regexp_replace(col, pattern, replacement)` | Regex string replacement (e.g. strip OS build suffix) |
| `regexp_extract(col, pattern)` | Extract first regex match — e.g. `regexp_extract(switchphysicalport, '(\\d+)$')` for trailing digits. ClickHouse `extract(col, pattern)` works too (Common Mistakes #11) |
| `timestampDiff('unit', col1, col2)` | Difference between two timestamps; units: `'second'`, `'millisecond'`, `'nanosecond'` |
| `severity_s2i(col)` | Severity string → integer for sort (FCT vulnerability severity) |
| `fct_webcat(threat)` | FortiClient web category from threat field |
| `lagInFrame(col) OVER (PARTITION BY x ORDER BY y ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)` | Previous row value — use for state-change detection in window queries |

---

## Common Query Patterns

Patterns A–F and the time series example above were all tested on FAZ 7.6 (FortiOS 7.2–7.6 logs). The outer query can only use columns the hcache returns, so re-aggregate the hcache's aliases (`sum(bandwidth)`), not the raw log columns. Raw columns there fail with "Missing columns".

### Pattern A: Simple Top-N
```sql
SELECT catdesc, count(*) AS hits
FROM $log-webfilter
WHERE $filter AND action = 'blocked' AND catdesc IS NOT NULL
GROUP BY catdesc
ORDER BY hits DESC
```

### Pattern B: Top-N with HCache
```sql
SELECT user_src, sum(sessions) AS sessions
FROM ###(
    SELECT coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) AS user_src,
           count(*) AS sessions
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,1)>0)
    GROUP BY user_src
    /*SkipSTART*/ORDER BY sessions DESC/*SkipEND*/
)### t
GROUP BY user_src
ORDER BY sessions DESC
```

### Pattern C: Bandwidth Top Users
```sql
SELECT user_src, sum(bandwidth) AS bandwidth
FROM ###(
    SELECT coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) AS user_src,
           sum(coalesce(sentdelta,sentbyte,0)+coalesce(rcvddelta,rcvdbyte,0)) AS bandwidth
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)
    GROUP BY user_src
    /*SkipSTART*/ORDER BY bandwidth DESC/*SkipEND*/
)### t
GROUP BY user_src
ORDER BY bandwidth DESC
```

### Pattern D: Time Series
```sql
SELECT $flex_timescale(timestamp) AS hodex, sum(traffic_out) AS out, sum(traffic_in) AS in
FROM ###(
    SELECT $flex_timestamp AS timestamp,
           sum(coalesce(sentdelta,sentbyte,0)) AS traffic_out,
           sum(coalesce(rcvddelta,rcvdbyte,0)) AS traffic_in
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)
    GROUP BY timestamp
)### t
GROUP BY hodex
HAVING sum(traffic_out+traffic_in) > 0
ORDER BY hodex
```

### Pattern E: IPS Attack with Block Rate
```sql
SELECT attack,
       sum(totalnum) AS totalnum,
       cast(100.0 * sum(blocked) / sum(totalnum) AS decimal(10,2)) AS block_pct
FROM ###(
    SELECT attack,
           count(*) AS totalnum,
           sum(CASE WHEN action NOT IN ('detected','pass_session') THEN 1 ELSE 0 END) AS blocked
    FROM $log-attack
    WHERE $filter AND subtype='ips' AND nullifna(attack) IS NOT NULL
    GROUP BY attack
    /*SkipSTART*/ORDER BY totalnum DESC/*SkipEND*/
)### t
GROUP BY attack
ORDER BY totalnum DESC
```

### Pattern F: Direction-based attacker/victim (IPS)
`direction='incoming'` means the attack flowed server→client, so the victim is `srcip`. Write the CASE inline, because `${THREAT_*}` does not expand in custom datasets.
```sql
SELECT
    ipstr(CASE WHEN direction='incoming' THEN dstip ELSE srcip END) AS attacker,
    ipstr(CASE WHEN direction='incoming' THEN srcip ELSE dstip END) AS victim,
    count(*) AS hits
FROM $log-attack
WHERE $filter AND subtype='ips'
GROUP BY attacker, victim
ORDER BY hits DESC
```

---

## Common Mistakes

1. **Missing `$filter`** — always include on raw log queries
2. **Filter on computed column**: `WHERE user_src IS NOT NULL` on a SELECT alias works on FAZ 7.6 (ClickHouse resolves aliases), but prefer hcache when the result is reused, so the scan is cached
3. **Raw IP display** — always use `ipstr(srcip)`, not raw `srcip`
4. **N/A strings** — use `nullifna(user)` not `user IS NOT NULL`
5. **logflag missing** — traffic queries without `bitAnd(logflag,1)>0` inflate counts
6. **Bandwidth without logflag=32** — use `bitOr(1,32)` to include long-lived sessions
7. **Hardcoded table names** — use `$log-traffic` not `siem.sp1_FGT_tlog`
8. **HAVING vs WHERE** — can't `WHERE sum(x) > 0`, use `HAVING sum(x) > 0`
9. **epid/euid < 1024** — system IDs, null out before joining
10. **`$filter-drilldown` inside hcache** — must go on outer query only
11. **Regex function names** — both the FAZ snake_case helpers (`regexp_extract`, `regexp_replace`) and the ClickHouse names (`extract`, `regexpExtract`, `replaceRegexpOne`, `replaceRegexpAll`, `match`) work in the dataset test (FAZ 7.6, tested October 2026). `regexExtract` doesn't exist in either.
12. **Outer ORDER BY on an inner-only column** — outer ORDER BY may only use final SELECT names or aggregates of them (`ORDER BY sum(totalnum)`). FAZ re-applies it in a merge step that only sees output columns: the dataset test passes, but the report fails with `MERGE: ... Missing columns`. Sort by the output alias
13. **`WITH TOTALS`** — not supported: the query fails with `unimplemented 7`. Compute the total in a separate query or with `UNION ALL`
14. **Grouping by a boolean from a `LowCardinality` column** — `GROUP BY match(classifier, 'x')` or a `LIKE` result fails with `LowCardinality(UInt8) is not supported`. Cast the column first: `match(CAST(ifNull(col, '') AS String), 'x')`, or group by an `if(..., 'yes', 'no')` built on the cast value
15. **Macros resolve within the dataset's device type** — `$log-<type>` always maps to a table of the selected device type, and some names are aliases (with FortiMail selected, `$log-malware` is FortiMail's `virus` table). A query that runs doesn't prove it read the table you meant. With `$log-` macros, one dataset can't join logs of two device types
16. **An alias that matches a real column** — ``SELECT `user` AS admin ... GROUP BY admin`` fails on FortiGate event logs with ``Column `user` is not under aggregate function``, because `admin` is also a column and `GROUP BY` takes the column. Pick aliases that aren't column names (`admin_user`), or group by the expression

---

## Canonical Enum Values (FortiOS)

This is the authoritative list for closed-set fields. The "Real Values Discovered" sections in the column files are samples from one environment and time window. Use them as examples, not as complete sets.

### `action` (traffic): `accept`, `deny`, `close`, `drop`, `server-rst`, `client-rst`, `timeout`, `ip-conn`
### `action` (UTM): `passthrough`, `blocked`, `detected`, `block`, `pass`, `pass_session`, `reset`, `dropped`
### `utmaction` (traffic): `allow`, `block`, or empty when no UTM was involved. These were the only values on FortiOS 7.2.10, 7.4.12 and 7.6.7 (~160 M rows). Other log types and FortiClient logs may use `passthrough` and other values
### `utmevent`: always NULL in FortiGate traffic logs (FortiOS doesn't send it). Filter on `countX>0` instead (see UTM event macros)
### `apprisk`: `critical`, `high`, `elevated`, `medium`, `low`
### `direction` (UTM/IPS logs): `incoming`, `outgoing`. Traffic logs have **no** `direction` column
### `subtype` (attack): `ips`, `anomaly`
### `level`: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `information`, `debug`
### `subtype` (traffic): `forward`, `local`, `multicast`, `sniffer`, `ztna`
### `subtype` (event): `system`, `router`, `vpn`, `user`, `endpoint`, `ha`, `compliance`, `connector`, `wad`, `wanopt`, `wireless`, `netscan`, `security-rating`
### `proto` (UInt8): `1`=ICMP, `6`=TCP, `17`=UDP, `47`=GRE, `50`=ESP, `89`=OSPF

---

## Column Type Gotchas

- **IP columns** (`srcip`, `dstip`): `Nullable(IPv6)` — IPv4 stored as `::ffff:192.168.1.1`. Always `ipstr()`.
- **`sentbyte` vs `sentdelta`**: use `coalesce(sentdelta, sentbyte, 0)` — delta for long-lived, byte for closed sessions. `sentbyte` is cumulative on interim logs. In testing, `sum(sentbyte)` alone came out ~1,600× too high.
- **`itime` vs `dtime`**: `$filter` filters on `itime`; use `from_dtime(dtime)` for device-local time display.
- **`logid`**: `LowCardinality(String)` — use `logid_to_int(logid)` for numeric compare.
- **`N/A` sentinels**: `user`, `unauthuser`, `app` columns use `"N/A"` instead of NULL — always `nullifna()`.
- **`epid`/`euid` < 1024**: system-reserved, meaningless for joins — guard with `CASE WHEN epid < 1024 THEN NULL`.
- **`fct-event` logid**: `UInt64` not String — do NOT use `logid_to_int()`.

---

## logid Reference (FortiGate Events)

`logid` is a 10-digit string such as `0100032001`: two digits log type (`01` event, `02` antivirus, `15` DNS), two digits subtype, then the message ID. `logid_to_int(logid)` returns the message ID (`32001`), so `logid = '32001'` matches nothing; prefer the full string. This is a **selection**, not a complete list: the meanings follow the FortiOS 7.6.4 Log Message Reference, with notes from real logs added, and the last column says whether the logid occurred in real logs on two FAZ 7.6 instances. For the complete list of your version, see the FortiOS Log Message Reference ("Log ID numbers"); for what your FAZ logs, group `$log-event` by `logid, logdesc`. The full map by topic is in [fortigate-logmodel.md](fortigate-logmodel.md).

| logid | Short | Category | Meaning | Seen in logs |
|---|---|---|---|---|
| `0100032001` / `0100032002` / `0100032003` | `32001` / `32002` / `32003` | Admin | Admin login successful / failed / logout | yes |
| `0100032021` | `32021` | Admin | Admin login disabled after failed attempts (source IP only in `msg`) | yes |
| `0100044547` / `0100044546` | `44547` / `44546` | Config | Object attribute / attribute configured: any config change, by an admin or FortiManager | yes |
| `0100026001` / `0100026002` / `0100026003` | `26001` / `26002` / `26003` | DHCP | DHCP ack / release / statistics | yes |
| `0100020099` | `20099` | Interface | Interface status changed (interface name only in `msg`) | yes |
| `0100022105` / `0100022107` / `0100022108` / `0100022109` | `22105` / `22107` / `22108` / `22109` | Hardware | Power supply failed / voltage anomaly / fan anomaly / temperature too high | no |
| `0100022106` | `22106` | Hardware | Optional power supply not detected | yes |
| `0108037892` | `37892` | HA | Virtual cluster member state moved (failover) | yes |
| `0108035011` / `0108035012` / `0108035013` | `35011` / `35012` / `35013` | HA | HA secondary synchronization failed / secondary sync failed / HA failover failed | no |
| `0113022933` / `0113022925` | `22933` / `22925` | SD-WAN | SLA notification (state change) / SLA information (measurements) | yes |
| `0113022936` / `0113022938` | `22936` / `22938` | SD-WAN | Internet service passive quality information / bandwidth monitoring result | no |
| `0101039424` / `0101039947` | `39424` / `39947` | VPN | SSL VPN tunnel up, `ssl-web` / `ssl-tunnel` (one tunnel-mode login writes both) | yes |
| `0101037138` | `37138` | VPN | IPsec connection status changed (tunnel up/down) | yes |
| `0104043551` | `43551` | WiFi | Physical AP join | yes |
| `0104043630` / `0104043629` | `43630` / `43629` | WiFi | Client RADIUS authentication success / failure | yes |
| `0201009233` | `9233` | Antivirus log | File submitted to Sandbox (`$log-virus`, not event) | yes |
| `1501054200` | `54200` | DNS log | DNS resolution error (`$log-dns`, not event) | yes |

Config change filter: `WHERE $filter AND cfgtid > 0`

---

## Quick Reference Card

```
Log sources:     $log-traffic  $log-webfilter  $log-app-ctrl  $log-attack
                 $log-virus  $log-event  $log-dns  $log-dlp
                 $log-emailfilter  $log-fct-traffic  $log-fct-event  $log-file-filter

Filters:         $filter                        (always required on raw logs)
                 $dev_filter                    (device only, no time)
                 $last3day_period $filter        (3-day lookback)
                 $pre_period                    (previous period comparison)
                 $cust_time_filter(alerttime)   (SOC tables)

Time:            $flex_timestamp               (inner GROUP BY — integer bucket)
                 $flex_timescale(col)          (outer SELECT — formatted)
                 $hour_of_day                  (hour 0–23)
                 $day_of_week / $DAY_OF_MONTH

HCache:          ###(inner)### t               (anonymous)
                 ###base(/*tag:lbl*/...)base### (named/shared)
                 /*SkipSTART*/ORDER BY.../*SkipEND*/

User identity:   coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`))
Bytes:           coalesce(sentdelta,sentbyte,0)  /  coalesce(rcvddelta,rcvdbyte,0)
IP display:      ipstr(`srcip`)
logflag:         bitAnd(logflag,1)>0   /   bitAnd(logflag,bitOr(1,32))>0

ADOM tables:     $ADOM_ENDPOINT  $ADOM_ENDUSER  $ADOM_EPEU_DEVMAP
                 $ADOMTBL_PLHD_POLINFO
SOC tables:      $event (alerttime)  $incident (createtime)
                 $event_history  $incident_history

Fabric hint:     /*fabricStart*/ (per-ADOM subquery) /*fabricEnd*/
Avoid:           ebtr_agg_flat()  ebtr_value()  — NOT installed

Macros:          confirmed in custom datasets: ${REPORT_SESSION}, ${REPORT_SESSION_WITH_LONGLIVE}, ${BLOCKED_ACTION}. Write others inline
Identity macros: ${USER}  ${USER_SRC}  ${EP_SRC}  ${SAAS_USER}
Severity macros: ${LEVEL2SEVID} (fails — write inline), ${SEVID2SEVERITY}  ${EVENTSEV2STR}  ${FCTVULNSEV2ID} (unverified)
IPS direction:   inline CASE on direction='incoming' (${THREAT_*} not expanded in custom datasets)
```

---

## Grammar — Supported SQL Features

The FAZ SQL dialect (ANTLR4 grammar) supports:

**Statements:** SELECT, CREATE TEMPORARY TABLE, DROP TABLE, INSERT, UPDATE

**Query structure:** UNION [ALL], WITH (CTE), subqueries, VALUES

**Clauses:** SELECT [DISTINCT], FROM, JOIN (INNER/LEFT/RIGHT/FULL + ARRAY JOIN), WHERE, GROUP BY, HAVING, ORDER BY, LIMIT, OFFSET, SAMPLE, FOR

**Expressions:** arithmetic (+,-,*,/), bitwise (AND/OR), comparisons (=,<,>,<=,>=,<>,!=), IS [NOT] NULL, LIKE, IN, BETWEEN, EXISTS, NOT, AND, OR, CASE WHEN...END

**Functions:** scalar functions, aggregate functions, window functions (with OVER, PARTITION BY, frame clauses), higher-order functions (arrayMap, arrayFilter etc.), TRIM, SUBSTRING, quantile functions

**Type casting:** CAST(x AS type), `::type` shorthand, VARCHAR, DECIMAL types

**Other:** JSON attribute access, array constructors, subscript access, column aliases, table aliases

**Not supported:** `WITH TOTALS` (fails with `unimplemented 7`). Tested and working: `WITH` CTEs, scalar subqueries in SELECT, `quantile`/`quantileIf`/`quantileExact`, window functions with `PARTITION BY`, `ARRAY JOIN`, `uniqExact`/`uniqExactIf`, `cityHash64`

---

## Real Query Examples (from predefined datasets)

### Top IPS victims (built-in)
```sql
SELECT victim, sum(totalnum) AS totalnum
FROM ###(
    SELECT (CASE WHEN direction='incoming' THEN ipstr(dstip) ELSE ipstr(srcip) END) AS source,
           (CASE WHEN direction='incoming' THEN ipstr(srcip) ELSE ipstr(dstip) END) AS victim,
           count(*) AS totalnum
    FROM $log
    WHERE $filter-exclude-var
    GROUP BY source, victim
    ORDER BY totalnum DESC
)### t
WHERE $filter-drilldown AND victim IS NOT NULL
GROUP BY victim
ORDER BY sum(totalnum) DESC
```
Custom-dataset equivalent, tested and working: use `$log-attack` and `WHERE $filter`, and drop `$filter-drilldown`.

### Window function — SD-WAN device down time tracking
Structure from a built-in dataset. `logdev_id` and logids `220001`/`220002` don't exist in FortiGate event logs ("Missing columns"), so for FortiGate use `devid` and the link up/down logids of your environment. The nesting below was tested on FAZ 7.6 with `devid` and FortiGate event logs.
```sql
SELECT devid, link_status,
    (CASE WHEN link_status=0 THEN sum(etime-stime) END) AS down_time
FROM (
    SELECT devid, status_rank, max(link_status) AS link_status,
           min(timestamp) AS stime, max(timestamp) AS etime
    FROM (
        SELECT devid, timestamp, link_status,
            sum(abs(coalesce(status_switch, 0)))
                OVER (PARTITION BY devid ORDER BY timestamp
                      ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS status_rank
        FROM (
            SELECT timestamp, devid, link_status,
                link_status - lagInFrame(link_status)
                    OVER (PARTITION BY devid ORDER BY timestamp
                          ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS status_switch
            FROM (
                SELECT itime AS timestamp, logdev_id AS devid,
                    (CASE WHEN logid='220002' THEN 1 ELSE 0 END) AS link_status
                FROM $log
                WHERE $filter AND logid_to_int(logid) IN (220001, 220002)
            ) t1
        ) t2
    ) t3
    WHERE status_rank IS NOT NULL
    GROUP BY devid, status_rank
    HAVING min(timestamp) != max(timestamp)
) t4
GROUP BY devid, link_status
ORDER BY down_time DESC
```

### Conditional aggregation — cache hit rate
```sql
SELECT root_domain(hostname) AS host,
    sum(CASE WHEN resptype='cached' THEN 1 ELSE 0 END) AS cache_num,
    sum(CASE WHEN resptype IN ('normal','generated') THEN 1 ELSE 0 END) AS normal_num
FROM $log
WHERE $filter AND hostname IS NOT NULL AND subtype='http-transaction'
GROUP BY host
ORDER BY cache_num DESC, normal_num DESC
```

### Response time comparison — nanosecond precision
```sql
SELECT root_domain(hostname) AS host,
    sum(CASE WHEN resptype='cached'
        THEN timestampDiff('nanosecond', reqtime, respfinishtime) ELSE 0 END) AS cache_time,
    sum(CASE WHEN resptype IN ('normal','generated')
        THEN timestampDiff('nanosecond', reqtime, respfinishtime) ELSE 0 END) AS normal_time
FROM $log
WHERE $filter AND hostname IS NOT NULL AND subtype='http-transaction'
GROUP BY host
ORDER BY cache_time DESC
```

### Daily average using $days_num
```sql
SELECT cast(sum(sessions)/$days_num AS decimal(18,0)) AS ave_session
FROM ###(
    SELECT $flex_timestamp AS timestamp, subtype, src, dst,
           count(*) AS sessions,
           sum(ibytes+obytes) AS bandwidth
    FROM $log
    WHERE $filter
    GROUP BY timestamp, subtype, src, dst
    ORDER BY sessions DESC, bandwidth DESC
)### t
WHERE subtype='slb_http'
```

### FCT regex — strip OS build suffix
```sql
SELECT uid AS fctuid,
    regexp_replace(os, '\\(build.*', '') AS os_short,
    fctver, subtype, fgtserial
FROM $log
WHERE $filter AND subtype != 'admin'
GROUP BY uid, os_short, fctver, subtype, fgtserial
```

### Severity classification with sort key
```sql
SELECT devid, vulnname, vulnseverity,
    severity_s2i(vulnseverity) AS severity_level,
    vulnid
FROM $log
WHERE $filter AND vulnname IS NOT NULL
GROUP BY devid, vulnname, vulnseverity, severity_level, vulnid
ORDER BY severity_level DESC
```

### FortiClient web category
```sql
SELECT fct_webcat(threat) AS category,
    remotename AS website,
    count(*) AS requests
FROM $log
WHERE $filter AND direction='outbound' AND threat IS NOT NULL
    AND utmaction='passthrough' AND lower(utmevent)='webfilter'
GROUP BY category, website
ORDER BY requests DESC
```
