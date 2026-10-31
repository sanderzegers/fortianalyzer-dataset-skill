# FortiAnalyzer 7.6.8 verification notes

Reviewed against a lab appliance reporting 7.6.8 build 3788 and ClickHouse 25.8.15.35 on 2026-10-31. This is an incremental documentation correction, not certification of every retained example.

## Evidence checked

- GUI report handlers submit, poll, and cancel asynchronous JSON-RPC queries. FazReportSQL.parseFazKeyword extracts chart/macro names from HTML; it is not the claimed SQL-variable expander.
- ClickHouse metadata confirms log views, PostgreSQL proxy tables, and aggregate-state dashboard tables. PostgreSQL hcache_query/ref/res contain cache metadata; hcache_res does not contain arbitrary dataset result rows.
- Installed helper definitions and live SQL checks confirm nullifna sentinels, incident ID formatting, log-ID conversion, severity mapping, split_part, and fct_webcat behavior. Live rewriter probes distinguish plain and DISTINCT string_agg.
- A synthetic LEFT JOIN demonstrated the need for an explicitly nullable match marker under join_use_nulls=false.
- Raw SOC count and countMerge totals at five-minute, hourly, and daily resolutions each returned 515. Combining overlapping resolutions would duplicate the events.
- Traffic aggregate sumMerge SQL executed but returned no rows. FortiGate event logs were also empty. Empty results do not validate traffic metrics.
- Function catalog inspection found arrayJoin, but not array_join, regexp_replace, ebtr_agg_flat, or ebtr_value.

## Remaining verification

Report variable expansion and time boundaries; hcache lifetime/reuse/truncation and SkipSTART; multi-statement execution; Fabric and drilldown semantics; remaining enums/log-ID mappings; representative populated traffic examples; diagram rendering and all cross-references.

The local report API responded to probes, but a complete report query was not demonstrated. Direct ClickHouse results do not establish GUI/report behavior. Legacy references to observed log IDs were not reproduced during this review.

## Operational notes

A temporary localhost-only read-only ClickHouse account was used with user authorization. Its configuration and credential files were removed at the end of the session. No existing accounts were changed and no log data was inserted or modified.
