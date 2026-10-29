# Materialized Views (`fv_*`)

Pre-aggregated AggregatingMergeTree tables maintained automatically by ClickHouse as logs are ingested. Used by built-in dashboard datasets for fast time-series charts. **Not available in custom report datasets** — for reference when reading built-in datasets only.

---

## Naming Convention

```
fv_{devtype}_{logtype}_{metric}_{interval}_{sp}
```

| Segment | Values |
|---|---|
| `devtype` | `fgt`, `ffw`, `fct`, `fpx`, `fwb`, `fml`, `fdd`, `sim` |
| `logtype` | `t` (traffic), `e` (event), `X` (SOC/extended) |
| `metric` | `src_dst`, `ipsec`, `sifv`, etc. |
| `interval` | `5min`, `hour`, `day` |
| `sp` | Service partition, e.g. `sp1` |

**Examples:**
- `fv_fgt_t_src_dst_5min_sp1` — FortiGate traffic, 5-min buckets
- `fv_fgt_t_src_dst_hour_sp1` — FortiGate traffic, hourly buckets
- `fv_ffw_e_ipsec_day_sp1` — FortiFirewall event, daily buckets (`fpx` is FortiProxy)
- `fv_sim_X_sifv_hour_sp1` — SOC/integrated, hourly buckets

> Views only exist for device types that have sent logs. Check availability:
> ```sql
> SELECT name FROM system.tables WHERE database='siem' AND name LIKE 'fv_%';
> ```

---

## Common Columns (traffic views: `fv_fgt_t_src_dst_*`)

| Column | Description |
|---|---|
| **`timescale`** | Pre-bucketed timestamp integer — use `$fv_line_timescale(timescale)` for display (NOT `$flex_timescale`) |
| **`traffic_in`** | Bytes received (aggregated) |
| **`traffic_out`** | Bytes sent (aggregated) |
| **`sessions`** | Session count |
| `agg_time` | Alternate name for `timescale` in some views |

> **Key difference:** Use `$fv_line_timescale(timescale)` — not `$flex_timescale()`. The column is already pre-bucketed by the view, not raw `itime`.

---

## Standard Query Pattern

Dashboards typically UNION multiple granularities so the right resolution is used based on the selected time range:

```sql
SELECT
    $fv_line_timescale(timescale) AS time,
    sum(traffic_in) AS traffic_in,
    sum(traffic_out) AS traffic_out,
    sum(sessions) AS sessions
FROM (
    (SELECT timescale,
            sum(traffic_in) AS traffic_in,
            sum(traffic_out) AS traffic_out,
            sum(sessions) AS sessions
     FROM fv_fgt_t_src_dst_5min_sp1
     WHERE $filter
     GROUP BY timescale)
    UNION ALL
    (SELECT timescale,
            sum(traffic_in) AS traffic_in,
            sum(traffic_out) AS traffic_out,
            sum(sessions) AS sessions
     FROM fv_fgt_t_src_dst_hour_sp1
     WHERE $filter
     GROUP BY timescale)
) combined
GROUP BY time
ORDER BY time
```
