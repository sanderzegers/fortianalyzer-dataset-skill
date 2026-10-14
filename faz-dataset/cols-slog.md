# `$log-attack` — IPS / Intrusion Prevention

All common columns apply (see cols-common.md).

> **`$log-attack` holds two kinds of rows.** `subtype='ips'` rows are IPS signature hits (logid 0419016384 and similar). `subtype='anomaly'` rows are DoS-policy anomalies such as `udp_flood` (logid 0720018432/0720018433). On one test site, anomalies were about 94 % of the rows. **Add `subtype='ips'` to IPS reports** and `subtype='anomaly'` to DoS reports. `$log-anomaly` is not a separate table: it returns the same rows as `$log-attack`.

| Column | Type | Description |
|---|---|---|
| **`attack`** | LowCardinality(String) | Attack/signature name — use `nullifna()` |
| **`attackid`** | Nullable(UInt32) | Numeric attack ID |
| **`severity`** | LowCardinality(String) | `critical`, `high`, `medium`, `low`, `info`, `debug` |
| **`direction`** | LowCardinality(String) | `incoming`, `outgoing` |
| `ref` | Nullable(String) | External reference URL |
| `attackcontext` | Nullable(String) | Attack context data |
| `attackcontextid` | Nullable(String) | Attack context ID |
| `count` | Nullable(UInt32) | Hit count. Anomaly rows only (aggregated DoS events) |
| `threat` | LowCardinality(String) | Threat name. Anomaly rows only |
| `threattype` | LowCardinality(String) | Threat type (`ips` on anomaly rows, empty on IPS signature rows) |
| `threatlevel` | Nullable(Int8) | Numeric threat level. Anomaly rows only |
| `icmpid` / `icmptype` / `icmpcode` | Nullable(String) | ICMP fields for ICMP-based attacks |
| **`action`** | LowCardinality(String) | `detected`, `blocked`, `dropped`, `reset`, `pass_session` |

## Key Patterns

```sql
-- Blocked = action NOT IN ('detected','pass_session')
sum(CASE WHEN action NOT IN ('detected','pass_session') THEN 1 ELSE 0 END) AS blocked

-- Victim/attacker based on direction
CASE WHEN direction='incoming' THEN ipstr(srcip) ELSE ipstr(dstip) END AS victim
CASE WHEN direction='incoming' THEN ipstr(dstip) ELSE ipstr(srcip) END AS attacker

-- Top attacks with block rate
SELECT attack,
       sum(totalnum) AS totalnum,
       cast(100.0 * sum(blocked) / sum(totalnum) AS decimal(10,2)) AS block_pct
FROM ###(
    SELECT attack,
           count(*) AS totalnum,
           sum(CASE WHEN action NOT IN ('detected','pass_session') THEN 1 ELSE 0 END) AS blocked
    FROM $log-attack
    WHERE $filter AND nullifna(attack) IS NOT NULL
    GROUP BY attack
    /*SkipSTART*/ORDER BY totalnum DESC/*SkipEND*/
)### t
GROUP BY attack
ORDER BY totalnum DESC
```

## Real Values Discovered from FAZ Instance

### `action` (Attack Action)

> **Suspect sample:** these match traffic-log actions, not IPS actions, and the discovery query probably hit the wrong table. Use the schema values above (`detected`, `blocked`, `dropped`, `reset`, `pass_session`) for filters and block-rate logic.

| Value | Notes |
|---|---|
| `accept` | Accepted |
| `block` | Blocked |
| `close` | Closed |
| `drop` | Dropped |
| `pass` | Passed |

### `severity` (Severity)

Observed from FAZ attack logs:

| Value | Notes |
|---|---|
| `critical` | Critical severity |
| `high` | High severity |
| `medium` | Medium severity |
| `low` | Low severity |
| `informational` | Informational — the schema lists `info`; match both with `severity IN ('info','informational')` |

### `level` (Attack Level)

| Value | Notes |
|---|---|
| `information` | Informational |

### Additional `action` Values (from attack logs)

Observed from FAZ attack logs:

| Value | Notes |
|---|---|
| `dropped` | Packet dropped |
| `detected` | Attack detected but not blocked |

### `threat` (Threat Name)

Observed threat names from FAZ attack logs:

| Value | Notes |
|---|---|
| `udp_flood` | UDP flood attack |

### `threattype`

| Value | Notes |
|---|---|
| `ips` | Intrusion Prevention System |

### `attack` (Attack Name) — Additional Values

Observed from FAZ attack logs:

| Value | Notes |
|---|---|
| `VACRON.CCTV.Board.CGI.cmd.Parameter.Command.Execution` | CCTV board CGI exploit |
| `ZGrab.Scanner` | ZGrab network scanner |
| `udp_flood` | UDP flood (most common) |

### `ref` (Reference URL)

Observed reference URLs from FAZ attack logs:

| Pattern | Notes |
|---|---|
| `http://www.fortinet.com/ids/VID{NUM}` | Fortinet IDS database reference |
| `https://fortiguard.fortinet.com/encyclopedia/ips/{NUM}` | FortiGuard IPS encyclopedia |

