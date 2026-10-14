# FortiOS Version Differences in FAZ Logs

- **FAZ owns the schema.** Every FortiGate in an ADOM gets the same columns, whatever its FortiOS version. "Missing columns" is never a FortiOS issue; fix the column name.
- **FortiOS fills the columns.** An older FortiOS leaves newer fields NULL or `''`. The query runs, but those devices contribute nothing for those fields.
- **Empty usually means configuration, not version.** Identity (FSSO/EMS), ZTNA, shaping and DNS filter columns are empty wherever the feature is off. Only the fields below are version-gated.

## Version-gated fields

| Log type | Fields | Sent from FortiOS |
|---|---|---|
| traffic | `durationdelta`, `sentpktdelta`, `rcvdpktdelta` | 7.4 |
| traffic | `srczone`, `dstzone`, `emstag`, `emstag2`, `vipincomingip`, `tcpnrt`, `tcpsrt`, `tcporgrtrs`, `tcprplrtrs`, `tcpsynrtrs`, `tcpsynackrtrs`, `tcprst`, `tunnelsessionid`, `tunnelproto`, `tunnelsrcip`, `tunneldstip` | 7.6 (zones and TCP metrics only when the feature is configured) |
| app-ctrl | `aiuser`, `cloudgenai`, `dcgeo`, `model`, `prompt`, `usecase` (GenAI), `srczone`, `dstzone` | 7.6.4 |
| app-ctrl | `messageid`, `transid` | 7.6 |
| ssl | `srcmac`, `srcname`, `transid` | 7.6 |

When a query uses these fields:

- **Packet or duration totals:** use `coalesce(sentpktdelta, sentpkt, 0)` and `coalesce(durationdelta, duration, 0)`. On FortiOS 7.2 the deltas are NULL, so long-lived sessions are overcounted there; tell the user if FortiGates are older than 7.4. Byte deltas (`sentdelta`, `rcvddelta`) exist on all versions, so `coalesce(sentdelta, sentbyte, 0)` is always correct.
- **GenAI or zone reports:** warn that older FortiGates report nothing. For mixed estates, group by `srcintf`/`dstintf` instead of zones.

## `logver` = FortiOS version

`logver` packs major, minor, patch and a 4-digit build: `706073704` = 7.6.7 build 3704, `704122902` = 7.4.12 build 2902. Compare it numerically:

```sql
-- FortiGates on FortiOS 7.4 or later
WHERE $filter AND logver >= 704000000

-- Which FortiOS versions log into this ADOM?
SELECT intDiv(logver, 100000000) AS major,
       intDiv(logver, 1000000) % 100 AS minor,
       intDiv(logver, 10000) % 100 AS patch,
       logver % 10000 AS build,
       count(DISTINCT devid) AS devices
FROM $log-traffic
WHERE $filter
GROUP BY major, minor, patch, build
ORDER BY major, minor, patch
```

Behaviour that is the same on every version (`utmevent` always NULL in traffic, SSL `tlsver`/`cipher`, macro status) is documented in faz-sql-reference.md and the column files.
