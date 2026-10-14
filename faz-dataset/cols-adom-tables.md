# ADOM Reference Table Columns

These are FAZ-managed lookup tables, not ClickHouse log tables. They are backed by PostgreSQL and accessed via ClickHouse proxy tables. Use in JOINs against log data.

---

## `$ADOM_ENDPOINT` — Endpoint Inventory

Backed by `faz_fabric_endpoints`. Join key: `epid`. **Always filter `epid > 1024`** (values < 1024 are system-reserved).

| Column | Description |
|---|---|
| **`epid`** | Endpoint ID (join key) |
| **`epname`** | Endpoint hostname |
| **`epip`** | Endpoint IP (as string) |
| `epmac` | MAC address |
| `eptype` | Endpoint type |
| `dvid` | Device ID |
| **`osname`** | OS name |
| `firstseen` | First seen timestamp (Unix epoch) |
| **`lastseen`** | Last seen timestamp (Unix epoch) |

```sql
-- Enrich log data with endpoint name
SELECT coalesce(ep.epname, ipstr(t.srcip)) AS src_host,
       sum(bandwidth) AS bandwidth
FROM ###(
    SELECT srcip,
           (CASE WHEN epid < 1024 THEN NULL ELSE epid END) AS ep_id,
           sum(coalesce(sentdelta,sentbyte,0)+coalesce(rcvddelta,rcvdbyte,0)) AS bandwidth
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)
    GROUP BY srcip, ep_id
    /*SkipSTART*/ORDER BY bandwidth DESC/*SkipEND*/
)### t
LEFT JOIN $ADOM_ENDPOINT ep ON t.ep_id = ep.epid
GROUP BY src_host
ORDER BY bandwidth DESC
```

---

## `$ADOM_ENDUSER` — End User Registry

Backed by `faz_fabric_endusers`. Join key: `euid`. **Always filter `euid > 1024`**.

| Column | Description |
|---|---|
| **`euid`** | End user ID (join key) |
| **`euname`** | Username |
| `euip` | User IP |
| **`eugroup`** | User group — use `coalesce(eugroup, 'Unknown')` for unknown groups |
| `firstseen` | First seen timestamp (Unix epoch) |
| **`lastseen`** | Last seen timestamp (Unix epoch) |

---

## `$ADOM_EPEU_DEVMAP` — Endpoint/User to Device Mapping

| Column | Description |
|---|---|
| **`epid`** | Endpoint ID |
| **`euid`** | End user ID |
| `dvid` | Device ID |

---

## `$ADOMTBL_PLHD_POLINFO` — Policy Info

| Column | Description |
|---|---|
| `uuid` | Policy UUID — join via `poluuid = polinfo.uuid` |
| **`name`** | Policy name |

```sql
LEFT JOIN $ADOMTBL_PLHD_POLINFO polinfo ON t.poluuid = polinfo.uuid
```

---

## `devtable_ext` — Device Table (for SOC/event queries)

Use to resolve numeric `dvid` to a human-readable device name. Available in all queries.

| Column | Description |
|---|---|
| **`dvid`** | Device ID (join key — matches `dvid` on log rows and `$event`) |
| **`devname`** | Device display name |
| `devtype` | Device type string |
| `devid` | Device serial/identifier string |

```sql
LEFT JOIN devtable_ext d ON log.dvid = d.dvid
```

---

## Full Endpoint + Enduser Join Pattern

```sql
SELECT
    coalesce(f_user, eu.euname, ipstr(log_data.srcip)) AS user_src,
    coalesce(ep.epname, ipstr(log_data.srcip)) AS ep_src,
    sum(bandwidth) AS bandwidth
FROM (
    SELECT srcip, f_user,
           (CASE WHEN epid < 1024 THEN NULL ELSE epid END) AS ep_id,
           (CASE WHEN euid < 1024 THEN NULL ELSE euid END) AS eu_id,
           sum(bandwidth) AS bandwidth
    FROM ###(
        SELECT srcip,
               coalesce(nullifna(`user`), nullifna(`unauthuser`)) AS f_user,
               epid, euid,
               sum(coalesce(sentdelta,sentbyte,0)+coalesce(rcvddelta,rcvdbyte,0)) AS bandwidth
        FROM $log-traffic
        WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)
        GROUP BY srcip, f_user, epid, euid
        /*SkipSTART*/ORDER BY bandwidth DESC/*SkipEND*/
    )### t
    GROUP BY srcip, f_user, ep_id, eu_id
) log_data
LEFT JOIN $ADOM_ENDPOINT ep ON log_data.ep_id = ep.epid
LEFT JOIN $ADOM_ENDUSER eu  ON log_data.eu_id  = eu.euid
GROUP BY user_src, ep_src
ORDER BY bandwidth DESC
```
