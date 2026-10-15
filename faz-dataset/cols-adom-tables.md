# ADOM Reference Table Columns

These are FAZ-managed lookup tables, not ClickHouse log tables. They are backed by PostgreSQL and accessed via ClickHouse proxy tables. Use in JOINs against log data. They are ADOM-wide, so a dataset of any device type can join them.

---

## UEBA: FAZ's endpoint and user identification

`$ADOM_ENDPOINT`, `$ADOM_ENDUSER` and `$ADOM_EPEU_DEVMAP` are FAZ's UEBA data (Fabric View > Asset Identity Center). They aren't sent by any device: **FAZ derives them from the logs it receives** (plus optional connectors) and stamps every log row it can identify with `epid` (endpoint) and `euid` (end user). Treat them as FAZ's interpretation. **The device log fields are the source of truth** (`srcip`, `srcmac`, `user`/`unauthuser`, FortiGate `fctuid`, FortiClient `uid`); use `epid`/`euid` as a convenient key and check a finding against those fields.

**Data sources** (per ADOM, Fabric View > Asset Identity Center; [FAZ 7.6.4 admin guide](https://docs.fortinet.com/document/fortianalyzer/7.6.4/administration-guide/184956/configuring-endpoint-and-end-user-data-sources)): FortiGate, FortiClient, FortiWeb and FortiNAC logs are **on** by default (rules can exclude devices and subnets); FortiMail logs and the EMS connector are **off** by default. A disabled source gets no identification, so whether `epid`/`euid` are filled depends on FAZ configuration, not on the device.

**How endpoints are formed** (same guide): with FortiClient and EMS data, all interfaces of a device become one endpoint keyed by the FortiClient UID; without FortiClient, **each network interface is a separate endpoint**. `detecttype` in `$ADOM_ENDPOINT` says which: `by_mac`, `by_fctuid`, `by_sno` (serial number), `unknown`.

**Values below 1024 are reasons, not IDs** ([FAZ 7.6.4: User and endpoint ID log fields](https://docs.fortinet.com/document/fortianalyzer/7.6.4/administration-guide/564377/user-and-endpoint-id-log-fields)): `1` device type not supported, `2` log type not supported, `3` not enough information, `4` UID range exhausted, `5`–`8` internal / HA errors, `10` log version not supported, `100` local host event, `101` public IP on a non-LAN interface, `102` log ID not identified, `103` too many IPs on one MAC, `104` VPN IP not tracked. Seen in real logs but **undocumented**: `105` and `109`. Filter real IDs with `epid > 1024` / `euid > 1024`, and group by the code to see why rows have none.

**Measured on two FAZ 7.6 instances** (October 2026):

| Logs | `epid` real ID | `euid` real ID | Codes on the rest |
|---|---|---|---|
| FortiGate traffic | 81 % / 43 % | 54 % / 3 % | `3`, `104`, `105` |
| FortiClient traffic | 100 % | 94 % | |
| FortiAuthenticator event | rare | 76 % (users, although FortiAuthenticator isn't a listed data source) | `3`, `104`, `109` |
| FortiMail history | 0 % | 0 % | `3`, `105` (FortiMail source off by default) |
| FortiWeb attack | 0 % | 0 % | `3`, `104` (internet clients) |

- **Consistent across device types:** the same endpoint had the same `epid` in FortiClient and FortiGate logs (78 of 78 and 48 of 48 endpoints, matched by FortiClient `uid` = FortiGate `fctuid`), and the same user name had the same `euid` in FortiAuthenticator and FortiGate logs (9 of 9).
- **Complete in the tables:** every `epid` seen in FortiGate traffic existed in `$ADOM_ENDPOINT` with a name (3,400 of 3,400 and 292 of 292).

---

## `$ADOM_ENDPOINT` — Endpoint Inventory

Backed by `faz_fabric_endpoints`. Join key: `epid`. **Always filter `epid > 1024`**. Columns identical on two FAZ 7.6 instances.

| Column | Description |
|---|---|
| **`epid`** | Endpoint ID (join key) |
| **`epname`** | Endpoint name (hostname; an IP-like name when no hostname is known) |
| **`epip`** | Endpoint IP |
| `mac` | MAC address |
| `macipcount` | Number of IPs seen on the MAC |
| **`fctuid`** | FortiClient UID, filled when the endpoint is identified through FortiClient/EMS |
| `detecttype` | `by_mac`, `by_fctuid`, `by_sno`, `unknown` |
| `detectkey` | The value behind `detecttype` |
| `epdevtype` | Device type |
| **`osname`** / `osversion` | Operating system |
| `ownereuname` | Owner user name (from EMS) |
| `hwvendor` / `hwfamily` / `hwversion` | Hardware |
| `eptag`, `epuuid`, `uniepid`, `importance`, `purduelevel` | Tags, UUID, unified ID, importance, Purdue level |
| **`attrdatasrc`** | JSON naming the source of each attribute, e.g. `{"osname": "FGT", "ownereuname": "EMS"}`: `FGT` = FortiGate logs, `FGTAPI` = FortiGate device inventory, `EMS` = EMS connector |
| `firstseen` / **`lastseen`** | First / last seen (Unix epoch) |

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

-- Where FAZ got each endpoint's identity and OS from
SELECT detecttype, JSONExtractString(toString(attrdatasrc), 'osname') AS os_src, count(*) AS n
FROM $ADOM_ENDPOINT
GROUP BY detecttype, os_src
ORDER BY n DESC

-- Why rows have no endpoint/user ID (codes below 1024)
SELECT if(epid > 1024, 'id', toString(epid)) AS ep, if(euid > 1024, 'id', toString(euid)) AS eu, count(*) AS n
FROM $log-traffic
WHERE $filter
GROUP BY ep, eu
ORDER BY n DESC
```

---

## `$ADOM_ENDUSER` — End User Registry

Backed by `faz_fabric_endusers`. Join key: `euid`. **Always filter `euid > 1024`**. Columns identical on two FAZ 7.6 instances.

**Contains personal data** beyond log content (enriched from EMS/Active Directory connectors): `birthday`, `gender`, `homeaddr`, `phone`, `email`, `employeeid`, `manager`. Select only the columns a report needs.

| Column | Description |
|---|---|
| **`euid`** | End user ID (join key) |
| **`euname`** | User name as FAZ normalised it, not a copy of the log value: compared with the log's `user` for the same `euid`, 81 % matched exactly and 97 % after removing `DOMAIN\` / `@domain` on one FAZ; on the other, machine accounts `host/<computer>.<domain>` appeared without the `host/` prefix |
| `realeuid` / `euuuid` | Unified user ID / UUID |
| `fctuid` | FortiClient UID of the user's endpoint |
| `authtype` | How the user was identified |
| **`eugroup`** | User group — use `coalesce(eugroup, 'Unknown')` (empty on about half the users of one FAZ) |
| `vpnip` | VPN IP |
| `firstname`, `lastname`, `title`, `department`, `manager`, `country`, `email`, `workemail`, `workphone`, `phone`, `workaddr`, `homeaddr`, `employeeid`, `birthday`, `gender`, `socialid` | Directory attributes (connector-enriched) |
| `attrdatasrc` | JSON naming the source of each attribute |
| `importance` | Importance |
| `firstseen` / **`lastseen`** | First / last seen (Unix epoch) |

```sql
-- Sessions per user via euid (prefer the log's own user field where it exists)
SELECT coalesce(nullifna(t.log_user), eu.euname) AS user_name,
       coalesce(eu.eugroup, 'Unknown') AS user_group, sum(t.sessions) AS sessions
FROM (SELECT euid, any(`user`) AS log_user, count(*) AS sessions
      FROM $log-traffic
      WHERE $filter AND euid > 1024 AND bitAnd(logflag, 1) > 0
      GROUP BY euid) t
LEFT JOIN $ADOM_ENDUSER eu ON t.euid = eu.euid
GROUP BY user_name, user_group
ORDER BY sessions DESC
```

---

## `$ADOM_EPEU_DEVMAP` — Endpoint/User to Device Mapping

| Column | Description |
|---|---|
| **`epid`** | Endpoint ID |
| **`euid`** | End user ID |
| `devid` | Device serial the pair was seen on |
| `vd` | VDOM |
| `srcmac` / `srcintf` | MAC and interface the endpoint was seen with |
| `firstactive` / `lastactive` | First / last activity |
| `epdevtopo` | Topology information |

FAZ sometimes rejects queries on these tables (and on FortiClient tables) with "SQL query is forbidden", for example scalar subqueries such as `SELECT (SELECT count() FROM $ADOM_ENDPOINT)`. The exact trigger couldn't be pinned down; splitting the query into simple single-table queries worked every time.

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
