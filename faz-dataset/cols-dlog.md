# `$log-dns` — DNS Filter

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`qname`** | LowCardinality(String) | DNS query name (domain queried) |
| **`qtype`** | Nullable(String) | Query type: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `PTR`, `SRV` |
| `qtypeval` | Nullable(UInt16) | Numeric query type |
| `qclass` | LowCardinality(String) | Query class (`IN`) |
| `exchange` | Nullable(String) | MX exchange value |
| `ipaddr` | Array(IPv6) | Resolved IP addresses — use `arrayJoin(ipaddr)` + `ipstr()` |
| **`botnetdomain`** | Nullable(String) | Botnet domain if matched |
| **`botnetip`** | Nullable(IPv6) | Botnet IP if matched — use `ipstr()` |
| `cat` | Nullable(UInt8) | Web category for domain |
| **`catdesc`** | LowCardinality(String) | Category description |
| `domainfilteridx` | Nullable(UInt8) | Domain filter entry index |
| `domainfilterlist` | Nullable(String) | Domain filter list name |
| `xid` | Nullable(UInt16) | DNS transaction ID |
| `rcode` | Nullable(UInt32) | DNS response code (0=NOERROR, 3=NXDOMAIN) |
| `sscname` | Nullable(String) | Safe Search enforced CNAME |
| `eventtype` | LowCardinality(String) | `dns-query`, `domain`, `botnet` |
| `error` | Nullable(String) | DNS error |
| `tdthreatname` / `tdthreattype` / `tdtype` / `tdwfcate` / `tdinfoid` / `tdscantime` | — | Inline threat detection fields |
| `echmsg` | — | Encrypted Client Hello message |

## Key Patterns

```sql
-- Resolved IPs from DNS queries
SELECT qname, ipstr(arrayJoin(ipaddr)) AS resolved_ip
FROM $log-dns
WHERE $filter AND length(ipaddr) > 0

-- Botnet domain queries
SELECT botnet, count(DISTINCT nullifna(`qname`)) AS qname_cnt,
       count(DISTINCT ipstr(`srcip`)) AS src_cnt, sum(total_num) AS total_num
FROM ###(
    SELECT coalesce(nullifna(`botnetdomain`), ipstr(`botnetip`)) AS botnet,
           nullifna(`qname`) AS qname, srcip,
           count(*) AS total_num
    FROM $log-dns
    WHERE $filter AND (nullifna(`botnetdomain`) IS NOT NULL OR `botnetip` IS NOT NULL)
    GROUP BY botnet, qname, srcip
    /*SkipSTART*/ORDER BY total_num DESC/*SkipEND*/
)### t
GROUP BY botnet
ORDER BY total_num DESC
```

## Real Values Discovered from FAZ Instance

### `action` (DNS Action)

Observed from FAZ DNS logs:

| Value | Notes |
|---|---|
| `pass` | Passed |

### `level` (DNS Level)

| Value | Notes |
|---|---|
| `notice` | Notice |


### `catdesc` (Category Description)

Observed category descriptions from FAZ DNS logs:

| Value | Notes |
|---|---|
| `File Sharing and Storage` | Cloud storage services |
| `Streaming Media and Download` | Video/audio streaming, file downloads |
| `Proxy Avoidance` | Privacy proxy services |
| `Freeware and Software Downloads` | App stores, package repos |
| `Internet Telephony` | VoIP services |
| `Alcohol` | Alcohol-related content |
| `Unrated` | Uncategorized domains |
| `Newly Observed Domain` | New domains not yet categorized |

### `qname` (Query Name)

Observed query names from FAZ DNS logs:

| Pattern | Examples |
|---|---|
| Cloud storage | `api.cloud-storage.example.com`, `api.cloud-storage-ext.example.com`, `client.cloud-storage.example.com`, `d.cloud-storage.example.com`, `bolt.cloud-storage.example.com`, `t8.cloud-storage.example.com`, `dl-debug.cloud-storage.example.com`, `api.cloud-drive.example.com`, `docs.drive.example.com`, `mask.proxy.example.com`, `gateway.proxy.example.com`, `p139-contacts.proxy.example.com`, `p158-caldav.proxy.example.com`, `p158-contacts.proxy.example.com`, `p139-content.proxy.example.com` |
| Media streaming | `www.media-stream.example.com`, `accounts.media-stream.example.com`, `spclient.wg.media-stream.example.com`, `gew4-spclient.media-stream.example.com`, `api-partner.media-stream.example.com`, `video-cf.media-stream.example.com`, `edge-web-gew4.dual-gslb.media-stream.example.com`, `gew4-dealer.g2.media-stream.example.com`, `itunes.music.example.com`, `bag.itunes.music.example.com`, `sf-api-token-service.itunes.music.example.com` |
| Privacy/proxy | `mask.proxy.example.com` (very frequent), `mask.proxy.example.com` |
| Communication | `edge.voice-call.example.com`, `eu-api.asm.voice-call.example.com`, `mira.config.voice-call.example.com`, `grpc.chat.secure-messaging.example.com`, `api.ai-assistant.example.com` |
| Gaming/new domains | `gaming-site.example.com`, `www.beer-craft.example.com`, `docusign.example.com`, `beer-club.example.com` |
| Randomized/CDN | `1807754d-9d3a-559c-be7f-21ed41449439.prd.edge-inf.example.com`, `1a1inqjh.p.qrcdn.example.com`, `12fa7dd4ed4192457a4d.cf-prod-us-proxy.proxyhog.example.com`, `nld-prebid.a-mx.example.com` |
| Software | `play.store.example.com`, `cmux.example.com`, `r.cmux.example.com`, `apt.archive.example.com` |
