# `$log-virus` — Antivirus

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`virus`** | LowCardinality(String) | Virus/malware name |
| **`virusid`** | Nullable(UInt32) | Numeric virus ID — use `virusid_to_str()` for display |
| **`action`** | LowCardinality(String) | `blocked`, `passthrough`, `detected` |
| `checksum` | Nullable(String) | File checksum |
| `filehash` | Nullable(String) | File hash (SHA256/MD5) |
| `filehashsrc` | Nullable(String) | Source of file hash |
| **`filename`** | Nullable(String) | Infected file name |
| **`filetype`** | LowCardinality(String) | File type: `MS-Office`, `PDF`, `ZIP`, etc. |
| `analyticssubmit` | LowCardinality(String) | Submitted to FortiSandbox? |
| `analyticscksum` | Nullable(String) | Analytics checksum |
| `fsaverdict` | LowCardinality(String) | FortiSandbox verdict |
| `quarskip` | LowCardinality(String) | Quarantine skip reason |
| `filefilter` | LowCardinality(String) | File filter match |
| `contentdisarmed` | Nullable(String) | CDR (content disarm/reconstruct) status |
| **`direction`** | LowCardinality(String) | `incoming`, `outgoing` |
| `eventtype` | LowCardinality(String) | `infected`, `blocked`, `passthrough` |
| `from` / `to` | LowCardinality(String) | Email from/to (for email AV) |
| `sender` / `recipient` | LowCardinality(String) | Email sender/recipient |
| `subject` | LowCardinality(String) | Email subject |
| `viruscat` | Nullable(String) | Virus category |
| `itype` / `dtype` | Nullable(String) | Infection type / detection type |
| `sharename` / `pathname` | Nullable(String) | SMB share/path (file server AV) |
| `icbaction` / `icbverdict` / `icbseverity` / `icbconfidence` / `icbfiletype` / `icbfileid` / `icberror` | — | Inline cloud-based scan fields |
| `cdrcontent` / `contentencoding` | — | CDR content / content encoding |
| `url` / `referralurl` / `httpmethod` | — | Web transfer fields. There is **no** `hostname` or `filesize` column in the virus table ("Missing columns") |

## Key Pattern

```sql
-- Top viruses by victim count
SELECT virus,
       count(DISTINCT ipstr(`srcip`)) AS victims,
       count(*) AS detections,
       sum(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked
FROM $log-virus
WHERE $filter AND nullifna(virus) IS NOT NULL
GROUP BY virus
ORDER BY detections DESC
```

## Real Values Discovered from FAZ Instance

### `action` (Virus Action)

Observed from FAZ virus logs:

| Value | Notes |
|---|---|
| `analytics` | Sent to FortiSandbox |
| `monitored` | Monitored only |

### `level` (Virus Level)

| Value | Notes |
|---|---|
| `information` | Informational |
