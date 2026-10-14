# `$log-file-filter` — File Filter

All common columns apply (see cols-common.md).

> **One column set for every version.** The FAZ defines this table, so every FortiGate gets the same columns whatever its FortiOS version. Checked on two FAZ 7.6 instances: identical columns. `fileaction`, `filehash`, `filehashsha256`, `filehashsha1`, `filehashmd5`, `filecategory`, `sentbyte` and `rcvdbyte` **don't exist** here ("Missing columns"). Use `action` for the action, and `$log-virus` (`filehash`) for hashes. See version-differences.md.

## Columns

| Column | Type | Description |
|---|---|---|
| **`filetype`** | LowCardinality(String) | File type detected |
| **`filename`** | Nullable(String) | Original filename — use `nullifna()` |
| `matchfiletype` / `matchfilename` | — | File type / filename pattern the rule matched |
| **`rulename`** | — | File filter rule that matched |
| `filtertype` | — | Filter type |
| **`action`** | LowCardinality(String) | File filter action |
| `direction` | — | `incoming` / `outgoing` |
| `level` | LowCardinality(String) | Log level: `notice`, `information`, `warning` |
| `filesize` | Nullable(UInt64) | File size in bytes |
| `hostname` / `url` | — | Web transfer host / URL |
| `from` / `to` / `sender` / `recipient` / `subject` / `attachment` | — | Email transfer fields |
| `sharename` / `pathname` | — | SMB share / path |

## Key Pattern

`action` takes the rule's configured action: `log-only` or `block`.

```sql
-- Blocked file transfers by rule and type
SELECT rulename, filetype, count(*) AS cnt
FROM $log-file-filter
WHERE $filter AND action = 'block'
GROUP BY rulename, filetype
ORDER BY cnt DESC

-- Large transfers by filetype
SELECT filetype, nullifna(filename) AS fname, direction, filesize
FROM $log-file-filter
WHERE $filter AND nullifna(filename) IS NOT NULL AND filesize > 1000000
ORDER BY filesize DESC
```

## Real Values Discovered from FAZ Instance

Seen on FortiOS 7.4.12 over 24 hours. Treat these as examples. Which values occur depends on the file-filter profile.

### `action`

| Value | Notes |
|---|---|
| `log-only` | Rule matched and was only logged. This was the only value seen; it matches the rule action `log-only` |
| `block` | Rule action `block`. Not in this sample |

### `filetype`

Lowercase FortiOS file-type names, e.g. `cab`, `gzip`, `zip`, `msi`, `exe`, `crx`, `msofficex` (OOXML Office), `msoffice` (legacy Office), `base64`, `pdf`, `mime`, `bat`, `xz`, `class`, `unknown`. Filter with lowercase literals.

### `direction`

`incoming`, `outgoing`.
