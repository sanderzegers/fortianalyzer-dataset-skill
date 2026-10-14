# `$log-ssl` — SSL/TLS Inspection Logs

All common columns apply (see cols-common.md).

> **One column set for every version.** These columns were checked on two FAZ 7.6 instances receiving logs from FortiOS 7.2.10, 7.4.12 and 7.6.7. The column set is identical on all of them and matches the FortiOS 7.4 and 7.6 Log Message Reference. Names like `sslversion`, `sslcipher`, `sslaction`, `sslserver`, `sslprotocol`, `sslrootcacert`, `sslexpiredcert`, `sslcipherid` and `url` **don't exist** in this table and fail with "Missing columns". `sslaction` exists only in `$log-traffic`. See version-differences.md.

## Columns

| Column | Type | Description |
|---|---|---|
| **`hostname`** | LowCardinality(String) | Server hostname |
| **`sni`** | — | TLS Server Name Indication sent by the client |
| **`tlsver`** | — | TLS version, lowercase: `tls1.0`, `tls1.1`, `tls1.2`, `tls1.3`. Empty on many anomaly/exempt events |
| **`cipher`** | — | Cipher suite as a **hex IANA ID** (`0x1301`, `0xc030`), not a name |
| `authalgo` / `kxproto` / `kxcurve` | — | Authentication algorithm (`rsa`, `ecdsa`) / key exchange protocol (`ecdhe`) / key exchange curve |
| `handshake` | — | Handshake type |
| **`action`** | LowCardinality(String) | Inspection action (see values below) |
| **`eventtype`** / **`eventsubtype`** | — | What the inspection flagged (see values below) |
| `reason` | — | Reason for the action |
| `mitm` | — | Whether the session was intercepted (deep inspection) |
| `cn` / `san` | — | Certificate common name / subject alternative names |
| `issuer` | — | Certificate issuer |
| `sn` / `ski` | — | Certificate serial number / subject key identifier |
| `notbefore` / `notafter` | — | Certificate validity window |
| `keyalgo` / `keysize` | — | Certificate key algorithm / key size |
| `certhash` / `certdesc` | — | Certificate hash / description |
| `cat` / **`catdesc`** | — | Web category ID / description. Filled on category-based exemptions |
| `profile` / `profilegroup` | — | SSL/SSH inspection profile / profile group |
| `srcmac` / `srcname` / `transid` | — | Added in FortiOS 7.6 (log reference). Empty on 7.2/7.4 FortiGates, and not seen filled on 7.6.7 either |

## Key Patterns

```sql
-- Discover what this deployment logs
SELECT eventtype, eventsubtype, action, tlsver, count(*) AS cnt
FROM $log-ssl
WHERE $filter
GROUP BY eventtype, eventsubtype, action, tlsver
ORDER BY cnt DESC

-- Deprecated TLS versions (pre-TLS 1.2)
SELECT coalesce(nullifna(sni), hostname) AS server, tlsver, count(*) AS cnt
FROM $log-ssl
WHERE $filter AND tlsver IN ('tls1.0', 'tls1.1')
GROUP BY server, tlsver
ORDER BY cnt DESC

-- Cipher / TLS version usage (cipher is a hex IANA ID, e.g. 0x1301 = TLS_AES_128_GCM_SHA256)
SELECT tlsver, cipher, count(*) AS cnt
FROM $log-ssl
WHERE $filter AND cipher != ''
GROUP BY tlsver, cipher
ORDER BY cnt DESC

-- Inspection exemptions by reason
SELECT eventsubtype, count(*) AS cnt
FROM $log-ssl
WHERE $filter AND eventtype = 'ssl-exempt'
GROUP BY eventsubtype
ORDER BY cnt DESC

-- Certificates by issuer and expiry
SELECT coalesce(nullifna(sni), hostname) AS server, cn, issuer, notafter, count(*) AS cnt
FROM $log-ssl
WHERE $filter AND cn IS NOT NULL
GROUP BY server, cn, issuer, notafter
ORDER BY cnt DESC
```

## Real Values Discovered from FAZ Instances

Seen on FortiOS 7.2.10, 7.4.12 and 7.6.7 over 7 days. Which values occur depends on the SSL inspection profile, not on the version, so treat these as examples.

### `eventtype` / `eventsubtype`

| `eventtype` | `eventsubtype` values seen |
|---|---|
| `ssl-anomaly` | `certificate-anomaly`, `certificate-probe-failed`, `handshake-failure`, `certificate-blocklisted` |
| `ssl-exempt` | `allowlist`, `address`, `user-category`, `fortiguard-category` |
| `ssl-negotiation` | `unexpected-protocol`, `unsupported-cipher`, `unallowed-version` |

### `action`

| Value | Notes |
|---|---|
| `exempt` | Exempted from inspection (`ssl-exempt` events) |
| `bypass` | Not inspected, passed through |
| `info` | Informational anomaly, no action |
| `blocked` | Connection blocked |
| `resign-as-untrusted` | Server cert re-signed with the untrusted CA |
| `resign-as-trusted` | Server cert re-signed with the trusted CA |

### `tlsver`

`tls1.0`, `tls1.1`, `tls1.2`, `tls1.3`, or empty. Lowercase, no `v`.

### `cipher`

Hex IANA IDs, e.g. `0x1301` (TLS_AES_128_GCM_SHA256), `0x1302` (TLS_AES_256_GCM_SHA384), `0x1303` (TLS_CHACHA20_POLY1305_SHA256), `0xc030` (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384). Often empty on anomaly and exempt events.
