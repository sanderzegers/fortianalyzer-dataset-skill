# FortiAuthenticator Logs (device type 12)

FortiAuthenticator sends only `event` logs: RADIUS/EAP/802.1X, LDAP, SAML and admin authentication, plus system and admin events. The table is small (32 columns). Columns and types verified on two FAZ 7.6 instances with FortiAuthenticator logs, identical on both (October 2026).

## Differences from FortiGate event logs

- FortiOS-style names: **`logid`** (UInt64, so compare numbers directly, no `logid_to_int()`), **`level`**, **`devid`**, `vd`, `user`, `action`, `status`, `msg`.
- No `srcip`/`dstip`: **`userip`** (`Nullable(IPv6)`, use `ipstr()`) is the client, **`nas`** (String) is the RADIUS client (NAS) that sent the request. Mostly an IPv4 address as text, sometimes a name.
- Values are **capitalised**: `Authentication`, `Failed`, `Success`, `EAP Login`.
- Columns are Nullable. Use `ifNull(col, '')` before string functions.

## `$log-event`

| Column | Type | Description |
|---|---|---|
| `type` | String | Always `event` |
| **`subtype`** | String | `Authentication` (~99 % of rows), `System`, `Admin`, `User`, `Web` |
| `level` | String | `information`, `notice`, `warning`, `error` |
| **`logdesc`** | String | Fixed event name per `logid`, e.g. `AUTH_FAIL_BADPASS`. **Use this to classify events** (see below) |
| `action` | String | `Authentication`, `EAP Login`, `Login`, `Logout`, `Assertion` (SAML), `Add`, `Edit`, `Delete`, or empty |
| `status` | String | `Success`, `Failed`, `Pending`, `Start`, or empty |
| **`user`** | String | User name **as entered**: plain name, `user@domain`, `DOMAIN\user`, and on failures also typos and brute-force junk. Use `lower()` and expect noise |
| `userip` | IPv6 | Client IP. Filled on RADIUS password failures, mostly empty on EAP/802.1X rows |
| `nas` | String | NAS (RADIUS client) address or name. Empty on `System`/`Admin` rows |
| `logid` | UInt64 | 5-digit message ID: `1xxxx` admin, `2xxxx` authentication, `3xxxx` system, `5xxxx` user portal (seen) |
| `faclogindex` | Int64 | FortiAuthenticator's own log index |
| `msg` | String | Readable text (contains user names) |

**`action` and `status` are unreliable for classification:** the same `logid` comes both with and without them (e.g. `AUTH_OK_NOFTK` rows mostly have empty `action`/`status`). Classify by `logdesc` or `logid`.

### `logdesc` values seen

| Area | `logdesc` (`logid`) |
|---|---|
| Auth success | `AUTH_OK` (20000), `AUTH_OK_NOFTK` (20001, OK without FortiToken), `AUTH_OK_FROM_NEW_BROWSER` (20003), `AUTH_PARTIAL_OK` (20300, first factor OK, token pending), `DOT1X_AUTH_OK` (20420), `EAP_AUTH_START` (20430), `EAP_AUTH_RESULT` (20431, `status` tells the result) |
| Auth failure | `AUTH_FAIL` (20100), `AUTH_FAIL_NOUSER` (20101), `AUTH_FAIL_BADPASS` (20102), `AUTH_FAIL_BADTOKEN`, `AUTH_FAIL_TOKEN_TIMEOUT`, `AUTH_FAIL_NO_FOLLOWUP_LOGIN`, `AUTH_FAIL_USER_NOT_FOUND` (20320), `AUTH_FAIL_USER_LOCKED` (20323), `AUTH_FAIL_USER_NOT_FILTERED` (20324), `AUTH_FAIL_LOCK_USER` (20331, user got locked out), `AUTH_FAIL_USER_AD_AUTH_ERROR` (20334), `AUTH_FAIL_IP_LOCKED` (20365), `AUTH_FAIL_LOCK_IP` (20366, IP got locked out), `AUTH_FAIL_RLDAP_CONNECT` (20312), `DOT1X_AUTH_FAIL` (20421) |
| SAML | `SAML_IDP_SP_REQ_OK` (20502), `SAML_IDP_SP_REQ_FAILED` (20503), `SAML_IDP_PORTAL_LOGIN` (50007), `SAML_IDP_PORTAL_LOGOUT` (50008) |
| Admin access | `AUTH_ADMIN_LOGIN_GUI` (20994), `AUTH_ADMIN_LOGOUT_GUI` (20995), `AUTH_ADMIN_LOGOUT_CLI` |
| Admin config | `GUI_ENTRY_ADDITION`, `GUI_ENTRY_CHANGE` (10002), `GUI_ENTRY_DELETION` (10003), `LDAP_USER_IMPORT` (10203), `PUBLISH_CRL` (10128) |
| System | `FTM_SRV` (30909), `SMTP_SEND_MAIL` (30908), `REMOTE_SERVER_STATUS` (30500), `LOG_AUTO_DELETION` (30301), `LDAP_USER_SYNC`, `CONF_BACKUP`, `SNMP_TRAP`, `API_ACCESS` (`Web` subtype) |

These are examples; other events exist. Group by `logdesc` to see what a deployment logs.

## Key Patterns

```sql
-- Authentication results by event type
SELECT logdesc, count(*) AS cnt
FROM $log-event
WHERE $filter AND subtype = 'Authentication'
GROUP BY logdesc
ORDER BY cnt DESC

-- Failed logins per user (password failures, unknown users, token failures)
SELECT lower(ifNull(`user`, '')) AS username, count(*) AS failures
FROM $log-event
WHERE $filter AND logdesc LIKE 'AUTH_FAIL%'
GROUP BY username
ORDER BY failures DESC

-- Lockouts (users and IPs)
SELECT logdesc, lower(ifNull(`user`, '')) AS username, ipstr(userip) AS client_ip, count(*) AS cnt
FROM $log-event
WHERE $filter AND logdesc IN ('AUTH_FAIL_LOCK_USER', 'AUTH_FAIL_LOCK_IP', 'AUTH_FAIL_USER_LOCKED', 'AUTH_FAIL_IP_LOCKED')
GROUP BY logdesc, username, client_ip
ORDER BY cnt DESC

-- Success vs failure per NAS (RADIUS client)
SELECT nas, countIf(logdesc LIKE 'AUTH_OK%' OR logdesc = 'DOT1X_AUTH_OK') AS ok,
       countIf(logdesc LIKE 'AUTH_FAIL%' OR logdesc = 'DOT1X_AUTH_FAIL') AS failed
FROM $log-event
WHERE $filter AND subtype = 'Authentication' AND ifNull(nas, '') != ''
GROUP BY nas
ORDER BY failed DESC
```
