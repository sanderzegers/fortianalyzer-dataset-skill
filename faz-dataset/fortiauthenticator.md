# FortiAuthenticator Logs (device type 12)

FortiAuthenticator sends only `event` logs: RADIUS/EAP/802.1X, LDAP, SAML and admin authentication, plus system and admin events. The table is small (32 columns). Columns and types verified on two FAZ 7.6 instances with FortiAuthenticator logs, identical on both (October 2026).

**All log types:** [fortiauthenticator-logids.tsv](fortiauthenticator-logids.tsv) lists the 238 log types of FortiAuthenticator 6.6.9 (ID, name, sub category, FAZ `subtype`, description, and the `logdesc` constant where seen). Fortinet publishes no FortiAuthenticator log reference; the list comes from the device itself (**Logging > Log Access > Log Types**) and can be rebuilt with `scripts/build-fortiauthenticator-logids.py`. All 53 logids seen on two FAZ instances are in it, with matching categories. **Grep it, don't read it whole:** `grep -i 'token' fortiauthenticator-logids.tsv`.

## Differences from FortiGate event logs

- FortiOS-style names: **`logid`** (UInt64, no `logid_to_int()`), **`level`**, **`devid`**, `vd`, `user`, `action`, `status`, `msg`.
- **Never filter on `logid`.** In `WHERE` or `HAVING`, FAZ handles a `logid` condition as a string (as for FortiGate's string `logid`), although `SELECT` shows a number. The same affects FortiClient `fct-event` (Common Mistake #17): `WHERE logid IN (20101, 20102)` **silently returns 0 rows**, and `WHERE logid = 20102` fails with "no supertype for types String, UInt16". Filter on `logdesc` (`WHERE logdesc IN ('AUTH_FAIL_BADPASS', ...)`) or `subtype`, and use `logid` only inside `SELECT` expressions such as `countIf(logid = 20102)` or a `multiIf` you group by. Both gave identical counts on two FAZes.
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
| `logid` | UInt64 | 5-digit log type ID: `10xxx` Admin Configuration, `20xxx` Authentication, `25xxx` Accounting, `30xxx`/`31xxx` System, `40xxx` High Availability, `500xx` User Portal, `505xx` Web Service, `60xxx` Hardware Monitor |
| `faclogindex` | Int64 | FortiAuthenticator's own log index |
| `msg` | String | Readable text (contains user names) |

**`action` and `status` are unreliable for classification:** the same `logid` comes both with and without them (e.g. `AUTH_OK_NOFTK` rows mostly have empty `action`/`status`). Classify by `logdesc` or `logid`.

### `logdesc` values seen

| Area | `logdesc` (`logid`) |
|---|---|
| Auth success | `AUTH_OK` (20000), `AUTH_OK_NOFTK` (20001, OK without FortiToken), `AUTH_OK_FROM_NEW_BROWSER` (20003), `AUTH_PARTIAL_OK` (20300, first factor OK, token pending), `DOT1X_AUTH_OK` (20420), `EAP_AUTH_START` (20430), `EAP_AUTH_RESULT` (20431, `status` tells the result) |
| Auth failure | `AUTH_FAIL` (20100), `AUTH_FAIL_NOUSER` (20101), `AUTH_FAIL_BADPASS` (20102), `AUTH_FAIL_BADTOKEN`, `AUTH_FAIL_TOKEN_TIMEOUT`, `AUTH_FAIL_NO_FOLLOWUP_LOGIN`, `AUTH_FAIL_USER_NOT_FOUND` (20320), `AUTH_FAIL_USER_LOCKED` (20323), `AUTH_FAIL_USER_NOT_FILTERED` (20324), `AUTH_FAIL_LOCK_USER` (20331, user got locked out), `AUTH_FAIL_USER_AD_AUTH_ERROR` (20334), `AUTH_FAIL_IP_LOCKED` (20365), `AUTH_FAIL_LOCK_IP` (20366, IP got locked out), `AUTH_FAIL_RLDAP_CONNECT` (20312), `DOT1X_AUTH_FAIL` (20421) |
| SAML | `SAML_IDP_SP_REQ_OK` (20502), `SAML_IDP_SP_REQ_FAILED` (20503), `SAML_IDP_PORTAL_LOGIN` (50007), `SAML_IDP_PORTAL_LOGOUT` (50008) |
| Admin access | `AUTH_ADMIN_LOGIN_GUI` (20994), `AUTH_ADMIN_LOGOUT_GUI` (20995), `AUTH_ADMIN_LOGOUT_CLI` (20999) |
| Admin config | `GUI_ENTRY_ADDITION` (10001), `GUI_ENTRY_CHANGE` (10002), `GUI_ENTRY_DELETION` (10003), `LDAP_USER_IMPORT` (10203), `PUBLISH_CRL` (10128), `CERT_SIGN` (10125), `CERT_KEY` (10122), `CERT_PKCS12_EXPORT` (10124), `EMAIL_SET` (10050), `MOBILE_SET` (10054), `FIDO_KEY_REG` (10139) |
| System | `FTM_SRV` (30909), `SMTP_SEND_MAIL` (30908), `REMOTE_SERVER_STATUS` (30500), `LOG_AUTO_DELETION` (30301), `USER_MAINTENANCE` (30302), `LDAP_USER_SYNC` (30303), `CONF_BACKUP` (30305), `SNMP_TRAP` (31001), `API_ACCESS` (50501, `Web` subtype) |

These are the `logdesc` constants seen on two FAZes. The `logdesc` constant of a log type that never occurred isn't known in advance (the device list gives only a display name such as "Authentication Failed Push Notification Denied"). For those, filter on `subtype` and count by `logid` in `SELECT` (see the patterns).

Log types the device can send but that never occurred on either FAZ: RADIUS accounting (`25000`–`25002`, sub category Accounting), HA (`40000`–`40007`), hardware monitoring (`60000`/`60001`), MAC authentication, guest portal and TACACS+. Their FAZ `subtype` is unverified.

## Correlating with FortiGate VPN logins

When a FortiGate authenticates VPN users against FortiAuthenticator (RADIUS), there is no shared key: match FortiGate tunnel-up / login rows to FortiAuthenticator rows by **user name and time** (FortiAuthenticator event within about 2 minutes before the tunnel-up). Normalise names first, since the two sides write them differently: `lower(replaceRegexpAll(user, '^.*\\\\|@.*$', ''))` turns `DOMAIN\user` and `user@domain` into `user`. **Untested:** in both estates examined, FortiGate VPN didn't authenticate through FortiAuthenticator (1 of 577 SSL VPN logins and 0 of 810 IPsec tunnels had a matching event), so match rates are unknown. Run the comparison in two queries, one per device type (investigating.md).

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

-- Admin access to FortiAuthenticator: GUI/CLI logins, failed or denied attempts
-- (logid only inside countIf: never filter on logid, see above)
SELECT lower(ifNull(`user`, '')) AS admin_user,
       countIf(logid = 20994) AS gui_logins, countIf(logid = 20998) AS cli_logins,
       countIf(logid IN (20996, 20997)) AS denied_or_failed
FROM $log-event
WHERE $filter AND subtype = 'Authentication'
GROUP BY admin_user
HAVING gui_logins + cli_logins + denied_or_failed > 0
ORDER BY denied_or_failed DESC

-- Second-factor (token) failures by reason, one column per log type
SELECT countIf(logid = 20103) AS bad_token_code, countIf(logid = 20104) AS replayed_code,
       countIf(logid = 20107) AS token_out_of_sync, countIf(logid = 20113) AS push_denied,
       countIf(logid = 20114) AS no_followup_login, countIf(logid = 20301) AS token_timeout,
       countIf(logid IN (20325, 20332, 20333)) AS token_not_usable
FROM $log-event
WHERE $filter AND subtype = 'Authentication'

-- Authentications by method (grouping by a logid expression is fine; filtering on it is not)
SELECT multiIf(logid IN (20420, 20421, 20422, 20430, 20431), '802.1X / EAP',
               logid BETWEEN 20500 AND 20503 OR logid IN (50006, 50007, 50008), 'SAML',
               logid BETWEEN 20400 AND 20404, 'MAC',
               logid BETWEEN 20600 AND 20611, 'Guest portal',
               logid BETWEEN 20994 AND 20999, 'Admin access',
               'RADIUS / password') AS method,
       countIf(logdesc LIKE '%OK%') AS ok, countIf(logdesc LIKE '%FAIL%') AS failed
FROM $log-event
WHERE $filter AND subtype IN ('Authentication', 'User')
GROUP BY method
ORDER BY failed DESC
```
