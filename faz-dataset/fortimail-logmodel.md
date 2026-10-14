# FortiMail Log Model

How FortiMail events map onto its four FAZ tables, how records link, and patterns that join them. Column details are in [fortimail.md](fortimail.md). Mapped on one production deployment (FAZ 7.6, about 2.4 million messages over 30 days, October 2026). Counts and percentages below come from that deployment; check them on yours before relying on them.

## Where is it logged?

| Looking for | Table and filter | `msg` starts with |
|---|---|---|
| Final verdict per message | `history` | (columns `classifier`, `disposition`) |
| Admin releases a message from the system quarantine | `emailfilter`, `subtype='admin'` | `Administrator <admin> released system quarantine message for re-scan ...` |
| Admin bulk-releases from the quarantine page | `emailfilter`, `subtype='admin'` | `System quarantine message released: N message(s) were released by Administrator <admin> ...` |
| Release from the history-log view | `emailfilter`, `subtype='default'` | `Quarantine release from history log. Total N message(s), N released.` (**no admin named**) |
| Admin opens or downloads a quarantined message | `emailfilter`, `subtype='admin'` | `Administrator <admin> opened System quarantine message ...` / `... downloaded System quarantine message ...` |
| Mailbox's quarantine folder removed | `emailfilter`, `subtype='default'` | `Removed quarantine box of nonexisting user: ...` |
| Each attachment and its AV result | `emailfilter` | `File name: <name>, scanned by Antivirus Scanner(clean), ...` |
| Safelist hit | `emailfilter` | `System Safe List: ...`, `Domain <domain> safe list: ...`, `<user> Personal safe list: ...` |
| Newsletter score | `emailfilter` | `Newsletter: score = N`, `Newsletter: found header List-Unsubscribe`, `Suspicious Newsletter: ...` |
| Lookalike / BEC checks | `emailfilter` | `Detected by CousinDomain: ...`, `Sender Alignment: ...` |
| QR codes | `emailfilter` | `Extracted URL from QR code` |
| FortiSandbox rating of a file | `virus`, `subtype='fortisandbox'` | `File <name> (checksum: <sha256>) has been scanned by FortiSandbox. Scan result: rating=<RATING>` |
| FortiSandbox rating of a URL | `virus`, `subtype='fortisandbox'` | `URL has been scanned by FortiSandbox. Scan result: rating=<RATING>. (<url>)` |
| Delivered / deferred / bounced | `event`, `subtype='smtp'` | sendmail lines, see "Delivery status" |
| Admin login, failed login | `event`, `type='kevent'`, `subtype='admin'` | `User <admin> logged in`, `User <name> login failed` |
| Admin reads or searches logs | `event`, `type='kevent'`, `subtype='admin'` | `History logs accessed (user: ...)`, `User <admin> performed search on History log: [...]`, `User <admin> downloaded log ...` |
| Configuration change | `event`, `type='kevent'`, `subtype='config'` | `Modified '<obj>' on '<table>' : <field>[old->new] (user: <admin>, from: <channel>)`, `Added ...`, `Deleted ...`, `Copied ...`, `Domain block list add ...`, `System safe list add: ...` |
| HA heartbeat, AV/IPS updates, LDAP errors | `event`, `type='kevent'`, `subtype` `ha` / `update` / `system` | `hahbd: ...`, `Update result: ...`, `ldapcached: ...` |
| Webmail login | `event`, `subtype='webmail'` | `WebMail: Login for <addr> from <ip> failed` |

Config changes appear twice under HA: once with `from: https(<ip>)` on the primary and once with `from: HA` on the secondary. Filter out `from: HA` to count them once.

Not seen in the logs examined: releases by end users from the personal quarantine (quarantine report or webmail) and the `Quarantine` disposition that goes with a personal quarantine. Treat their format as unverified.

## Linking records

`session_id` (`<queue id>-<queue id>`, e.g. `6B2cD3e4012345-6B2cD3e6012345`) is the same in all four tables for one SMTP session:

| From | To | Key | Use |
|---|---|---|---|
| `history` | `emailfilter`, `virus` | `session_id` | Checks, attachments, sandbox stages of a message. Count `DISTINCT session_id` |
| `history` | `event` (`subtype='smtp'`) | `session_id` | Delivery status. All 956 accepted inbound sessions in a 6-hour sample of one deployment had matching lines |
| `emailfilter` release line | `history` of the **quarantined** message | `extract(msg, 'original session ID\\(([^)]+)\\)')` ↔ `session_id` | Reason, domain and quarantine time of a released message |
| `emailfilter` release line | `history` of the **re-delivered** copy | `extract(msg, 'session ID\\(([^)]+)\\), original')` ↔ `session_id` | The re-scanned copy gets a new session, classifier `Not Spam` in almost every case |
| `virus` | FortiSandbox `malware` | SHA-256 from `msg` (`checksum: ...`) ↔ `sha256` | A second query with the FortiSandbox device type (see investigating.md) |
| `history` | `history` | `message_id` | The same message in several sessions (forwarding, re-sends). Empty on rejected sessions |

## Delivery status

`event`/`smtp` rows are sendmail log lines with `action='NONE'` and `status='N/A'`. Classify them by `msg`:

| `msg` pattern | Meaning |
|---|---|
| `from=<...>, size=N, class=N, nrcpts=N, ...` | Message accepted and queued |
| `to=<...>, ... stat=Sent (...)` (or `<addr>,<addr>, ... stat=Sent`) | Delivered to the next hop |
| `... stat=Deferred: ...` | Temporary failure, will retry |
| `... dsn=5.x.x, stat=...` | Permanent failure |
| `...: DSN: ...` | Bounce message created |
| `Milter: ... reject=...` | Rejected during the SMTP dialogue |
| `STARTTLS=...` | TLS negotiation |

## Patterns

```sql
-- Quarantine releases per admin, with the original reason and the wait time
SELECT r.admin, h.classifier AS quarantine_reason, count(*) AS releases,
       round(avg(dateDiff('minute', h.quarantined, r.release_time)) / 60, 1) AS avg_wait_h
FROM (SELECT dtime AS release_time,
             extract(msg, '^\\S+ (\\S+) released') AS admin,
             extract(msg, 'original session ID\\(([^)]+)\\)') AS osid
      FROM $log-emailfilter
      WHERE $filter AND subtype = 'admin'
        AND msg LIKE '%released system quarantine message%original session ID%') r
JOIN (SELECT session_id, any(classifier) AS classifier, min(dtime) AS quarantined
      FROM $log-history
      WHERE $filter AND ifNull(disposition, '') LIKE '%Quarantine%'
      GROUP BY session_id) h ON r.osid = h.session_id
GROUP BY r.admin, quarantine_reason
ORDER BY releases DESC

-- Subscription bombing: the victim gets signed up to many newsletters, so a recipient-day
-- shows far more newsletters than normal, mostly from different senders.
-- Calibrate the volume threshold first (next query). 50 is the valley found on one
-- deployment; senders >= 0.6 x threshold only excludes a burst from one single sender.
SELECT rcpt, d, n AS newsletters, senders
FROM (SELECT lower(`to`) AS rcpt, toDate(dtime) AS d, count(*) AS n,
             uniqExact(lower(splitByChar('@', ifNull(`from`, ''))[-1])) AS senders
      FROM $log-history
      WHERE $filter AND direction = 'in'
        AND classifier IN ('Newsletter', 'Newsletter Suspicious') AND ifNull(`to`, '') != ''
      GROUP BY rcpt, d) t
WHERE n >= 50 AND senders >= 30
ORDER BY n DESC

-- Calibration: recipient-days per volume bucket. Normal days fall off steadily; flooded
-- mailboxes form a second hump at high volume (seen: 42 / 13 / 61 recipient-days for
-- 21-50 / 51-100 / 100+). Put the threshold in the valley before the hump. Percentiles
-- don't work here: an ongoing flood pulls p99 up into the flood itself.
SELECT multiIf(n <= 5, '1-5', n <= 10, '6-10', n <= 20, '11-20', n <= 50, '21-50',
               n <= 100, '51-100', '100+') AS newsletters_per_day,
       count(*) AS recipient_days, round(avg(senders / n), 2) AS senders_per_newsletter
FROM (SELECT lower(`to`) AS rcpt, toDate(dtime) AS d, count(*) AS n,
             uniqExact(lower(splitByChar('@', ifNull(`from`, ''))[-1])) AS senders
      FROM $log-history
      WHERE $filter AND direction = 'in'
        AND classifier IN ('Newsletter', 'Newsletter Suspicious') AND ifNull(`to`, '') != ''
      GROUP BY rcpt, d) t
GROUP BY newsletters_per_day
ORDER BY min(n)

-- Delivery status per accepted inbound message
SELECT multiIf(e.sent > 0, 'delivered', e.deferred > 0, 'deferred', e.failed > 0, 'failed',
               'no final status yet') AS status, count(*) AS messages
FROM (SELECT session_id FROM $log-history
      WHERE $filter AND direction = 'in' AND ifNull(disposition, '') LIKE '%Accept%'
      GROUP BY session_id) h
LEFT JOIN (SELECT session_id AS sid,
                  countIf(msg LIKE '%stat=Sent%') AS sent,
                  countIf(msg LIKE '%stat=Deferred%') AS deferred,
                  countIf(msg LIKE '%dsn=5%') AS failed
           FROM $log-event
           WHERE $filter AND type = 'event' AND subtype = 'smtp' AND ifNull(session_id, '') != ''
           GROUP BY sid) e ON h.session_id = e.sid
GROUP BY status
ORDER BY messages DESC
```
