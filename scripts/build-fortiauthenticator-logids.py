#!/usr/bin/env python3
"""Build faz-dataset/fortiauthenticator-logids.tsv from FortiAuthenticator's own log type list.

Fortinet publishes no FortiAuthenticator log reference; the complete list is only in the device GUI
under Logging > Log Access > Log Types (100 rows per page). Save each page as HTML, then run:

  python scripts/build-fortiauthenticator-logids.py page1.html page2.html page3.html

The script reads the table rows (Log Type ID, Name, Sub category, Category, Description) and maps
the sub category to the `subtype` value FAZ shows. The `logdesc` constant (e.g. AUTH_FAIL_BADPASS)
and `seen_in_logs` come from real FAZ logs, not from the device list; the script keeps them from the
existing file. Fill them for new IDs with:

  SELECT logid, any(logdesc) FROM $log-event WHERE $filter GROUP BY logid   (device type FortiAuthenticator)

The saved pages also contain session tokens (csrf); they are not copied into the output.
"""
import csv
import html
import os
import re
import sys

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   'faz-dataset', 'fortiauthenticator-logids.tsv')
COLS = ['logid', 'name', 'logdesc', 'sub_category', 'faz_subtype', 'description', 'seen_in_logs']
# Device "Sub category" -> FAZ `subtype`, as seen in real logs. Unseen categories stay empty.
SUBTYPE = {'Admin Configuration': 'Admin', 'Authentication': 'Authentication', 'System': 'System',
           'User Portal': 'User', 'Web Service': 'Web'}
ROW = re.compile(
    r'<td class="field-log_type_id">(\d+)</td><td class="field-name">(.*?)</td>'
    r'<td class="field-sub_category[^"]*">(.*?)</td><td class="field-category">(.*?)</td>'
    r'<td class="field-description">(.*?)</td>', re.S)


def text(s):
    return ' '.join(html.unescape(re.sub(r'<[^>]+>', '', s)).split())


def main(pages):
    old = {}
    if os.path.exists(OUT):
        old = {r['logid']: r for r in csv.DictReader(open(OUT, encoding='utf-8'), delimiter='\t')}
    rows = {}
    for p in pages:
        for lid, name, sub, cat, desc in ROW.findall(open(p, encoding='utf-8').read()):
            rows[lid] = {'logid': lid, 'name': text(name), 'sub_category': text(sub),
                         'faz_subtype': SUBTYPE.get(text(sub), ''), 'description': text(desc),
                         'logdesc': old.get(lid, {}).get('logdesc', ''),
                         'seen_in_logs': old.get(lid, {}).get('seen_in_logs', 'no')}
    if not rows:
        sys.exit('no log type rows found; save the Log Types pages as HTML')
    with open(OUT, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=COLS, delimiter='\t', lineterminator='\n')
        w.writeheader()
        for lid in sorted(rows, key=int):
            w.writerow(rows[lid])
    print('%d log types written to %s' % (len(rows), OUT))


if __name__ == '__main__':
    main(sys.argv[1:])
