#!/usr/bin/env python3
"""Build faz-dataset/fortigate-logids.tsv from Fortinet's FortiOS Log Reference PDFs.

Usage:
  pip install pypdf
  python scripts/build-fortigate-logids.py 7.2.13 7.4.12 7.6.7 8.0.1

For each version, the script reads the "Log ID numbers" page on docs.fortinet.com to find the
Log Reference PDF, extracts every log message entry (message ID, name, meaning, type, category,
severity) and the "Log ID definitions" table (type and subtype codes), and computes the 10-digit
logid as <2-digit type><2-digit subtype><6-digit message ID>. One row per logid; the `versions`
column lists the versions whose reference documents it, and the text columns come from the newest
of those versions (for `meaning`, the one with the most word breaks, since PDF text extraction
sometimes drops spaces). A message ID renamed between versions gets one row per name. Downloaded files are cached in ./.logref-cache.
"""
import csv
import os
import re
import sys
import urllib.request

import pypdf

LIST_URL = ('https://docs.fortinet.com/document/fortigate/{v}/fortios-log-message-reference/'
            '34314/log-id-numbers')
CACHE = '.logref-cache'
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   'faz-dataset', 'fortigate-logids.tsv')


def fetch(url, path):
    if not os.path.exists(path):
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=120) as r, open(path, 'wb') as f:
            f.write(r.read())
    return path


def pdf_text(version):
    os.makedirs(CACHE, exist_ok=True)
    txt = os.path.join(CACHE, 'ref-%s.txt' % version)
    if os.path.exists(txt):
        return open(txt, encoding='utf-8').read()
    page = open(fetch(LIST_URL.format(v=version), os.path.join(CACHE, 'list-%s.html' % version)),
                encoding='utf-8', errors='ignore').read()
    m = re.search(r'https://fortinetweb[^"]+Log_Reference\.pdf', page)
    if not m:
        sys.exit('no Log Reference PDF link found for %s' % version)
    reader = pypdf.PdfReader(fetch(m.group(0), os.path.join(CACHE, 'ref-%s.pdf' % version)))
    text = '\n'.join((p.extract_text() or '') for p in reader.pages)
    open(txt, 'w', encoding='utf-8').write(text)
    return text


FOOTER = re.compile(r'^(?:FortiOS [\d.]+ Log Reference \d+|Fortinet,? Inc\.|Log Messages|Log schema structure)\s*$',
                    re.M)


def clean(text):
    """Remove page headers and footers, which the PDF puts in the middle of entries."""
    return re.sub(r'\n{2,}', '\n', FOOTER.sub('', text))


def codes(text):
    """Parse 'Log ID definitions': {type name: (type code, {subtype name: subtype code})}."""
    start = text.index('Log ID definitions\nFollowing are the definitions')
    end = text.index('Message ID:', start)
    out, cur = {}, None
    for line in text[start:end].splitlines():
        line = line.strip()
        m = re.match(r'^([a-z0-9_-]+):\s*(\d+)(?:\s+l\s+([a-z0-9_.-]+):\s*(\d+))?$', line)
        if m:  # a new log type, possibly with its first subtype on the same line
            cur = m.group(1)
            out[cur] = (int(m.group(2)), {})
            if m.group(3):
                out[cur][1][m.group(3)] = int(m.group(4))
            continue
        m = re.match(r'^l\s+([a-z0-9_.-]+):\s*(\d+)$', line)
        if m and cur:
            out[cur][1][m.group(1)] = int(m.group(2))
    return out


ENTRY = re.compile(
    r'Message ID: (\d+)\s*\nMessage Description: (\S+)\s*\nMessage Meaning: (.*?)\s*\n'
    r'Type: (.*?)\s*\nCategory: (.*?)\s*\nSeverity: (.*?)\s*\n', re.S)

# Type names in the entries vs. log type names in the code table, where they differ
TYPE_ALIAS = {'antivirus': 'virus', 'av': 'virus', 'web filter': 'webfilter', 'app-ctrl': 'app-ctrl',
              'application control': 'app-ctrl', 'ips': 'ips', 'dns': 'dns', 'email filter': 'emailfilter'}


def entries(text):
    text = clean(text)
    table = codes(text)
    for mid, name, meaning, typ, cat, sev in ENTRY.findall(text):
        t = typ.strip().lower()
        t = TYPE_ALIAS.get(t, t.replace(' ', '-'))
        c = cat.strip().lower()
        logid = ''
        if t in table and c in table[t][1]:
            logid = '%02d%02d%06d' % (table[t][0], table[t][1][c], int(mid))
        yield {'logid': logid, 'msgid': int(mid), 'name': name, 'meaning': ' '.join(meaning.split()),
               'type': typ.strip(), 'subtype': cat.strip(), 'severity': sev.strip()}


def main(versions):
    rows = {}
    for v in sorted(versions, key=lambda s: [int(x) for x in s.split('.')]):
        n = 0
        for e in entries(pdf_text(v)):
            key = (e['msgid'], e['name'])
            row = rows.setdefault(key, dict(e, versions=[]))
            # Newest version wins, except for text the PDF extraction glued together
            # ("Corruptedarchive"): keep the meaning with the most word breaks.
            best = row['meaning']
            row.update({k: val for k, val in e.items() if val})
            if best.count(' ') > row['meaning'].count(' '):
                row['meaning'] = best
            row['versions'].append(v)
            n += 1
        print('%s: %d entries' % (v, n))
    cols = ['logid', 'msgid', 'name', 'meaning', 'type', 'subtype', 'severity', 'versions']
    with open(OUT, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(cols)
        for key in sorted(rows):
            r = rows[key]
            w.writerow([r['logid'], r['msgid'], r['name'], r['meaning'], r['type'], r['subtype'],
                        r['severity'], ','.join(r['versions'])])
    missing = sum(1 for r in rows.values() if not r['logid'])
    print('%d logids written to %s (%d without a computable 10-digit logid)'
          % (len(rows), OUT, missing))


if __name__ == '__main__':
    main(sys.argv[1:] or ['7.2.13', '7.4.12', '7.6.7', '8.0.1'])
