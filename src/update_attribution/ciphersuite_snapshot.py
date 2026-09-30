#!/usr/bin/env python3
"""Build the cipher-suite classification table from a ciphersuite.info API response.

The paper labels cipher suites with the four ciphersuite.info categories (recommended,
secure, weak, insecure). Because the site's classifications change over time, the
analysis uses a dated snapshot: data/reference/ciphersuite_info_api_2026-09-30.json is the
unmodified response of https://ciphersuite.info/api/cs/ retrieved on 2026-09-30, and
data/reference/ciphersuite_info_2026-09-30.csv is the table derived from it (one row per
suite: hex code, IANA name, OpenSSL name, category, TLS versions), which tls_classes.py
reads.

Usage:
  python3 src/update_attribution/ciphersuite_snapshot.py            # rebuild the CSV from the JSON
  python3 src/update_attribution/ciphersuite_snapshot.py --fetch    # download a new, dated snapshot
"""
import argparse
import csv
import datetime
import json
import urllib.request

from paths import REFERENCE

API = 'https://ciphersuite.info/api/cs/'
DATE = '2026-09-30'


def to_rows(api):
    rows = []
    for entry in api['ciphersuites']:
        (iana, d), = entry.items()
        code = (d['hex_byte_1'][2:] + d['hex_byte_2'][2:]).lower()
        rows.append(dict(hex=code, iana_name=iana, openssl_name=d.get('openssl_name', ''),
                         security=d['security'], tls_version='/'.join(d.get('tls_version', []))))
    return sorted(rows, key=lambda r: r['hex'])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--fetch', action='store_true', help='download the current API response first')
    args = ap.parse_args()
    date = datetime.date.today().isoformat() if args.fetch else DATE
    src = REFERENCE / f'ciphersuite_info_api_{date}.json'
    if args.fetch:
        with urllib.request.urlopen(API, timeout=60) as r:
            src.write_bytes(r.read())
        print('downloaded', src)
    rows = to_rows(json.loads(src.read_text()))
    out = REFERENCE / f'ciphersuite_info_{date}.csv'
    with open(out, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    counts = {k: sum(r['security'] == k for r in rows) for k in ('recommended', 'secure', 'weak', 'insecure')}
    print(f'wrote {out} ({len(rows)} suites: {counts})')


if __name__ == '__main__':
    main()
