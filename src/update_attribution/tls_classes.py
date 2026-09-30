#!/usr/bin/env python3
"""Cipher-suite labels from a dated ciphersuite.info API snapshot.

The snapshot (data/reference/ciphersuite_info_2026-09-30.csv, 351 suites, retrieved from
https://ciphersuite.info/api/cs/ on 2026-09-30) replaces the hand-written sets in
legacy/src/ciphersuite.py, which put ECDHE-CBC suites under "Recommended", TLS 1.3 suites
under "Secure", and the renegotiation SCSV 0x00FF under "Insecure".

Signaling values (RFC 5746 renegotiation SCSV 0x00FF, RFC 7507 fallback SCSV 0x5600)
and GREASE values (RFC 8701) are not cipher suites and get their own labels.

Usage as a module:
    from tls_classes import label, name
    label('0xc02f')  -> 'secure'
"""
import csv

from paths import CIPHERSUITE_SNAPSHOT as SNAPSHOT

SIGNALING = {'00ff': 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV', '5600': 'TLS_FALLBACK_SCSV'}
GREASE = {f'{b:x}a{b:x}a' for b in range(16)}  # 0a0a, 1a1a, ..., fafa


def _load():
    table = {}
    with open(SNAPSHOT, newline='') as f:
        for row in csv.DictReader(f):
            table[row['hex']] = (row['iana_name'], row['security'])
    return table


_TABLE = _load()


def norm(code):
    """Normalize '0xC02F' / 'c02f' / '49199'-style codes to 4 lowercase hex digits."""
    s = str(code).strip().lower()
    if s.startswith('0x'):
        s = s[2:]
    return s.zfill(4)


def label(code):
    """ciphersuite.info security label, or 'signal', 'grease', 'unknown'."""
    c = norm(code)
    if c in SIGNALING:
        return 'signal'
    if c in GREASE:
        return 'grease'
    return _TABLE.get(c, (None, 'unknown'))[1]


def name(code):
    c = norm(code)
    if c in SIGNALING:
        return SIGNALING[c]
    return _TABLE.get(c, (c, ''))[0]


def config_key(offered):
    """Offered suite list as a comparable key, with GREASE values collapsed."""
    return ','.join('GREASE' if norm(c) in GREASE else norm(c) for c in offered.split(',') if c)


if __name__ == '__main__':
    for c in ['0x1301', '0xc02f', '0xc02b', '0xc013', '0x009c', '0x0005', '0x00ff', '0x0a0a']:
        print(c, name(c), label(c))
