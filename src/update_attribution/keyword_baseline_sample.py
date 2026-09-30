#!/usr/bin/env python3
"""Where do keyword matches of the naive update filter come from?

The naive filter marked a Mon(IoT)r capture as update-related if 'update', 'firmware',
'software' or 'download' occurred anywhere in its tshark JSON dissection. The 6,315
captures it selected are in retrospective/imc19_dataset_update/. This script draws a
fixed random sample (seed 7, n=300), records which dissector fields matched, and
separates captures that match only protocol vocabulary (TCP window-update annotation,
SIP methods, STUN attributes, OCSP/X.509 fields) from captures with a match in
application content (HTTP, XML, JSON, DNS names).

Usage: python3 src/update_attribution/keyword_baseline_sample.py [--n 300] [--seed 7]
"""
import argparse
import collections
import json
import os
import random
import re
import subprocess

from paths import RAW_RETRO_KEYWORD_SELECTION as SELECTED, require
PATTERN = re.compile(r'update|firmware|software|download', re.I)
VOCAB = ('tcp.analysis.window_update', '_ws.expert', 'sip.', 'stun.', 'ocsp.', 'x509af.', 'pkix1',
         'tls.', 'http.response.code', 'nbns', 'dhcp', 'dns.flags')
UPDATE_ENDPOINTS = ('softwareupdates', 'hub-updates', 'CheckSWAutoUpd')


def matched_fields(obj, key=''):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if PATTERN.search(k):
                yield k
            yield from matched_fields(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from matched_fields(v, key)
    elif isinstance(obj, str) and PATTERN.search(obj):
        yield key


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--n', type=int, default=300)
    ap.add_argument('--seed', type=int, default=7)
    args = ap.parse_args()
    require(SELECTED)
    pcaps = sorted(os.path.join(r, f) for r, _, fs in os.walk(SELECTED) for f in fs if f.endswith('.pcap'))
    random.seed(args.seed)
    sample = random.sample(pcaps, args.n)
    kinds, vocab_only, update_hits = collections.Counter(), 0, 0
    for p in sample:
        js = json.loads(subprocess.run(['tshark', '-r', p, '-T', 'json'], capture_output=True, text=True).stdout or '[]')
        fields = set(matched_fields(js))
        if all(any(k.startswith(v) or v in k for v in VOCAB) for k in fields):
            vocab_only += 1
        if any(any(u in k for u in UPDATE_ENDPOINTS) for k in fields):
            update_hits += 1
        seen = set()
        for k in fields:
            if 'window_update' in k or k == '_ws.expert.message':
                seen.add('TCP window-update annotation')
            elif k.startswith('sip'):
                seen.add('SIP method')
            elif k.startswith('stun'):
                seen.add('STUN attribute')
            elif 'ocsp' in k or 'x509' in k or 'pkix' in k:
                seen.add('OCSP/X.509 field')
        kinds.update(seen)
    n = len(sample)
    print(f'captures in naive selection: {len(pcaps)}; sample: {n} (seed {args.seed})')
    print(f'only protocol vocabulary: {vocab_only} ({100 * vocab_only / n:.1f}%)')
    for k, v in kinds.most_common():
        print(f'  {k}: {v} ({100 * v / n:.1f}%)')
    print(f'request to an update endpoint: {update_hits} ({100 * update_hits / n:.1f}%)')


if __name__ == '__main__':
    main()
