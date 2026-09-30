#!/usr/bin/env python3
"""Precision and recall of a naive keyword filter for update traffic.

The filter marks a Mon(IoT)r capture as update-related if 'update', 'firmware',
'software' or 'download' occurs (case-insensitive) anywhere in the capture's
`tshark -T json` dissection. For every selected capture we record in which dissector
fields the keywords occur, and group them into protocol vocabulary (Wireshark's TCP
window-update annotation, SIP methods, STUN attributes, OCSP/X.509 fields, other
dissector labels) versus application content (HTTP, XML, JSON, DNS names, ...).
Recall is measured against the captures that contain update flows to confirmed update
servers (retrospective_attribution.py, update_flows.csv).

Outputs: data/derived/retrospective/keyword_baseline.csv (one row per selected capture)
and a printed summary. Scan results are cached line by line in
cache/retrospective/keyword_baseline_cache_v2.jsonl, so an interrupted run resumes.

Usage: python3 src/update_attribution/keyword_baseline.py [--jobs 12]
"""
import argparse
import collections
import csv
import json
import os
import re
import subprocess
from concurrent.futures import ProcessPoolExecutor

from paths import CACHE_KEYWORD, DERIVED_RETRO as OUT, RAW_RETRO as DATASET, require
PATTERN = re.compile(r'update|firmware|software|download', re.I)


def category(key):
    k = key.lower()
    if 'window_update' in k or k == '_ws.expert.message':
        return 'tcp-window-update'
    if k.startswith('sip'):
        return 'sip'
    if k.startswith('stun'):
        return 'stun'
    if 'ocsp' in k or 'thisupdate' in k or 'nextupdate' in k:
        return 'ocsp'
    if 'x509' in k or 'pkix' in k:
        return 'certificate-name'
    if k == 'tls.handshake.extensions_server_name':
        return 'tls-server-name'
    if k.startswith(('http', 'xml', 'json', 'urlencoded', 'data-text', 'media', 'mime')) or ' http/' in k \
            or k.startswith(('get ', 'post ', 'subscribe ', 'notify ', 'm-search ')):
        return 'app-content'
    if k.startswith('dns') or 'type a, class' in k or 'type aaaa, class' in k:
        return 'dns-name'
    if k.startswith(('tls', 'ssl')):
        return 'tls-field'
    return 'other:' + k.split('.')[0][:24]


def walk(obj, key=''):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if PATTERN.search(k):
                yield k
            yield from walk(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v, key)
    elif isinstance(obj, str) and PATTERN.search(obj):
        yield key


KEY_LINE = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*:')
STR_LINE = re.compile(r'^\s*"((?:[^"\\]|\\.)*)",?\s*$')


def scan(rel):
    """Stream the tshark JSON dissection line by line (large captures produce GBs of JSON).

    A key that contains a keyword yields that key; a string value that contains a keyword
    yields the key it belongs to (for list items, the most recent key), as in a full parse.
    """
    proc = subprocess.Popen(['tshark', '-r', str(DATASET / rel), '-T', 'json'], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, errors='replace')
    cats, key, matched = set(), '', False
    for line in proc.stdout:
        m = KEY_LINE.match(line)
        if m:
            key = m.group(1)
            if PATTERN.search(line):
                matched = True
                if PATTERN.search(key):
                    cats.add(category(key))
                rest = line[m.end():]
                if PATTERN.search(rest):
                    cats.add(category(key))
            continue
        if PATTERN.search(line):
            matched = True
            if STR_LINE.match(line):
                cats.add(category(key))
    proc.wait()
    return rel, (sorted(cats) if matched else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--jobs', type=int, default=12)
    args = ap.parse_args()
    require(DATASET)
    caps = sorted(os.path.relpath(os.path.join(r, f), DATASET)
                  for r, _, fs in os.walk(DATASET) for f in fs if f.endswith('.pcap'))
    OUT.mkdir(parents=True, exist_ok=True)
    cache = CACHE_KEYWORD
    cache.parent.mkdir(parents=True, exist_ok=True)
    done = {}
    if cache.exists():
        for line in cache.read_text().splitlines():
            d = json.loads(line)
            done[d['capture']] = d['categories']
    todo = [c for c in caps if c not in done]
    print(f'{len(done)} captures cached, {len(todo)} to scan', flush=True)
    with ProcessPoolExecutor(args.jobs) as ex, open(cache, 'a') as fh:
        for i, (rel, cats) in enumerate(ex.map(scan, todo, chunksize=16)):
            fh.write(json.dumps({'capture': rel, 'categories': cats}) + '\n')
            done[rel] = cats
            if i % 2000 == 0:
                fh.flush()
                print(f'  {i}/{len(todo)}', flush=True)
    selected = {rel: cats for rel, cats in done.items() if cats is not None}
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / 'keyword_baseline.csv', 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['capture', 'categories'])
        for rel, cats in sorted(selected.items()):
            w.writerow([rel, ';'.join(cats)])
    vocab = {'tcp-window-update', 'sip', 'stun', 'ocsp', 'tls-field'}
    only_vocab = [r for r, c in selected.items() if c and all(x in vocab or x.startswith('other:') for x in c)]
    cat_counts = collections.Counter(x for c in selected.values() for x in c)
    confirmed = set()
    uf = OUT / 'update_flows.csv'
    if uf.exists():
        with open(uf, newline='') as fh:
            confirmed = {r['capture'] for r in csv.DictReader(fh)}
    n = len(selected)
    print(f'captures: {len(caps)}; selected by keyword filter: {n}')
    print(f'only protocol vocabulary / dissector labels: {len(only_vocab)} ({100 * len(only_vocab) / n:.1f}%)')
    for k, v in cat_counts.most_common(12):
        print(f'  {k}: {v} ({100 * v / n:.1f}%)')
    if confirmed:
        hit = confirmed & set(selected)
        print(f'captures with confirmed update flows: {len(confirmed)}; selected by filter: {len(hit)} '
              f'(recall {100 * len(hit) / len(confirmed):.1f}%); precision {100 * len(hit) / n:.1f}%')
        nv = [r for r in only_vocab if r in confirmed]
        print(f'vocabulary-only captures that nevertheless contain confirmed update flows: {len(nv)}')


if __name__ == '__main__':
    main()
