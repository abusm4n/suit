#!/usr/bin/env python3
"""Per-flow payload entropy of update flows, grouped by how each flow is protected.

Revisits the entropy analysis of earlier versions of the paper: instead of per-device
means over all packets, it computes the normalized Shannon entropy (bits per byte / 8) of
the server-to-device payload of each update flow, and groups flows by what protocol
inspection says about them (TLS 1.3, TLS 1.2, HTTP image or asset, HTTP check or metadata,
unencrypted local push). If entropy were a reliable encryption test, encrypted and
unencrypted flows would fall into different bands; they do not.

At most MAX_BYTES of payload per flow are used (the first bytes of the flow).
Inputs: data/derived/controlled/flows.csv and data/derived/retrospective/update_flows.csv,
plus the raw captures. Output: data/derived/controlled/entropy_by_channel.csv

Usage: python3 src/update_attribution/entropy_by_channel.py
"""
import collections
import csv
import ipaddress
import math
import subprocess

from paths import CONTROLLED_CAPTURES as FILES, DERIVED_CONTROLLED as CTRL, DERIVED_RETRO as RETRO
from paths import RAW_CONTROLLED as CTRL_PCAPS, RAW_RETRO as RETRO_PCAPS, require

MAX_BYTES = 2_000_000
IMAGE_ROLES = ('image', 'asset')


def entropy(data):
    if not data:
        return None
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(data).values()) / 8


def payloads(pcap, proto, streams, server_of):
    """Server-to-device payload bytes per stream (first MAX_BYTES)."""
    field = 'tcp.payload' if proto == 'tcp' else 'udp.payload'
    sfield = 'tcp.stream' if proto == 'tcp' else 'udp.stream'
    flt = f'{proto} && ({" || ".join(f"{sfield}=={s}" for s in streams)})'
    out = subprocess.Popen(['tshark', '-r', str(pcap), '-Y', flt, '-T', 'fields', '-E', 'separator=|',
                            '-e', sfield, '-e', 'ip.src', '-e', field], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, text=True)
    buf = collections.defaultdict(bytearray)
    for line in out.stdout:
        st, src, hexdata = (line.rstrip('\n').split('|') + ['', ''])[:3]
        if not hexdata or src != server_of[st] or len(buf[st]) >= MAX_BYTES:
            continue
        buf[st] += bytes.fromhex(hexdata.replace(':', ''))[:MAX_BYTES - len(buf[st])]
    out.wait()
    return buf


def group(proto_label, role, lan):
    if lan:
        return 'local push'
    if proto_label == '1.3':
        return 'TLS 1.3'
    if proto_label == '1.2':
        return 'TLS 1.2'
    return 'HTTP, image or asset' if any(r in role for r in IMAGE_ROLES) else 'HTTP, check or metadata'


def main():
    require(CTRL_PCAPS, RETRO_PCAPS)
    rows = []
    # controlled
    flows = [r for r in csv.DictReader(open(CTRL / 'flows.csv')) if r['endpoint']]
    by = collections.defaultdict(list)
    for f in flows:
        by[(f['device'], f['proto'])].append(f)
    for (dev, proto), fl in by.items():
        server_of = {f['stream']: f['remote'] for f in fl}
        buf = payloads(CTRL_PCAPS / FILES[dev], proto, list(server_of), server_of)
        for f in fl:
            data = bytes(buf.get(f['stream'], b''))
            h = entropy(data)
            if h is None:
                continue
            rows.append(dict(dataset='ours', device=dev, endpoint=f['endpoint'], role=f['role'],
                             group=group(f['tls_version'], f['role'], f['lan'] == 'True'),
                             bytes=len(data), entropy=round(h, 4)))
    # retrospective
    retro = list(csv.DictReader(open(RETRO / 'update_flows.csv')))
    bycap = collections.defaultdict(list)
    for f in retro:
        bycap[f['capture']].append(f)
    for cap, fl in bycap.items():
        pcap = RETRO_PCAPS / cap
        # server = the public address in the stream (resolved by tshark below)
        streams = [f['stream'] for f in fl]
        out = subprocess.run(['tshark', '-r', str(pcap), '-Y', ' || '.join(f'tcp.stream=={s}' for s in streams),
                              '-T', 'fields', '-E', 'separator=|', '-e', 'tcp.stream', '-e', 'ip.src', '-e', 'ip.dst'],
                             capture_output=True, text=True).stdout
        server_of = {}
        for line in out.splitlines():
            st, a, b = (line.split('|') + ['', ''])[:3]
            for ip in (a, b):
                try:
                    if not ipaddress.ip_address(ip).is_private:
                        server_of.setdefault(st, ip)
                except ValueError:
                    pass
        buf = payloads(pcap, 'tcp', [s for s in streams if s in server_of], server_of)
        for f in fl:
            data = bytes(buf.get(f['stream'], b''))
            h = entropy(data)
            if h is None:
                continue
            role = f['role'] + (' asset' if f['endpoint'] == 'updates-http.cdn-apple.com' else '')
            rows.append(dict(dataset='2019', device=f['device'], endpoint=f['endpoint'], role=role,
                             group=group(f['tls_version'], role, False), bytes=len(data), entropy=round(h, 4)))
    with open(CTRL / 'entropy_by_channel.csv', 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    agg = collections.defaultdict(list)
    for r in rows:
        agg[(r['group'], r['dataset'])].append(r['entropy'])
    for k, v in sorted(agg.items()):
        v.sort()
        above = sum(x > 0.8 for x in v) / len(v)
        print(f'{k[0]:26s} {k[1]:5s} n={len(v):5d} median={v[len(v) // 2]:.3f} min={v[0]:.3f} '
              f'max={v[-1]:.3f} share>0.8={100 * above:.0f}%')


if __name__ == '__main__':
    main()
