#!/usr/bin/env python3
"""Print the numbers behind the paper's tables and key statements.

Reads only the versioned tables in data/ (no raw captures needed), so every number can
be checked right after cloning. Each block names the table or section it supports.

Usage: python3 src/update_attribution/paper_numbers.py
"""
import collections
import csv
import signal
import statistics

from paths import CIPHERSUITE_SNAPSHOT, DERIVED_CONTROLLED as CTRL, DERIVED_RETRO as RETRO, REPO

IMAGES = REPO / 'data' / 'derived' / 'image_protection' / 'integrity_tiers.csv'


def rows(path):
    with open(path, newline='') as fh:
        return list(csv.DictReader(fh))


def head(title):
    print(f'\n== {title} ' + '=' * max(0, 84 - len(title)))


def pct(a, b):
    return f'{100 * a / b:.1f}%' if b else '-'


def table1():
    head('Table 1: identifying update traffic')
    f = rows(CTRL / 'funnel.csv')
    s = collections.Counter()
    for r in f:
        for k in ('flows', 'lan', 'wan', 'update_flows', 'update_tls', 'update_http', 'update_lan'):
            s[k] += int(r[k])
    servers = {e for r in f for e in r['endpoints'].split(';') if e and not e.startswith('LAN:')}
    with_upd = sum(1 for r in f if int(r['update_flows']))
    print(f'our captures : {len(f)} captures, {with_upd} with update traffic; flows {s["flows"]:,} '
          f'(local {s["lan"]} / Internet {s["wan"]:,}); update flows {s["update_flows"]} '
          f'(TLS {s["update_tls"]} / HTTP {s["update_http"]} / local push {s["update_lan"]}); '
          f'confirmed update servers {len(servers)}; devices with update traffic {with_upd} of {len(f)}')
    r = {x['metric']: int(x['value']) for x in rows(RETRO / 'funnel.csv')}
    print(f'2019 traces  : {r["captures"]:,} captures ({r["captures_iot_data"]:,} interaction + '
          f'{r["captures_iot_idle"]} idle), {r["distinct_hostnames"]} distinct hostnames, '
          f'{r["captures_with_update_traffic"]} with update traffic; update flows {r["update_flows"]:,} '
          f'(TLS {r["update_flows_tls"]:,} / HTTP {r["update_flows_http"]}); confirmed update servers '
          f'{r["confirmed_update_servers"]}; {r["device_labels"]} device labels ({r["device_models"]} models)')
    print('share of bytes that is update traffic (Figure 5):',
          ', '.join(f'{x["device"]} {100 * float(x["update_share"]):.0f}%' for x in f))


def keyword_baseline():
    head('Section 4.3 / Figure 4: keyword filter baseline')
    sel = rows(RETRO / 'keyword_baseline.csv')
    confirmed = {r['capture'] for r in rows(RETRO / 'update_flows.csv')}
    vocab = {'tcp-window-update', 'sip', 'stun', 'ocsp', 'tls-field'}
    cats = collections.Counter()
    only_vocab = accidental = 0
    for r in sel:
        cs = [c for c in r['categories'].split(';') if c]
        cats.update({('other' if c.startswith('other:') else c) for c in cs})
        v = cs and all(c in vocab or c.startswith('other:') for c in cs)
        only_vocab += bool(v)
        accidental += bool(v) and r['capture'] in confirmed
    n = len(sel)
    hit = len(confirmed & {r['capture'] for r in sel})
    print(f'selected {n:,} captures; only protocol vocabulary {pct(only_vocab, n)}; TCP window-update '
          f'{pct(cats["tcp-window-update"], n)}, STUN {pct(cats["stun"], n)}, SIP {pct(cats["sip"], n)}')
    print(f'with update traffic {hit} of {n:,} (precision {pct(hit, n)}); recall {pct(hit, len(confirmed))}; '
          f'matched only through unrelated fields: {accidental}')


def table2():
    head('Table 2: ciphersuite.info categories (snapshot 2026-09-30)')
    c = collections.Counter(r['security'] for r in rows(CIPHERSUITE_SNAPSHOT))
    print(', '.join(f'{k} {c[k]}' for k in ('recommended', 'secure', 'weak', 'insecure')), f'(total {sum(c.values())})')


def table3():
    head('Table 3: how the controlled devices received their updates')
    flows = [r for r in rows(CTRL / 'flows.csv') if r['endpoint']]
    leaf = collections.defaultdict(list)
    for r in rows(CTRL / 'leaf_certs.csv'):
        leaf[r['device']].append(f'{r["endpoint"]}: {r["issuer"]}, {r["key"]}, {r["validity_days"]} d')
    per = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, collections.Counter()]))
    for r in flows:
        chan = (f'TLS {r["tls_version"]} {r["suite_label"]}' if r['tls_version'] else
                'local push' if r['lan'] == 'True' else 'HTTP')
        e = per[r['device']][(r['endpoint'], r['role'])]
        e[0] += int(r['bytes_up']) + int(r['bytes_down'])
        e[1][chan] += 1
    for dev in sorted(per):
        print(dev)
        for (ep, role), (b, chans) in sorted(per[dev].items(), key=lambda kv: -kv[1][0]):
            size = f'{b / 1e9:.2f} GB' if b > 1e9 else f'{b / 1e6:.1f} MB'
            print(f'   {role:18s} {ep:36s} {size:>9s}  ' + ', '.join(f'{k} x{v}' for k, v in chans.items()))
        for s in leaf.get(dev, []):
            print(f'   leaf certificate   {s}')
    print('image protection (data/derived/image_protection/integrity_tiers.csv):')
    for r in rows(IMAGES):
        if r['tier'] not in ('?', ''):
            print(f'   {r["tier"]:9s} {r["integrity_primitive"][:58]:58s} {r["path"].split("/")[-1][:60]}')


def table4():
    head('Table 4: confirmed update servers in the 2019 traces')
    uf = rows(RETRO / 'update_flows.csv')
    leaf = {(r['endpoint'], r['role']): r for r in rows(RETRO / 'leaf_certs.csv')}
    by = collections.defaultdict(list)
    for r in uf:
        by[r['endpoint']].append(r)
    for ep, fl in sorted(by.items(), key=lambda kv: -len(kv[1])):
        devs = sorted({r['device'] for r in fl})
        protos = collections.Counter(r['proto'] for r in fl)
        suites = collections.Counter(f'{r["tls_version"]} {r["suite"].replace("TLS_", "")}' for r in fl if r['suite'])
        L = leaf.get((ep, 'server'))
        cert = f'{L["issuer"]}, {L["key"]}, {L["validity_days"]} d' if L else '-'
        print(f'{ep:30s} flows={len(fl):5d} {dict(protos)}  devices={",".join(devs)}')
        print(f'{"":30s} suites={dict(suites)}  leaf={cert}')
    c = leaf.get(('fwuprod.clouddevice.io', 'client'))
    if c:
        print(f'client certificate of the Honeywell thermostat: issuer {c["issuer"]}, valid until {c["not_after"]}')


def entropy():
    head('Section 5.2 / Figure 7: payload entropy per update flow')
    groups = collections.defaultdict(list)
    for r in rows(CTRL / 'entropy_by_channel.csv'):
        groups[(r['group'], r['dataset'])].append(float(r['entropy']))
    for (g, ds), v in sorted(groups.items()):
        print(f'{g:26s} {ds:5s} n={len(v):5d} median={statistics.median(v):.3f} min={min(v):.3f} '
              f'max={max(v):.3f} >0.8: {pct(sum(x > 0.8 for x in v), len(v))}')


def exposure():
    head('Table 5: what unencrypted update requests reveal')
    keys = ('model', 'hardware', 'installed', 'offered', 'build', 'region', 'platform', 'mac')
    for d, path in (('ours', CTRL), ('2019', RETRO)):
        for r in rows(path / 'exposure.csv'):
            got = ', '.join(f'{k}={r[k]}' for k in keys if r[k]) or 'nothing identifying'
            print(f'{d:4s} {r["device"]:16s} {r["endpoint"]:30s} requests={r["requests"]:>3s}  {got}')


def offered():
    head('Section 5.3 / Figure 8: offered cipher suites')
    for d, path in (('ours', CTRL), ('2019', RETRO)):
        for r in rows(path / 'offered_configs.csv'):
            n, w = int(r['suites']), int(r['weak'])
            ins = f', insecure {r["insecure"]}' if int(r['insecure']) else ''
            print(f'{d:4s} {r["device"]:22s} offered {n:3d}: weak {w:3d} ({100 * w / n:3.0f}%){ins}, '
                  f'TLS 1.3 offered: {r["offers_tls13"]}')
    neg = collections.Counter()
    for r in rows(CTRL / 'tls_update.csv'):
        neg[(r['device'], r['endpoint'], r['tls_version'], r['label'])] += int(r['connections'])
    print('negotiated on controlled update connections:')
    for (dev, ep, ver, lab), n in sorted(neg.items()):
        print(f'   {dev:11s} {ep:34s} TLS {ver} {lab:11s} x{n}')
    retro = collections.Counter((r['tls_version'], r['label']) for r in rows(RETRO / 'update_flows.csv') if r['label'])
    print('negotiated on 2019 update connections:', dict(retro))


def revocation():
    head('Table 6: revocation checking')
    tot = stapled = 0
    for d, path in (('ours', CTRL), ('2019', RETRO)):
        for r in rows(path / 'revocation.csv'):
            req, conns = int(r['staple_requested']), int(r['connections'])
            src = '+'.join(x for x, v in (('OCSP', r['ocsp']), ('CRL', r['crl'])) if v not in ('', 'none')) or \
                ('none' if r['ocsp'] == 'none' else 'not visible')
            if req == conns and req:
                tot += int(r['tls12'])
                stapled += int(r['stapled'])
            print(f'{d:4s} {r["device"]:21s} {r["endpoint"]:33s} leaf: {src:11s} staple requested '
                  f'{req}/{conns}; stapled {r["stapled"]}/{r["tls12"]} (TLS 1.2); lookups in '
                  f'{r["captures_with_revocation_lookup"]}/{r["captures"]} captures')
    print(f'clients that request stapling: stapled responses in {stapled} of {tot} visible TLS 1.2 connections')


def main():
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)   # quiet exit when piped into head
    table1()
    keyword_baseline()
    table2()
    table3()
    table4()
    entropy()
    exposure()
    offered()
    revocation()


if __name__ == '__main__':
    main()
