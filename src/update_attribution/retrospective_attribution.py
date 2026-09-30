#!/usr/bin/env python3
"""Update-traffic attribution for the Mon(IoT)r (2019) captures (SAC 2027 revision).

1. extract  : per capture, tshark fields for DNS answers, TLS ClientHello/ServerHello/
              Certificate messages and HTTP requests (parallel, cached as JSON);
2. candidates: hostnames (DNS query, TLS SNI, HTTP Host) and HTTP URIs that match update
              patterns -> candidates.csv (input to manual vetting);
3. attribute: flows whose SNI/Host (or, without SNI, the DNS name resolved for the server
              address) is a kept endpoint in data/reference/confirmed_update_servers_retrospective.csv, with the
              endpoint's URI regex where given -> update_flows.csv, funnel, TLS parameters,
              and server leaf certificates (direction-aware: client certificates of mutual
              TLS are reported separately, without their subject, which identifies the device).

Outputs (data/derived/retrospective/): funnel.csv (Table 1), candidates.csv, update_flows.csv,
leaf_certs.csv, offered_configs.csv. tshark extractions are cached in cache/retrospective/fields/.

Usage: python3 src/update_attribution/retrospective_attribution.py [--jobs 12]
"""
import argparse
import collections
import csv
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import warnings
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tls_classes import config_key, label, name  # noqa: E402

from paths import CACHE_RETRO_FIELDS as FIELDS_DIR, DERIVED_RETRO as OUT, RAW_RETRO as DATASET  # noqa: E402
from paths import SERVERS_RETRO as VETTED, require  # noqa: E402

# the 2019 SmartThings leaf has a non-positive serial number (RFC 5280 violation); parse it anyway
warnings.filterwarnings('ignore', message='Parsed a serial number')

FIELDS = ['frame.number', 'ip.src', 'ip.dst', 'tcp.stream', 'udp.stream', 'dns.qry.name', 'dns.a',
          'http.host', 'http.request.method', 'http.request.uri', 'http.user_agent',
          'http.content_type', 'http.content_length', 'tls.handshake.type',
          'tls.handshake.extensions_server_name', 'tls.handshake.version',
          'tls.handshake.extensions.supported_version', 'tls.handshake.ciphersuite',
          'tls.handshake.certificate']
FILTER = ('dns.flags.response==1 || http.request || http.response || tls.handshake.type==1 || '
          'tls.handshake.type==2 || tls.handshake.type==11')
CANDIDATE = re.compile(r'(update|upgrade|firmware|\bfw|fw[.-]|ota[.-]|[.-]ota|swu|download|dnld|'
                       r'mesu\.apple|gdmf\.apple|appldnld|/firmware|\.bin\b|\.img\b|\.pkg\b|\.ipsw)', re.I)


def out_name(rel):
    return FIELDS_DIR / (rel.replace('/', '__') + '.json')


def extract(rel):
    """tshark field extraction for one capture; leaf DER stored once per hash."""
    out = out_name(rel)
    if out.exists():
        return
    cmd = ['tshark', '-r', str(DATASET / rel), '-Y', FILTER, '-T', 'fields', '-E', 'separator=|',
           '-E', 'occurrence=a', '-E', 'aggregator=,']
    for f in FIELDS:
        cmd += ['-e', f]
    res = subprocess.run(cmd, capture_output=True, text=True)
    rows, certs = [], {}
    for line in res.stdout.splitlines():
        p = line.split('|')
        if len(p) < len(FIELDS):
            continue
        if p[-1]:
            leaf = p[-1].split(',')[0].replace(':', '')
            h = hashlib.sha256(bytes.fromhex(leaf)).hexdigest()
            certs.setdefault(h, {'leaf_der': leaf})
            p[-1] = h
        rows.append(p)
    out.write_text(json.dumps({'pcap': rel, 'fields': FIELDS, 'rows': rows, 'leaf_certs': certs}))


def captures():
    for root, _, files in os.walk(DATASET):
        for f in files:
            if f.endswith('.pcap'):
                yield os.path.relpath(os.path.join(root, f), DATASET)


def device_of(rel):
    parts = rel.split('/')          # iot-data|iot-idle / region / device / ...
    return parts[2] if len(parts) > 2 else parts[-1]


def private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def load_vetted():
    keep, reject = {}, {}
    with open(VETTED, newline='') as fh:
        for r in csv.DictReader(fh):
            (keep if r['decision'] == 'keep' else reject)[r['endpoint']] = r
    return keep, reject


def key_desc(c):
    k = c.public_key()
    if isinstance(k, rsa.RSAPublicKey):
        return f'RSA-{k.key_size}'
    if isinstance(k, ec.EllipticCurvePublicKey):
        return f'EC-{k.curve.key_size}'
    return type(k).__name__


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--jobs', type=int, default=12)
    args = ap.parse_args()
    require(DATASET)
    FIELDS_DIR.mkdir(parents=True, exist_ok=True)
    caps = sorted(captures())
    with ProcessPoolExecutor(args.jobs) as ex:
        list(ex.map(extract, caps, chunksize=64))

    keep, reject = load_vetted()
    cand = collections.defaultdict(collections.Counter)
    flows, leafs, hostnames = [], {}, set()
    for rel in caps:
        d = json.loads(out_name(rel).read_text())
        ix = {k: i for i, k in enumerate(d['fields'])}
        dev = device_of(rel)
        ip2host = {}
        per = {}
        for r in d['rows']:
            for k in ('dns.qry.name', 'tls.handshake.extensions_server_name', 'http.host'):
                for h in r[ix[k]].split(','):
                    if h:
                        hostnames.add(h.lower())
                        if CANDIDATE.search(h):
                            cand[h.lower()][dev] += 1
            uri = r[ix['http.request.uri']]
            if uri and CANDIDATE.search(uri):
                cand[r[ix['http.host']].lower() + ' ' + uri.split('?')[0][:80]][dev] += 1
            q, a = r[ix['dns.qry.name']], r[ix['dns.a']]
            if q and a:
                for qq in q.split(','):
                    if qq.lower() in keep:
                        for aa in a.split(','):
                            ip2host[aa] = qq.lower()
            st = r[ix['tcp.stream']]
            if not st:
                continue
            f = per.setdefault(st, dict(device=dev, capture=rel, stream=st, sni='', host='', uris=[],
                                        proto='', version='', suite='', offered='', certs=[], ips=set()))
            src, dst = r[ix['ip.src']], r[ix['ip.dst']]
            f['ips'].update([src, dst])
            ht = r[ix['tls.handshake.type']].split(',')
            sni = r[ix['tls.handshake.extensions_server_name']]
            if sni:
                f['sni'] = sni.lower()
            if r[ix['http.host']]:
                f['host'] = r[ix['http.host']].split(':')[0].lower()
                f['proto'] = 'HTTP'
            if r[ix['http.request.uri']]:
                f['uris'].append(r[ix['http.request.uri']])
            if '1' in ht and r[ix['tls.handshake.ciphersuite']]:
                f['offered'] = r[ix['tls.handshake.ciphersuite']]
                f['proto'] = f['proto'] or 'TLS'
            if '2' in ht:
                f['proto'] = 'TLS'
                sv = r[ix['tls.handshake.extensions.supported_version']]
                f['version'] = '1.3' if '0x0304' in sv else {'0x0303': '1.2', '0x0302': '1.1', '0x0301': '1.0'}.get(
                    r[ix['tls.handshake.version']].split(',')[0], '?')
                f['suite'] = r[ix['tls.handshake.ciphersuite']].split(',')[0]
            if '11' in ht and r[ix['tls.handshake.certificate']]:
                f['certs'].append((src, r[ix['tls.handshake.certificate']]))
        for f in per.values():
            ep = f['sni'] or f['host']
            if not ep:
                ep = next((ip2host[ip] for ip in f['ips'] if ip in ip2host), '')
            if ep not in keep:
                continue
            rx = keep[ep]['uri_regex']
            if rx and not any(re.search(rx, u) for u in f['uris']):
                continue
            server = next((ip for ip in f['ips'] if not private(ip)), '')
            f['endpoint'], f['role'], f['server'] = ep, keep[ep]['role'], server
            for src, h in f['certs']:
                role = 'server' if src == server else 'client'
                c = x509.load_der_x509_certificate(bytes.fromhex(d['leaf_certs'][h]['leaf_der']))
                # a client certificate's subject names the device (e.g. its MAC address): withheld
                subject = getattr((c.subject.get_attributes_for_oid(NameOID.COMMON_NAME) or [None])[0], 'value', '')
                rec = leafs.setdefault((ep, role, h), dict(
                    endpoint=ep, role=role,
                    subject=subject if role == 'server' else '(withheld: device identifier)',
                    issuer=getattr((c.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) or [None])[0], 'value', ''),
                    key=key_desc(c), not_before=c.not_valid_before_utc.date().isoformat(),
                    not_after=c.not_valid_after_utc.date().isoformat(),
                    validity_days=(c.not_valid_after_utc - c.not_valid_before_utc).days, connections=0))
                rec['connections'] += 1
            flows.append(f)

    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / 'candidates.csv', 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['candidate', 'devices', 'decision'])
        for c, devs in sorted(cand.items()):
            host = c.split(' ')[0]
            dec = 'keep' if host in keep else 'reject' if host in reject else 'unvetted'
            w.writerow([c, ';'.join(f'{k}:{v}' for k, v in devs.most_common()), dec])
    with open(OUT / 'update_flows.csv', 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['device', 'capture', 'stream', 'endpoint', 'role', 'proto', 'tls_version', 'suite', 'label',
                    'offered_config'])
        for f in flows:
            w.writerow([f['device'], f['capture'], f['stream'], f['endpoint'], f['role'], f['proto'], f['version'],
                        name(f['suite']) if f['suite'] else '', label(f['suite']) if f['suite'] else '',
                        config_key(f['offered']) if f['offered'] else ''])
    with open(OUT / 'leaf_certs.csv', 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=['endpoint', 'role', 'subject', 'issuer', 'key', 'not_before', 'not_after',
                                           'validity_days', 'connections'])
        w.writeheader()
        w.writerows(sorted(leafs.values(), key=lambda r: (r['endpoint'], r['role'])))

    labels = {f['device'] for f in flows}
    funnel = [('captures', len(caps)),
              ('captures_iot_data', sum(1 for c in caps if c.startswith('iot-data/'))),
              ('captures_iot_idle', sum(1 for c in caps if c.startswith('iot-idle/'))),
              ('distinct_hostnames', len(hostnames)),
              ('captures_with_update_traffic', len({f['capture'] for f in flows})),
              ('update_flows', len(flows)),
              ('update_flows_tls', sum(1 for f in flows if f['proto'] == 'TLS')),
              ('update_flows_http', sum(1 for f in flows if f['proto'] == 'HTTP')),
              ('confirmed_update_servers', len({f['endpoint'] for f in flows})),
              ('device_labels', len(labels)),
              # 't-' labels are second units of a model already in the testbed
              ('device_models', len({d[2:] if d.startswith('t-') else d for d in labels}))]
    with open(OUT / 'funnel.csv', 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['metric', 'value'])
        w.writerows(funnel)

    tls = [f for f in flows if f['proto'] == 'TLS' and f['suite']]
    print('captures', len(caps), '| distinct hostnames', len(hostnames),
          '| captures with update flows', len({f['capture'] for f in flows}),
          '| update flows', len(flows), dict(collections.Counter(f['proto'] for f in flows)))
    print('device labels', len({f['device'] for f in flows}), sorted({f['device'] for f in flows}))
    print('endpoints', len({f['endpoint'] for f in flows}))
    print('TLS versions', dict(collections.Counter(f['version'] for f in tls)),
          '| negotiated labels', dict(collections.Counter(label(f['suite']) for f in tls)))
    print('HTTP device labels', sorted({f['device'] for f in flows if f['proto'] == 'HTTP'}))
    for r in sorted(leafs.values(), key=lambda r: (r['endpoint'], r['role'])):
        print('leaf', r['endpoint'], r['role'], r['subject'], '|', r['issuer'], r['key'], r['validity_days'], 'd')
    cfgs = collections.defaultdict(set)
    for f in flows:
        if f['offered']:
            cfgs[f['device']].add(config_key(f['offered']))
    with open(OUT / 'offered_configs.csv', 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['device', 'suites', 'recommended', 'secure', 'weak', 'insecure', 'offers_tls13', 'insecure_names'])
        for dev, S in sorted(cfgs.items()):
            for cfg in sorted(S):
                codes = [c for c in cfg.split(',') if c != 'GREASE']
                labs = collections.Counter(label(c) for c in codes)
                w.writerow([dev, sum(v for k, v in labs.items() if k != 'signal'), labs['recommended'], labs['secure'],
                            labs['weak'], labs['insecure'], any(c in ('1301', '1302', '1303') for c in codes),
                            ';'.join(name(c) for c in codes if label(c) == 'insecure')])
    for dev, S in sorted(cfgs.items()):
        for cfg in S:
            codes = [c for c in cfg.split(',') if c != 'GREASE']
            ins = [name(c) for c in codes if label(c) == 'insecure']
            tls13 = any(c in ('1301', '1302', '1303') for c in codes)
            print(f'offered {dev:22s} suites={sum(1 for c in codes if label(c) != "signal"):3d} '
                  f'weak={sum(1 for c in codes if label(c) == "weak"):3d} tls13={tls13} insecure={ins}')


if __name__ == '__main__':
    main()
