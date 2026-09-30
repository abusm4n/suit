#!/usr/bin/env python3
"""Update-traffic attribution for the controlled captures (SAC 2027 revision).

For each device capture (controlled/dataset/<dev>/<dev>_filtered.pcapng) this script
1. extracts per-packet 5-tuples and lengths and the DNS / HTTP / TLS handshake events
   with tshark,
2. rebuilds bidirectional flows (TCP connections, UDP conversations) and splits them
   into LAN and WAN flows,
3. attributes flows to the update process using data/reference/confirmed_update_servers_controlled.csv
   (SNI or HTTP Host; for TLS without SNI, the DNS name resolved for the server address),
4. reports negotiated and offered TLS parameters of update connections with the
   ciphersuite.info snapshot labels (tls_classes.py), and
5. parses the server leaf certificates of TLS <= 1.2 update connections.

Outputs (data/derived/controlled/): flows.csv, funnel.csv, tls_update.csv,
offered_configs.csv, leaf_certs.csv. The printed summary gives the numbers used in
Tables 1 and 3 of the paper. tshark extractions are cached in cache/controlled/.

Usage:  python3 src/update_attribution/controlled_attribution.py [--refresh]
        (--refresh re-runs tshark; otherwise cached extractions are reused)
"""
import argparse
import collections
import csv
import hashlib
import ipaddress
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tls_classes import config_key, label, name  # noqa: E402

from paths import CACHE_CONTROLLED as CACHE, DERIVED_CONTROLLED as OUT, RAW_CONTROLLED as DATA  # noqa: E402
from paths import SERVERS_CONTROLLED as VETTED, require  # noqa: E402

# dataset folder -> (capture file, device IP, name used in the paper)
DEVICES = {
    'apple-tv':  ('apple-tv/apple-tv_filtered.pcapng', '10.42.0.25', 'apple-tv'),
    'dlink':     ('dlink/dlink_filtered.pcapng', '10.42.0.152', 'd-link-cam'),
    'eufy':      ('eufy/eufy_filtered.pcapng', '10.42.0.160', 'eufy-cam'),
    'fire-tv':   ('fire-tv/fire-tv_filtered.pcapng', '10.42.0.23', 'fire-tv'),
    'homepod':   ('homepod/homepod_filtered.pcapng', '10.42.0.79', 'homepod'),
    'riolink':   ('riolink/riolink_filtered.pcapng', '10.42.0.170', 'reolink-cam'),
    'sony-tv':   ('sony-tv/sony_tv_filtered.pcapng', '10.42.0.157', 'sony-tv'),
    'tapo-c100': ('tapo-c100/tapo-c100_filtered.pcapng', '10.42.0.135', 'tapo-c100'),
    'tapo-c200': ('tapo-c200/tapo-c200_filtered.pcapng', '10.42.0.173', 'tapo-c200'),
    'xiaomi':    ('xiaomi/xiaomi_filtered.pcapng', '10.42.0.207', 'xiaomi-cam'),
}

PKT_FIELDS = ['frame.time_epoch', 'frame.len', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst',
              'tcp.stream', 'udp.stream', 'tcp.srcport', 'tcp.dstport', 'udp.srcport',
              'udp.dstport', 'tcp.len', 'udp.length']
EVT_FIELDS = ['frame.number', 'ip.src', 'ip.dst', 'tcp.stream', 'dns.qry.name', 'dns.a',
              'http.host', 'http.request.method', 'http.request.uri', 'http.content_type',
              'http.content_length', 'tls.handshake.type', 'tls.handshake.extensions_server_name',
              'tls.handshake.extensions.supported_version', 'tls.handshake.ciphersuite']
EVT_FILTER = ('dns.flags.response==1 || http.request || http.response || '
              'tls.handshake.type==1 || tls.handshake.type==2')


def tshark_fields(pcap, fields, display_filter=None):
    cmd = ['tshark', '-r', str(pcap), '-T', 'fields', '-E', 'separator=|']
    if display_filter:
        cmd += ['-Y', display_filter]
    for f in fields:
        cmd += ['-e', f]
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def cached(path, producer, refresh):
    if refresh or not path.exists():
        path.write_text(producer())
    return path.read_text()


def is_lan(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_multicast or a.is_link_local or a.is_unspecified or ip.startswith('255.')


def build_flows(dev_ip, pkt_text):
    flows = {}
    for line in pkt_text.splitlines():
        p = line.split('|')
        if len(p) < 14:
            continue
        t, flen, s, d, s6, d6, ts, us, tsp, tdp, usp, udp_, tl, ul = p[:14]
        s, d = s or s6, d or d6
        if not s:
            continue
        if ts:
            key, sp, dp, pl = ('tcp', ts), tsp, tdp, int(tl or 0)
        elif us:
            key, sp, dp = ('udp', us), usp, udp_
            pl = max(int((ul or '8').split(',')[0]) - 8, 0)
        else:
            continue
        f = flows.setdefault(key, dict(proto=key[0], stream=key[1], a=s, b=d, ap=sp, bp=dp,
                                       up=0, down=0, t0=float(t), t1=float(t)))
        f['t1'] = float(t)
        if s == dev_ip:
            f['up'] += pl
        else:
            f['down'] += pl
    for f in flows.values():
        if f['a'] == dev_ip:
            f['remote'], f['rport'] = f['b'], f['bp']
        else:
            f['remote'], f['rport'] = f['a'], f['ap']
        f['lan'] = is_lan(f['remote'])
    return flows


def add_events(flows, evt_text):
    ip2name = collections.defaultdict(set)
    for line in evt_text.splitlines():
        p = line.split('|')
        if len(p) < 15:
            continue
        _, src, _, st, qn, da, host, meth, uri, _, _, ht, sni, sv, cs = p[:15]
        if qn and da:
            for a in da.split(','):
                ip2name[a].update(qn.split(','))
        if not st or ('tcp', st) not in flows:
            continue
        f = flows[('tcp', st)]
        if ht.startswith('1'):
            if sni:
                f['sni'] = sni
            f.setdefault('offered', cs)
        if ht.startswith('2'):
            f['tls_version'] = '1.3' if sv else '1.2'
            f['suite'] = cs.split(',')[0]
        if host:
            f['http_host'] = host.split(':')[0]
        if meth:
            f.setdefault('uris', []).append(uri)
    for f in flows.values():
        f['dns_names'] = sorted(ip2name.get(f['remote'], set()))


def load_vetted():
    vetted = collections.defaultdict(dict)
    with open(VETTED, newline='') as fh:
        for r in csv.DictReader(fh):
            vetted[r['device']][r['endpoint']] = (r['role'], r['confidence'])
    return vetted


def attribute(dev, flows, vetted):
    v = vetted.get(dev, {})
    for f in flows.values():
        f['endpoint'] = ''
        if f['lan']:
            lan_key = 'LAN:' + f['remote']
            if lan_key in v:
                f['endpoint'] = lan_key
            continue
        name_ = f.get('sni') or f.get('http_host')
        if not name_:
            hits = [n for n in f['dns_names'] if n in v]
            name_ = hits[0] if hits else None
        if name_ in v:
            f['endpoint'] = name_


def leaf_certs(pcap, streams):
    """Server leaf certificates (first certificate sent by the server) per stream."""
    if not streams:
        return []
    flt = ' || '.join(f'tcp.stream=={s}' for s in streams)
    out = tshark_fields(pcap, ['tcp.stream', 'ip.src', 'tls.handshake.certificate'],
                        f'tls.handshake.type==11 && ({flt})')
    seen = {}
    for line in out.splitlines():
        st, src, chain = line.split('|', 2)
        if src != streams[st]['server'] or not chain:
            continue
        der = bytes.fromhex(chain.split(',')[0].replace(':', ''))
        c = x509.load_der_x509_certificate(der)
        fp = hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest()[:16]
        k = c.public_key()
        if isinstance(k, rsa.RSAPublicKey):
            key = f'RSA-{k.key_size}'
        elif isinstance(k, ec.EllipticCurvePublicKey):
            key = f'EC-{k.curve.key_size}'
        else:
            key = type(k).__name__
        cn = lambda n: (n.get_attributes_for_oid(NameOID.COMMON_NAME) or [None])[0]
        rec = seen.setdefault(fp, dict(
            endpoint=streams[st]['endpoint'], subject=getattr(cn(c.subject), 'value', ''),
            issuer=getattr(cn(c.issuer), 'value', ''), key=key,
            not_before=c.not_valid_before_utc.date().isoformat(),
            not_after=c.not_valid_after_utc.date().isoformat(),
            validity_days=(c.not_valid_after_utc - c.not_valid_before_utc).days,
            self_signed=c.subject == c.issuer, connections=0))
        rec['connections'] += 1
    return list(seen.values())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--refresh', action='store_true', help='re-run tshark instead of using the cache')
    args = ap.parse_args()
    require(DATA)
    CACHE.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    vetted = load_vetted()
    flow_rows, funnel, tls_rows, cfg_rows, cert_rows = [], [], [], [], []
    for dev, (rel, ip, paper) in DEVICES.items():
        pcap = DATA / rel
        pk = cached(CACHE / f'{dev}.pkts.txt', lambda: tshark_fields(pcap, PKT_FIELDS), args.refresh)
        ev = cached(CACHE / f'{dev}.events.txt', lambda: tshark_fields(pcap, EVT_FIELDS, EVT_FILTER), args.refresh)
        flows = build_flows(ip, pk)
        add_events(flows, ev)
        attribute(dev, flows, vetted)
        upd = [f for f in flows.values() if f['endpoint']]
        lan = [f for f in flows.values() if f['lan']]
        total_bytes = sum(f['up'] + f['down'] for f in flows.values()) or 1
        upd_bytes = sum(f['up'] + f['down'] for f in upd)
        funnel.append(dict(device=paper, flows=len(flows), lan=len(lan), wan=len(flows) - len(lan),
                           update_flows=len(upd), update_tls=sum(1 for f in upd if f.get('suite')),
                           update_http=sum(1 for f in upd if f.get('http_host') and not f.get('suite')),
                           update_lan=sum(1 for f in upd if f['lan']),
                           update_mb=round(upd_bytes / 1e6, 2), update_share=round(upd_bytes / total_bytes, 3),
                           endpoints=';'.join(sorted({f['endpoint'] for f in upd}))))
        for f in flows.values():
            flow_rows.append(dict(device=paper, proto=f['proto'], stream=f['stream'], remote=f['remote'],
                                  rport=f['rport'], lan=f['lan'], sni=f.get('sni', ''),
                                  http_host=f.get('http_host', ''), dns_names=';'.join(f['dns_names'][:3]),
                                  bytes_up=f['up'], bytes_down=f['down'], t0=f['t0'], t1=f['t1'],
                                  endpoint=f['endpoint'],
                                  role=vetted[dev].get(f['endpoint'], ('', ''))[0] if f['endpoint'] else '',
                                  confidence=vetted[dev].get(f['endpoint'], ('', ''))[1] if f['endpoint'] else '',
                                  tls_version=f.get('tls_version', ''), suite=name(f['suite']) if f.get('suite') else '',
                                  suite_label=label(f['suite']) if f.get('suite') else '',
                                  offered_config=config_key(f['offered']) if f.get('offered') else ''))
        neg = collections.Counter((f['endpoint'], f['tls_version'], name(f['suite']), label(f['suite']))
                                  for f in upd if f.get('suite'))
        for (ep, ver, sname, lab), n in sorted(neg.items()):
            tls_rows.append(dict(device=paper, endpoint=ep, tls_version=ver, suite=sname, label=lab, connections=n))
        cfgs = collections.Counter(config_key(f['offered']) for f in upd if f.get('offered'))
        for cfg, n in cfgs.items():
            codes = [c for c in cfg.split(',') if c != 'GREASE']
            labs = collections.Counter(label(c) for c in codes)
            cfg_rows.append(dict(device=paper, connections=n, suites=sum(v for k, v in labs.items() if k != 'signal'),
                                 recommended=labs['recommended'], secure=labs['secure'], weak=labs['weak'],
                                 insecure=labs['insecure'], signal=labs['signal'],
                                 insecure_names=';'.join(name(c) for c in codes if label(c) == 'insecure'),
                                 offers_tls13=any(c in ('1301', '1302', '1303') for c in codes)))
        streams = {f['stream']: dict(endpoint=f['endpoint'], server=f['remote'])
                   for f in upd if f.get('tls_version') == '1.2'}
        for rec in leaf_certs(pcap, streams):
            cert_rows.append(dict(device=paper, **rec))

    def write(fname, rows):
        if rows:
            with open(OUT / fname, 'w', newline='') as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0]))
                w.writeheader()
                w.writerows(rows)
    write('flows.csv', flow_rows)
    write('funnel.csv', funnel)
    write('tls_update.csv', tls_rows)
    write('offered_configs.csv', cfg_rows)
    write('leaf_certs.csv', cert_rows)

    tot = collections.Counter()
    for r in funnel:
        for k in ('flows', 'lan', 'wan', 'update_flows', 'update_tls', 'update_http', 'update_lan'):
            tot[k] += r[k]
        print(f"{r['device']:12s} flows={r['flows']:4d} LAN={r['lan']:4d} WAN={r['wan']:4d} "
              f"update={r['update_flows']:4d} ({r['update_mb']:8.1f} MB, {100 * r['update_share']:5.1f}%)")
    endpoints = {e for r in funnel for e in r['endpoints'].split(';') if e and not e.startswith('LAN:')}
    print('TOTAL', dict(tot), 'vetted hostnames with update flows:', len(endpoints),
          'devices with update flows:', sum(1 for r in funnel if r['update_flows']))
    labs = collections.Counter()
    for r in tls_rows:
        labs[r['label']] += r['connections']
    print('negotiated on update connections:', dict(labs))
    for r in cert_rows:
        print('leaf', r['device'], r['endpoint'], r['issuer'], r['key'], r['validity_days'], 'd')


if __name__ == '__main__':
    main()
