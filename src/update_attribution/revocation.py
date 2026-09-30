#!/usr/bin/env python3
"""Revocation checking on update channels (Section 5.3 and the revocation table).

A long-lived update-server certificate is a lasting risk mainly if it cannot be
withdrawn after a key compromise. For every TLS update connection (controlled captures:
flows.csv; 2019 traces: update_flows.csv) this script records

  - the revocation sources named in the server's leaf certificate: the OCSP responder
    in the Authority Information Access extension and the CRL distribution points;
  - whether the client asks for a stapled OCSP response (status_request extension in
    the ClientHello, visible in TLS 1.2 and 1.3);
  - whether the server staples one (CertificateStatus message, visible in TLS 1.2 only,
    because TLS 1.3 encrypts it);

and, per capture, whether the device contacted an OCSP or CRL server at all (a DNS
query, HTTP Host header or TLS server name containing "ocsp" or "crl").

Outputs (one row per dataset, device and update server):
  data/derived/controlled/revocation.csv
  data/derived/retrospective/revocation.csv
and a summary on stdout.

Usage: python3 src/update_attribution/revocation.py [--jobs 12]
"""
import argparse
import collections
import csv
import subprocess
import warnings
from concurrent.futures import ProcessPoolExecutor

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from paths import CONTROLLED_CAPTURES as FILES, DERIVED_CONTROLLED as CTRL, DERIVED_RETRO as RETRO
from paths import RAW_CONTROLLED as CTRL_PCAPS, RAW_RETRO as RETRO_PCAPS, require
LOOKUP_WORDS = ('ocsp', 'crl')
warnings.filterwarnings('ignore', message='Parsed a serial number')   # 2019 SmartThings leaf


def revocation_sources(der):
    cert = x509.load_der_x509_certificate(der)
    ocsp, crl = [], []
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsp = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.OCSP]
    except x509.ExtensionNotFound:
        pass
    try:
        for dp in cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value:
            crl += [n.value for n in (dp.full_name or [])]
    except x509.ExtensionNotFound:
        pass
    return cert.issuer.rfc4514_string(), ocsp, crl


def handshakes(pcap, streams):
    """Per TCP stream: status_request offered, CertificateStatus seen, leaf certificate."""
    flt = 'tls.handshake && (' + ' || '.join(f'tcp.stream=={s}' for s in streams) + ')'
    out = subprocess.run(['tshark', '-r', str(pcap), '-Y', flt, '-T', 'fields', '-E', 'separator=|',
                          '-E', 'occurrence=a', '-E', 'aggregator=;', '-e', 'tcp.stream', '-e', 'tls.handshake.type',
                          '-e', 'tls.handshake.extension.type', '-e', 'tls.handshake.certificate'],
                         capture_output=True, text=True).stdout
    per = collections.defaultdict(lambda: dict(requested=False, stapled=False, leaf=None))
    for line in out.splitlines():
        st, types, exts, certs = (line.split('|') + ['', '', ''])[:4]
        t = set(types.split(';')) if types else set()
        if '1' in t and '5' in exts.split(';'):          # ClientHello with status_request
            per[st]['requested'] = True
        if '22' in t:                                     # CertificateStatus
            per[st]['stapled'] = True
        if certs and per[st]['leaf'] is None:
            per[st]['leaf'] = bytes.fromhex(certs.split(';')[0].replace(':', ''))
    return per


def lookups(pcap):
    """Names of OCSP or CRL servers the device contacted anywhere in the capture."""
    out = subprocess.run(['tshark', '-r', str(pcap), '-Y', 'dns.flags.response==0 || http.request || '
                          'tls.handshake.type==1', '-T', 'fields', '-E', 'separator=|', '-e', 'dns.qry.name',
                          '-e', 'http.host', '-e', 'tls.handshake.extensions_server_name'],
                         capture_output=True, text=True).stdout
    return sorted({n.lower() for line in out.splitlines() for n in line.split('|')
                   if n and any(w in n.lower() for w in LOOKUP_WORDS)})


def one_capture(job):
    dataset, device, pcap, flows = job
    streams = sorted({f['stream'] for f in flows}, key=int)
    per = handshakes(pcap, streams)
    res = []
    for f in flows:
        h = per.get(f['stream'])
        if h is None:
            continue
        src = revocation_sources(h['leaf']) if h['leaf'] else None
        res.append((f['endpoint'], f['device'], f['tls_version'], h['requested'], h['stapled'], src))
    return dataset, device, res, lookups(pcap)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--jobs', type=int, default=12)
    args = ap.parse_args()
    require(CTRL_PCAPS, RETRO_PCAPS)
    jobs = []
    ctrl = [f for f in csv.DictReader(open(CTRL / 'flows.csv')) if f['endpoint'] and f['tls_version']]
    by_dev = collections.defaultdict(list)
    for f in ctrl:
        by_dev[f['device']].append(f)
    for dev, fl in by_dev.items():
        jobs.append(('controlled', dev, CTRL_PCAPS / FILES[dev], fl))
    retro = [f for f in csv.DictReader(open(RETRO / 'update_flows.csv')) if f['proto'] == 'TLS']
    by_cap = collections.defaultdict(list)
    for f in retro:
        by_cap[f['capture']].append(f)
    for cap, fl in by_cap.items():
        jobs.append(('retrospective', fl[0]['device'], RETRO_PCAPS / cap, fl))

    agg = collections.defaultdict(lambda: dict(connections=0, staple_requested=0, stapled=0, tls12=0,
                                               issuer='', ocsp='', crl=''))
    caps = collections.defaultdict(lambda: dict(captures=0, with_lookup=0, hosts=collections.Counter()))
    with ProcessPoolExecutor(args.jobs) as ex:
        for dataset, device, res, names in ex.map(one_capture, jobs, chunksize=4):
            c = caps[(dataset, device)]
            c['captures'] += 1
            c['with_lookup'] += bool(names)
            c['hosts'].update(names)
            for ep, dev, ver, req, stp, src in res:
                a = agg[(dataset, dev, ep)]
                a['connections'] += 1
                a['staple_requested'] += req
                a['stapled'] += stp
                a['tls12'] += ver == '1.2'
                if src and not a['issuer']:
                    a['issuer'], ocsp, crl = src
                    a['ocsp'], a['crl'] = ' '.join(ocsp) or 'none', ' '.join(crl) or 'none'
    for dataset, out in (('controlled', CTRL), ('retrospective', RETRO)):
        rows = []
        for (ds, dev, ep), a in sorted(agg.items()):
            if ds != dataset:
                continue
            c = caps[(ds, dev)]
            rows.append(dict(device=dev, endpoint=ep, **a, captures=c['captures'],
                             captures_with_revocation_lookup=c['with_lookup'],
                             lookup_hosts=' '.join(sorted(c['hosts']))))
        with open(out / 'revocation.csv', 'w', newline='') as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f'== {dataset}: {out / "revocation.csv"}')
        for r in rows:
            print(f"  {r['device']:22s} {r['endpoint']:34s} conns={r['connections']:5d} "
                  f"requested={r['staple_requested']:5d} stapled={r['stapled']:4d}/{r['tls12']:<5d} "
                  f"ocsp={'yes' if r['ocsp'] not in ('', 'none') else r['ocsp'] or '?':4s} "
                  f"crl={'yes' if r['crl'] not in ('', 'none') else r['crl'] or '?':4s} "
                  f"lookups={r['captures_with_revocation_lookup']}/{r['captures']} {r['lookup_hosts'][:60]}")


if __name__ == '__main__':
    main()
