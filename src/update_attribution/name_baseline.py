#!/usr/bin/env python3
"""Name-level baseline for the 2019 (Mon(IoT)r) traces, and facts about the attributed traffic.

The keyword baseline (keyword_baseline.py) matches words anywhere in the dissected packets. This
script measures the stronger baseline that the attribution's candidate step itself uses: the
update patterns of retrospective_attribution.CANDIDATE applied to server names (DNS query, TLS
SNI, HTTP Host, and for TLS without SNI the DNS name resolved for the server address) and HTTP
URIs. It reports how many names, captures, and flows match, and how many of those are confirmed
update traffic (update_flows.csv), also without the Apple server names in the pattern. It also
records in which experiment types the update captures lie and whether any update ClientHello
carries TLS_FALLBACK_SCSV (0x5600).

Reads the cached tshark extractions of retrospective_attribution.py (cache/retrospective/fields/)
and data/derived/retrospective/update_flows.csv; writes data/derived/retrospective/name_baseline.csv.

Usage: python3 src/update_attribution/name_baseline.py
"""
import collections
import csv
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import retrospective_attribution as ra  # noqa: E402
from paths import CACHE_RETRO_FIELDS, DERIVED_RETRO as OUT, require  # noqa: E402

# the candidate pattern without the documented Apple update-server names
GENERIC = re.compile(ra.CANDIDATE.pattern.replace(r'mesu\.apple|gdmf\.apple|appldnld|', ''), re.I)


def experiment(capture):
    """iot-idle captures are idle; iot-data/<lab>/<device>/<experiment>/<file>.pcap otherwise."""
    if capture.startswith('iot-idle/'):
        return 'idle'
    exp = capture.split('/')[3]
    return exp if exp == 'power' else 'interaction'


def main():
    require(CACHE_RETRO_FIELDS)
    with open(OUT / 'update_flows.csv', newline='') as fh:
        upd = list(csv.DictReader(fh))
    upd_keys = {(r['capture'], r['stream']) for r in upd}
    upd_caps = {r['capture'] for r in upd}

    names, m_names = set(), set()
    caps = {'pattern': set(), 'generic': set()}
    flows = collections.Counter()
    fallback = 0
    for rel in sorted(ra.captures()):
        d = json.loads(ra.out_name(rel).read_text())
        ix = {k: i for i, k in enumerate(d['fields'])}
        ip2host, per = {}, {}
        for r in d['rows']:
            for k in ('dns.qry.name', 'tls.handshake.extensions_server_name', 'http.host'):
                for h in r[ix[k]].split(','):
                    if h:
                        names.add(h.lower())
                        if ra.CANDIDATE.search(h):
                            m_names.add(h.lower())
                        for key, rx in (('pattern', ra.CANDIDATE), ('generic', GENERIC)):
                            if rx.search(h):
                                caps[key].add(rel)     # a capture matches on any name, DNS lookups included
            uri = r[ix['http.request.uri']]
            for key, rx in (('pattern', ra.CANDIDATE), ('generic', GENERIC)):
                if uri and rx.search(uri):
                    caps[key].add(rel)
            q, a = r[ix['dns.qry.name']], r[ix['dns.a']]
            if q and a:
                for qq in q.split(','):
                    for aa in a.split(','):
                        ip2host[aa] = qq.lower()
            st = r[ix['tcp.stream']]
            if not st:
                continue
            f = per.setdefault(st, dict(sni='', host='', uris=[], ips=set()))
            f['ips'].update([r[ix['ip.src']], r[ix['ip.dst']]])
            if r[ix['tls.handshake.extensions_server_name']]:
                f['sni'] = r[ix['tls.handshake.extensions_server_name']].lower()
            if r[ix['http.host']]:
                f['host'] = r[ix['http.host']].split(':')[0].lower()
            if uri:
                f['uris'].append(uri)
            if ((rel, st) in upd_keys and '1' in r[ix['tls.handshake.type']].split(',')
                    and '0x5600' in r[ix['tls.handshake.ciphersuite']].lower()):
                fallback += 1
        for st, f in per.items():
            ep = f['sni'] or f['host'] or next((ip2host[ip] for ip in f['ips'] if ip in ip2host), '')
            if not ep:
                continue
            is_upd = (rel, st) in upd_keys
            for key, rx in (('pattern', ra.CANDIDATE), ('generic', GENERIC)):
                if rx.search(ep) or any(rx.search(u) for u in f['uris']):
                    flows[key] += 1
                    flows[key + '_update'] += is_upd

    exp = collections.Counter(experiment(c) for c in upd_caps)
    rows = [('distinct_names', len(names)),
            ('names_matching_pattern', len(m_names)),
            ('captures_matching_pattern', len(caps['pattern'])),
            ('captures_matching_pattern_with_update_traffic', len(caps['pattern'] & upd_caps)),
            ('flows_matching_pattern', flows['pattern']),
            ('flows_matching_pattern_update', flows['pattern_update']),
            ('update_captures_missed_without_apple_names', len(upd_caps - caps['generic'])),
            ('update_flows_total', len(upd)),
            ('update_captures_power', exp['power']),
            ('update_captures_idle', exp['idle']),
            ('update_captures_interaction', exp['interaction']),
            ('update_clienthellos_with_fallback_scsv', fallback)]
    for k, v in rows:
        print(f'{k:50s} {v}')
    with open(OUT / 'name_baseline.csv', 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['metric', 'value'])
        w.writerows(rows)
    print('wrote', (OUT / 'name_baseline.csv').relative_to(OUT.parents[2]))


if __name__ == '__main__':
    main()
