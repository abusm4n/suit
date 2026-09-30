#!/usr/bin/env python3
"""What unencrypted update exchanges reveal to a passive observer (Section 5.2 and the
exposure table).

Extracts every request of the unencrypted (HTTP) update flows in both datasets (request
line, Host, User-Agent and body; Base64 bodies are decoded) and records which device
attributes it discloses: model, hardware revision, installed version, offered (target)
version, region, and persistent device identifiers such as MAC addresses. The vendor
formats are parsed with the patterns below; MAC addresses are recorded only as present or
absent, never written out.

Outputs:
  data/derived/controlled/exposure.csv
  data/derived/retrospective/exposure.csv

Usage: python3 src/update_attribution/exposure.py
"""
import base64
import binascii
import collections
import csv
import re
import subprocess

from paths import CONTROLLED_CAPTURES as FILES, DERIVED_CONTROLLED as CTRL, DERIVED_RETRO as RETRO
from paths import RAW_CONTROLLED as CTRL_PCAPS, RAW_RETRO as RETRO_PCAPS, require
MAC = r'(?:[0-9A-Fa-f]{2}[:-]?){5}[0-9A-Fa-f]{2}'

# (field, regex over "METHOD host uri | user-agent | body"); named groups become values
PATTERNS = [
    # TP-Link Tapo image URL: /firmware/Tapo_C200v1_en_1.3.16_Build_240909_...
    ('tapo', r'/firmware/Tapo_(?P<model>C\d+)v(?P<hardware>\d+)_(?P<region>[a-z]{2})_(?P<offered>\d+\.\d+\.\d+)'
             r'_Build_(?P<build>\d+)'),
    # D-Link firmware query: model=<model>_<hw>_<variant>_FW_<version>_<MAC>
    ('dlink', r'model=(?P<model>[A-Z]+-[A-Z0-9]+)_(?P<hardware>[A-Z][a-z])_\w+?_FW_(?P<installed>\d+)_(?P<mac>'
              + MAC + r')'),
    # Samsung firmware header: /firmware/tv/<n>/SWU-OU_<firmware line>_<version>_<date>/OUITHeaders.dat;
    # the firmware line encodes the TV platform and the sales region
    ('samsung', r'/firmware/tv/\d+/SWU-OU_(?P<model>T-[A-Z0-9]+)_(?P<offered>\d+)_'),
    # Apple User-Agent: iOS/12.2.1 AppleTV/12.2.1 model/AppleTV5,3 hwp/t7000 build/16L250
    ('apple', r'AppleTV/(?P<installed>[\d.]+) model/(?P<model>[\w,]+) hwp/(?P<hardware>\w+) build/(?P<build>\w+)'),
]
# LG update check: Base64-encoded XML with <MODEL_NM>, <MAJOR_VER>, <MINOR_VER>, <COUNTRY>, <DEVICE_ID>
LG_TAGS = dict(model='MODEL_NM', installed_major='MAJOR_VER', installed_minor='MINOR_VER', region='COUNTRY',
               mac='DEVICE_ID', platform='PRODUCT_NM')


def decode_body(hexdata):
    if not hexdata:
        return ''
    try:
        raw = binascii.unhexlify(hexdata.replace(':', ''))
    except (binascii.Error, ValueError):
        return ''
    try:
        dec = base64.b64decode(raw, validate=True)
        if dec.lstrip().startswith(b'<'):
            return dec.decode('utf-8', 'replace')
    except (binascii.Error, ValueError):
        pass
    return raw.decode('utf-8', 'replace')


def attributes(text):
    found = {}
    for _, pat in PATTERNS:
        m = re.search(pat, text)
        if m:
            found.update({k: v for k, v in m.groupdict().items() if v})
    for key, tag in LG_TAGS.items():
        m = re.search(f'<{tag}>([^<]*)</{tag}>', text)
        if m and m.group(1):
            found[key] = m.group(1)
    if 'installed_major' in found:
        found['installed'] = f"{found.pop('installed_major')}.{found.pop('installed_minor', '')}"
    return found


def requests(pcap, streams):
    flt = 'http.request && (' + ' || '.join(f'tcp.stream=={s}' for s in streams) + ')'
    out = subprocess.run(['tshark', '-r', str(pcap), '-Y', flt, '-T', 'fields', '-E', 'separator=|',
                          '-e', 'tcp.stream', '-e', 'http.request.method', '-e', 'http.host', '-e', 'http.request.uri',
                          '-e', 'http.user_agent', '-e', 'http.file_data'], capture_output=True, text=True).stdout
    for line in out.splitlines():
        st, method, host, uri, ua, body = (line.split('|') + [''] * 5)[:6]
        yield st, method, host, uri, ua, decode_body(body)


def main():
    require(CTRL_PCAPS, RETRO_PCAPS)
    jobs = []
    ctrl = [f for f in csv.DictReader(open(CTRL / 'flows.csv'))
            if f['endpoint'] and not f['tls_version'] and f['lan'] != 'True' and f['proto'] == 'tcp']
    by_dev = collections.defaultdict(list)
    for f in ctrl:
        by_dev[f['device']].append(f)
    for dev, fl in by_dev.items():
        jobs.append(('controlled', CTRL_PCAPS / FILES[dev], fl))
    retro = [f for f in csv.DictReader(open(RETRO / 'update_flows.csv')) if f['proto'] == 'HTTP']
    by_cap = collections.defaultdict(list)
    for f in retro:
        by_cap[f['capture']].append(f)
    for cap, fl in by_cap.items():
        jobs.append(('retrospective', RETRO_PCAPS / cap, fl))
    agg = collections.OrderedDict()
    for dataset, pcap, fl in jobs:
        ep_of = {f['stream']: (f['device'], f['endpoint']) for f in fl}
        for st, method, host, uri, ua, body in requests(pcap, list(ep_of)):
            dev, ep = ep_of[st]
            found = attributes(' '.join([method, host, uri]) + ' | ' + ua + ' | ' + body)
            key = (dataset, dev, ep)
            example = f'{method} {uri}'[:120]
            if found.get('mac'):          # never write a device's MAC address out
                example = example.replace(found['mac'], '<MAC>')
                found['mac'] = 'yes'
            a = agg.setdefault(key, dict(requests=0, example_request=example,
                                         fields=collections.Counter(), values={}))
            a['requests'] += 1
            for k, v in found.items():
                a['fields'][k] += 1
                a['values'].setdefault(k, v)
    names = ['model', 'hardware', 'installed', 'offered', 'build', 'region', 'mac', 'platform']
    for dataset, out in (('controlled', CTRL), ('retrospective', RETRO)):
        rows = []
        for (ds, dev, ep), a in agg.items():
            if ds != dataset:
                continue
            row = dict(device=dev, endpoint=ep, requests=a['requests'])
            for k in names:
                row[k] = a['values'].get(k, '')
            row['example_request'] = a['example_request']
            rows.append(row)
        with open(out / 'exposure.csv', 'w', newline='') as fh:
            w = csv.DictWriter(fh, fieldnames=['device', 'endpoint', 'requests'] + names + ['example_request'])
            w.writeheader()
            w.writerows(rows)
        print(f'== {dataset}: {out / "exposure.csv"}')
        for r in rows:
            vals = ', '.join(f'{k}={r[k]}' for k in names if r[k])
            print(f"  {r['device']:16s} {r['endpoint']:28s} n={r['requests']:3d}  {vals or '(nothing identifying)'}")


if __name__ == '__main__':
    main()
