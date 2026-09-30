#!/usr/bin/env python3
"""Is reolink-cam's LAN firmware push encrypted?

The Reolink desktop client (192.168.0.11) pushed the update to the camera over a
proprietary UDP protocol. This script concatenates the client-to-camera UDP payload,
computes its normalized Shannon entropy, counts file-system/compression signatures, and
checks how many sampled 64-byte chunks of the vendor .pak image occur verbatim in the
stream (the .pak files are read from the vendor zips in controlled/dataset/riolink/firmware).

Usage: python3 src/update_attribution/lan_push_check.py
"""
import collections
import math
import subprocess
import tempfile
import zipfile
from pathlib import Path

from paths import CONTROLLED_CAPTURES, RAW_CONTROLLED, REOLINK_FIRMWARE as FW_DIR, require

PCAP = RAW_CONTROLLED / CONTROLLED_CAPTURES['reolink-cam']
CLIENT = '192.168.0.11'
SIGNATURES = {'UBI': b'UBI#', 'uImage': b'\x27\x05\x19\x56', 'SquashFS': b'hsqs', 'gzip': b'\x1f\x8b\x08',
              'xz': b'\xfd7zXZ', 'ZIP': b'PK\x03\x04'}


def main():
    require(PCAP, FW_DIR)
    hexdata = subprocess.run(['tshark', '-r', str(PCAP), '-Y', f'ip.src=={CLIENT} && udp', '-T', 'fields',
                              '-e', 'data.data'], capture_output=True, text=True).stdout
    stream = bytes.fromhex(hexdata.replace('\n', '').replace(':', ''))
    counts = collections.Counter(stream)
    h = -sum(c / len(stream) * math.log2(c / len(stream)) for c in counts.values()) / 8
    print(f'client->camera UDP payload: {len(stream):,} bytes, normalized Shannon entropy {h:.3f}')
    print('signatures:', {k: stream.count(v) for k, v in SIGNATURES.items()})
    with tempfile.TemporaryDirectory() as tmp:
        for z in sorted(FW_DIR.glob('*.zip')):
            with zipfile.ZipFile(z) as zf:
                for member in zf.namelist():
                    if member.endswith('.pak'):
                        data = zf.read(member)
                        step = max(len(data) // 200, 1)
                        offs = range(0, len(data) - 64, step)
                        hits = sum(stream.find(data[o:o + 64]) >= 0 for o in offs)
                        print(f'{Path(member).name}: {hits}/{len(offs)} sampled 64-byte chunks '
                              f'({100 * hits / len(offs):.0f}%) occur verbatim in the stream')


if __name__ == '__main__':
    main()
