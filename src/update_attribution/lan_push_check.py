#!/usr/bin/env python3
"""Is reolink-cam's LAN firmware push encrypted?

The Reolink desktop client (192.168.0.11) pushed the update to the camera over a
proprietary UDP protocol. This script concatenates the client-to-camera UDP payload,
computes its normalized Shannon entropy, counts file-system/compression signatures, and
checks how many sampled 64-byte chunks of the vendor .pak image occur verbatim in the
stream (the .pak files are read from the vendor zips in controlled/dataset/riolink/firmware).
It then reassembles the image: each datagram carries a 20-byte header, and the first datagram
of every 37,870-byte image block also a 130-byte message header (24-byte Baichuan header plus a
106-byte encrypted extension). It reports how many blocks there are, whether their headers are
identical, whether every image-carrying datagram matches the published image, which share of
the image is covered, and whether the session starts with a login (message 1).
The numbers are printed and written to data/derived/controlled/lan_push.csv.

Usage: python3 src/update_attribution/lan_push_check.py
"""
import collections
import csv
import math
import subprocess
import tempfile
import zipfile
from pathlib import Path

from paths import CONTROLLED_CAPTURES, DERIVED_CONTROLLED, RAW_CONTROLLED, REOLINK_FIRMWARE as FW_DIR, require

PCAP = RAW_CONTROLLED / CONTROLLED_CAPTURES['reolink-cam']
CLIENT = '192.168.0.11'
SIGNATURES = {'UBI': b'UBI#', 'uImage': b'\x27\x05\x19\x56', 'SquashFS': b'hsqs', 'gzip': b'\x1f\x8b\x08',
              'xz': b'\xfd7zXZ', 'ZIP': b'PK\x03\x04'}


UDP_DATA = bytes.fromhex('10cf872a')     # Reolink UDP data datagram
BC_MAGIC = bytes.fromhex('f0debc0a')     # Baichuan message header
UDP_HDR = 20


def reassemble(datagrams, img):
    """Map every client->camera data datagram onto the published image."""
    covered = bytearray(len(img))
    blocks, unmatched_data, control = [], 0, 0
    for d in datagrams:
        if d[:4] != UDP_DATA or len(d) <= 28:
            continue
        p = d[UDP_HDR:]
        o = img.find(p)
        if o >= 0:
            covered[o:o + len(p)] = b'\x01' * len(p)
            continue
        if p[:4] == BC_MAGIC and int.from_bytes(p[4:8], 'little') == 0x43 and int.from_bytes(p[20:24], 'little'):
            # image block: message 0x43 with a binary payload behind its extension; message 0x43
            # without one is the (encrypted) upgrade request that precedes the image
            hdr = 24 + int.from_bytes(p[20:24], 'little')
            o = img.find(p[hdr:])
            if o >= 0:
                covered[o:o + len(p) - hdr] = b'\x01' * (len(p) - hdr)
                blocks.append(p[:hdr])
                continue
            unmatched_data += 1
        elif len(p) >= 1000:
            unmatched_data += 1
        else:
            control += 1
    # identical headers apart from the body length field (bytes 8..12), which differs for the last block
    distinct = len({h[:8] + h[12:] for h in blocks})
    return dict(blocks=len(blocks), header_bytes=len(blocks[0]) if blocks else 0, distinct_headers=distinct,
                unmatched_data_datagrams=unmatched_data, control_datagrams=control,
                image_covered=f'{sum(covered) / len(img):.4f}')


def main():
    require(PCAP, FW_DIR)
    hexdata = subprocess.run(['tshark', '-r', str(PCAP), '-Y', f'ip.src=={CLIENT} && udp', '-T', 'fields',
                              '-e', 'data.data'], capture_output=True, text=True).stdout
    datagrams = [bytes.fromhex(line.replace(':', '')) for line in hexdata.splitlines() if line]
    stream = b''.join(datagrams)
    # the session opens with a Baichuan login (message 1) from the desktop client
    login = any(d[:4] == UDP_DATA and d[UDP_HDR:UDP_HDR + 4] == BC_MAGIC
                and int.from_bytes(d[UDP_HDR + 4:UDP_HDR + 8], 'little') == 1 for d in datagrams[:50])
    print('session starts with a login message:', login)
    counts = collections.Counter(stream)
    h = -sum(c / len(stream) * math.log2(c / len(stream)) for c in counts.values()) / 8
    print(f'client->camera UDP payload: {len(stream):,} bytes, normalized Shannon entropy {h:.3f}')
    sigs = {k: stream.count(v) for k, v in SIGNATURES.items()}
    print('signatures:', sigs)
    rows = []
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
                        r = reassemble(datagrams, data)
                        print('  reassembly:', r)
                        rows.append({'image': Path(member).name, 'stream_bytes': len(stream),
                                     'stream_entropy': f'{h:.3f}', 'chunks_sampled': len(offs),
                                     'chunks_in_stream': hits, 'share': f'{hits / len(offs):.3f}',
                                     **{f'sig_{k}': v for k, v in sigs.items()}, 'login': login, **r})
    out = DERIVED_CONTROLLED / 'lan_push.csv'
    with open(out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print('wrote', out.relative_to(DERIVED_CONTROLLED.parents[2]))


if __name__ == '__main__':
    main()
