#!/usr/bin/env python3
"""Full certificate chains sent by update servers in the controlled captures.

leaf_certs.csv (controlled_attribution.py) keeps only the server leaf. This script reads
the TLS 1.2 update connections from data/derived/controlled/flows.csv, extracts every
certificate of the server's Certificate message with tshark, and writes one row per
distinct (device, endpoint, position, certificate) to data/derived/controlled/chains.csv.
It backs the paper's statements on intermediates and roots (Section 5.3): key type and
size and validity of every certificate sent with an update-server leaf. TLS 1.3 encrypts
the Certificate message, so those connections cannot be covered.

Usage: python3 src/update_attribution/chains.py
"""
import collections
import csv
import hashlib
import warnings

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from controlled_attribution import DEVICES, tshark_fields
from paths import DERIVED_CONTROLLED, RAW_CONTROLLED, require

OUT = DERIVED_CONTROLLED / 'chains.csv'
# One vendor certificate has a non-positive serial number; cryptography warns but parses it.
warnings.filterwarnings('ignore', message='Parsed a serial number')


def key_name(k):
    if isinstance(k, rsa.RSAPublicKey):
        return f'RSA-{k.key_size}'
    if isinstance(k, ec.EllipticCurvePublicKey):
        return f'EC-{k.curve.key_size}'
    return type(k).__name__


def cn(name):
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def main():
    by_paper = {paper: (rel, ip) for dev, (rel, ip, paper) in DEVICES.items()}
    streams = collections.defaultdict(dict)
    with open(DERIVED_CONTROLLED / 'flows.csv') as fh:
        for r in csv.DictReader(fh):
            if r['endpoint'] and r['tls_version'] == '1.2':
                streams[r['device']][r['stream']] = (r['endpoint'], r['remote'])
    require(*(RAW_CONTROLLED / by_paper[d][0] for d in streams))
    rows = {}
    for device, st in sorted(streams.items()):
        flt = ' || '.join(f'tcp.stream=={s}' for s in st)
        out = tshark_fields(RAW_CONTROLLED / by_paper[device][0],
                            ['tcp.stream', 'ip.src', 'tls.handshake.certificate'],
                            f'tls.handshake.type==11 && ({flt})')
        for line in out.splitlines():
            s, src, chain = line.split('|', 2)
            endpoint, server = st[s]
            if src != server or not chain:
                continue
            for pos, hexder in enumerate(chain.split(',')):
                c = x509.load_der_x509_certificate(bytes.fromhex(hexder.replace(':', '')))
                fp = hashlib.sha256(c.public_bytes(Encoding.DER)).hexdigest()[:16]
                try:
                    is_ca = c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                except x509.ExtensionNotFound:
                    is_ca = False
                rec = rows.setdefault((device, endpoint, pos, fp), dict(
                    device=device, endpoint=endpoint, position=pos,
                    kind='leaf' if pos == 0 else ('root' if c.subject == c.issuer else 'intermediate'),
                    ca=is_ca, subject=cn(c.subject), issuer=cn(c.issuer), key=key_name(c.public_key()),
                    not_before=c.not_valid_before_utc.date().isoformat(),
                    not_after=c.not_valid_after_utc.date().isoformat(),
                    validity_days=(c.not_valid_after_utc - c.not_valid_before_utc).days,
                    fingerprint=fp, connections=0))
                rec['connections'] += 1
    rows = sorted(rows.values(), key=lambda r: (r['device'], r['endpoint'], r['position']))
    with open(OUT, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f'wrote {OUT.relative_to(DERIVED_CONTROLLED.parents[2])}: {len(rows)} rows')
    for r in rows:
        print(f"  {r['device']:<11} {r['endpoint']:<36} {r['position']} {r['kind']:<12} {r['key']:<9} "
              f"{r['not_before']}..{r['not_after']}  {r['subject'][:40]}")


if __name__ == '__main__':
    main()
