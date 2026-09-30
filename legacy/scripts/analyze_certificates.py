#!/usr/bin/env python3
"""Extract certificate metadata from the current Tapo C200 certificate folder."""

from pathlib import Path
import csv
import hashlib

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


CERT_DIR = Path("/home/ab/update_traffic/controlled/dataset/tapo-c200/certificates")
OUTPUT_CSV = Path("/home/ab/update_traffic/controlled/analysis_output/data/certificate_summary.csv")

FIELDS = [
    "filename",
    "file_sha256",
    "cert_fingerprint_sha256",
    "subject",
    "issuer",
    "not_before",
    "not_after",
    "serial_number",
    "public_key_type",
    "public_key_size",
    "signature_algorithm_oid",
    "is_self_signed",
]


def load_certificate(data: bytes):
    try:
        return x509.load_der_x509_certificate(data, default_backend())
    except Exception:
        return x509.load_pem_x509_certificate(data, default_backend())


def main() -> int:
    rows = []

    for path in sorted(CERT_DIR.glob("*.cer")):
        data = path.read_bytes()
        try:
            cert = load_certificate(data)
        except Exception as exc:
            print(f"[!] Failed to parse {path.name}: {exc}")
            continue

        public_key = cert.public_key()
        not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before).date().isoformat()
        not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after).date().isoformat()
        rows.append(
            {
                "filename": path.name,
                "file_sha256": hashlib.sha256(data).hexdigest(),
                "cert_fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": not_before,
                "not_after": not_after,
                "serial_number": hex(cert.serial_number),
                "public_key_type": type(public_key).__name__,
                "public_key_size": getattr(public_key, "key_size", ""),
                "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
                "is_self_signed": cert.subject == cert.issuer,
            }
        )
        print(f"{path.name}: extracted")

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved {len(rows)} certificates to {OUTPUT_CSV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
