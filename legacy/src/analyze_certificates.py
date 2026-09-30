#!/usr/bin/env python3
"""
Certificate Analysis Script for Controlled IoT Dataset

Scans all .cer files in the tapo-c200/certificates directory and extracts key certificate properties.
Outputs a summary CSV and prints results to the terminal.
"""
import os
import csv
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime

CERT_DIR = os.path.expanduser("~/update_traffic/controlled/dataset/tapo-c200/certificates")
OUTPUT_CSV = os.path.expanduser("~/update_traffic/controlled/analysis_output/data/certificate_summary.csv")

fields = [
    "filename", "subject", "issuer", "not_before", "not_after", "serial_number", "public_key_type", "public_key_size"
]

summary = []

for fname in sorted(os.listdir(CERT_DIR)):
    if not fname.endswith(".cer"):
        continue
    fpath = os.path.join(CERT_DIR, fname)
    try:
        with open(fpath, "rb") as f:
            data = f.read()
            try:
                cert = x509.load_der_x509_certificate(data, default_backend())
            except Exception:
                # Try PEM if DER fails
                try:
                    cert = x509.load_pem_x509_certificate(data, default_backend())
                except Exception as e:
                    print(f"[!] Failed to parse {fname}: {e}")
                    continue
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            not_before = cert.not_valid_before.strftime("%Y-%m-%d")
            not_after = cert.not_valid_after.strftime("%Y-%m-%d")
            serial = hex(cert.serial_number)
            pubkey = cert.public_key()
            if hasattr(pubkey, 'key_size'):
                key_type = pubkey.__class__.__name__
                key_size = pubkey.key_size
            else:
                key_type = type(pubkey).__name__
                key_size = ''
            summary.append({
                "filename": fname,
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "serial_number": serial,
                "public_key_type": key_type,
                "public_key_size": key_size
            })
            print(f"{fname}: {subject} | {issuer} | {not_before} - {not_after} | {key_type} {key_size}")
    except Exception as e:
        print(f"[!] Error reading {fname}: {e}")

# Write summary CSV
os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    for row in summary:
        writer.writerow(row)

print(f"\nSummary written to {OUTPUT_CSV}")
