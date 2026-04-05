#!/usr/bin/env python3
"""Build TLS-version and cipher-category breakdown for Feedback_2.

Why this exists:
- ClientHello contains offered cipher lists and can overcount weak suites.
- ServerHello reflects negotiated version/cipher and is what should drive claims.

Input format expected:
- Extracted TLS directory from `src/extract_tls.py`, containing:
  - `file_metadata.pickle`
  - `<uuid>/tls_handshake.json`

Example:
  python3 src/tls_breakdown.py \
    --input retrospective/dataset_extracted/iot-data_tls \
    --output retrospective/analysis_output
"""

import argparse
import csv
import importlib.util
import json
import os
import pickle
from collections import Counter, defaultdict


VERSION_MAP = {
    "0x0301": "TLS1.0",
    "0x0302": "TLS1.1",
    "0x0303": "TLS1.2",
    "0x0304": "TLS1.3",
}


def load_cipher_sets(ciphersuite_py_path: str):
    spec = importlib.util.spec_from_file_location("ciphersuite", ciphersuite_py_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def _norm_set(items):
        return set(str(x).lower().replace("0x", "").zfill(4) for x in items)

    return {
        "Secure": _norm_set(module.SECURE),
        "Recommended": _norm_set(module.RECOMMENDED),
        "Weak": _norm_set(module.WEAK),
        "Insecure": _norm_set(module.INSECURE),
    }


def classify_cipher(code: str, sets: dict) -> str:
    if not code:
        return "Unknown"
    for cat in ("Secure", "Recommended", "Weak", "Insecure"):
        if code in sets[cat]:
            return cat
    return "Unknown"


def normalize_hex(v):
    s = str(v).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.zfill(4)
    if all(c in "0123456789abcdef" for c in s):
        return s
    return None


def flatten_fields(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            np = f"{prefix}.{k}" if prefix else k
            yield from flatten_fields(v, np)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            np = f"{prefix}[{i}]"
            yield from flatten_fields(v, np)
    else:
        yield prefix, obj


def parse_tls_packet(packet):
    versions = []
    chosen_suites = []
    offered_suites = []

    for layer in packet.get("layers", []):
        if layer.get("layer_name") not in ("tls", "ssl"):
            continue

        for key, val in flatten_fields(layer.get("fields", {})):
            lk = key.lower()
            if lk.endswith("tls.handshake.version"):
                versions.append(str(val))

            if "tls.handshake.ciphersuite[" in lk:
                c = normalize_hex(val)
                if c:
                    offered_suites.append(c)
            elif lk.endswith("tls.handshake.ciphersuite"):
                c = normalize_hex(val)
                if c:
                    chosen_suites.append(c)

    return versions, chosen_suites, offered_suites


def write_csv(path, rows, headers):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to extracted TLS directory")
    parser.add_argument("--output", required=True, help="Directory for CSV outputs")
    parser.add_argument(
        "--ciphersuite-script",
        default="src/ciphersuite.py",
        help="Path to ciphersuite classification script",
    )
    parser.add_argument(
        "--device-field",
        default="region",
        choices=["region", "device", "dataset", "action"],
        help="Metadata field to group by (retrospective typically uses 'region')",
    )
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    sets = load_cipher_sets(args.ciphersuite_script)

    meta_path = os.path.join(args.input, "file_metadata.pickle")
    with open(meta_path, "rb") as f:
        metadata = pickle.load(f)

    by_device = defaultdict(lambda: {
        "sessions": 0,
        "server_versions": Counter(),
        "server_chosen_cat": Counter(),
        "client_offered_cat": Counter(),
    })

    overall_versions = Counter()
    overall_chosen = Counter()
    overall_offered = Counter()
    missing_json = 0

    for row in metadata:
        device = row.get(args.device_field) or "unknown"
        tls_json = os.path.join(args.input, row["uuid"], "tls_handshake.json")
        if not os.path.exists(tls_json):
            missing_json += 1
            continue

        with open(tls_json) as f:
            data = json.load(f)

        rec = by_device[device]
        rec["sessions"] += 1

        for packet in data.get("server_hello_packets", []):
            versions, chosen, _ = parse_tls_packet(packet)
            for version in versions:
                mapped = VERSION_MAP.get(version, version)
                rec["server_versions"][mapped] += 1
                overall_versions[mapped] += 1

            for suite in chosen:
                cat = classify_cipher(suite, sets)
                rec["server_chosen_cat"][cat] += 1
                overall_chosen[cat] += 1

        for packet in data.get("client_hello_packets", []):
            _, _, offered = parse_tls_packet(packet)
            for suite in offered:
                cat = classify_cipher(suite, sets)
                rec["client_offered_cat"][cat] += 1
                overall_offered[cat] += 1

    device_rows = []
    for dev, rec in sorted(by_device.items(), key=lambda kv: kv[1]["sessions"], reverse=True):
        sc = rec["server_chosen_cat"]
        oc = rec["client_offered_cat"]
        sv = rec["server_versions"]
        device_rows.append({
            "device": dev,
            "sessions": rec["sessions"],
            "tls10_serverhello": sv["TLS1.0"],
            "tls11_serverhello": sv["TLS1.1"],
            "tls12_serverhello": sv["TLS1.2"],
            "tls13_serverhello": sv["TLS1.3"],
            "chosen_secure": sc["Secure"],
            "chosen_recommended": sc["Recommended"],
            "chosen_weak": sc["Weak"],
            "chosen_insecure": sc["Insecure"],
            "chosen_unknown": sc["Unknown"],
            "offered_secure": oc["Secure"],
            "offered_recommended": oc["Recommended"],
            "offered_weak": oc["Weak"],
            "offered_insecure": oc["Insecure"],
            "offered_unknown": oc["Unknown"],
            "chosen_weak_insecure_total": sc["Weak"] + sc["Insecure"],
            "chosen_secure_recommended_total": sc["Secure"] + sc["Recommended"],
            "offered_weak_insecure_total": oc["Weak"] + oc["Insecure"],
        })

    summary_rows = [
        {"metric": "missing_tls_json", "value": missing_json},
        {"metric": "serverhello_tls10", "value": overall_versions["TLS1.0"]},
        {"metric": "serverhello_tls11", "value": overall_versions["TLS1.1"]},
        {"metric": "serverhello_tls12", "value": overall_versions["TLS1.2"]},
        {"metric": "serverhello_tls13", "value": overall_versions["TLS1.3"]},
        {"metric": "chosen_secure", "value": overall_chosen["Secure"]},
        {"metric": "chosen_recommended", "value": overall_chosen["Recommended"]},
        {"metric": "chosen_weak", "value": overall_chosen["Weak"]},
        {"metric": "chosen_insecure", "value": overall_chosen["Insecure"]},
        {"metric": "chosen_unknown", "value": overall_chosen["Unknown"]},
        {"metric": "offered_secure", "value": overall_offered["Secure"]},
        {"metric": "offered_recommended", "value": overall_offered["Recommended"]},
        {"metric": "offered_weak", "value": overall_offered["Weak"]},
        {"metric": "offered_insecure", "value": overall_offered["Insecure"]},
        {"metric": "offered_unknown", "value": overall_offered["Unknown"]},
    ]

    device_csv = os.path.join(args.output, "tls_device_breakdown.csv")
    summary_csv = os.path.join(args.output, "tls_overall_summary.csv")

    write_csv(
        device_csv,
        device_rows,
        headers=[
            "device",
            "sessions",
            "tls10_serverhello",
            "tls11_serverhello",
            "tls12_serverhello",
            "tls13_serverhello",
            "chosen_secure",
            "chosen_recommended",
            "chosen_weak",
            "chosen_insecure",
            "chosen_unknown",
            "offered_secure",
            "offered_recommended",
            "offered_weak",
            "offered_insecure",
            "offered_unknown",
            "chosen_weak_insecure_total",
            "chosen_secure_recommended_total",
            "offered_weak_insecure_total",
        ],
    )
    write_csv(summary_csv, summary_rows, headers=["metric", "value"])

    print(f"Wrote: {device_csv}")
    print(f"Wrote: {summary_csv}")


if __name__ == "__main__":
    main()
