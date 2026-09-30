"""Extract certificate identity and issuer details from all device certificate folders."""

import csv
from pathlib import Path

import pandas as pd
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


DEVICES = [
    'apple-tv', 'dlink', 'eufy', 'fire-tv', 'homepod',
    'riolink', 'sony-tv', 'tapo-c100', 'tapo-c200', 'xiaomi'
]
DATASET_BASE = Path('/home/ab/update_traffic/controlled/dataset')
OUTPUT_BASE = Path('/home/ab/update_traffic/controlled/analysis_output/data/certificate_identities')
OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
CERT_FOLDER_CANDIDATES = [
    'certificates',
    'certificate',
    'certificates_with_duplicate',
]

FIELDS = [
    'device',
    'filename',
    'certificate_identity',
    'certificate_common_name',
    'certificate_organization',
    'subject_dn',
    'verified_by',
    'issuer_common_name',
    'issuer_organization',
    'issuer_dn',
    'serial_number',
    'not_before',
    'not_after',
    'is_self_signed',
]


def load_certificate(cert_data):
    """Load a certificate by trying DER first and PEM second."""
    try:
        return x509.load_der_x509_certificate(cert_data, default_backend())
    except Exception:
        return x509.load_pem_x509_certificate(cert_data, default_backend())


def first_name_value(name, oid):
    """Return the first matching attribute value or an empty string."""
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else ''


def best_identity_label(name):
    """Prefer CN, then O, then full DN for a readable identity label."""
    common_name = first_name_value(name, NameOID.COMMON_NAME)
    if common_name:
        return common_name

    organization = first_name_value(name, NameOID.ORGANIZATION_NAME)
    if organization:
        return organization

    return name.rfc4514_string()


def iso_datetime(cert_value, fallback_value):
    """Normalize certificate validity timestamps to ISO format."""
    try:
        return cert_value.isoformat()
    except AttributeError:
        return fallback_value.isoformat()


def resolve_certificate_folder(device):
    """Pick the best available non-iPhone certificate folder for a device."""
    device_base = DATASET_BASE / device
    for folder_name in CERT_FOLDER_CANDIDATES:
        candidate = device_base / folder_name
        if candidate.exists() and candidate.is_dir():
            return candidate, folder_name
    return None, None


def collect_device_rows(device):
    """Extract identity rows for one device certificate folder."""
    cert_dir, source_folder = resolve_certificate_folder(device)
    rows = []

    if cert_dir is None:
        print(f"Warning: missing certificate folder for {device}")
        return rows

    cert_files = sorted(
        path for path in cert_dir.iterdir()
        if path.is_file() and path.suffix.lower() in {'.cer', '.crt', '.cert'}
    )

    print(
        f"Processing {device}: {len(cert_files)} certificate files "
        f"(source folder: {source_folder})"
    )

    for cert_file in cert_files:
        try:
            cert = load_certificate(cert_file.read_bytes())
        except Exception as exc:
            print(f"Error parsing {cert_file}: {exc}")
            continue

        subject = cert.subject
        issuer = cert.issuer

        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after

        rows.append({
            'device': device,
            'filename': cert_file.name,
            'certificate_identity': best_identity_label(subject),
            'certificate_common_name': first_name_value(subject, NameOID.COMMON_NAME),
            'certificate_organization': first_name_value(subject, NameOID.ORGANIZATION_NAME),
            'subject_dn': subject.rfc4514_string(),
            'verified_by': best_identity_label(issuer),
            'issuer_common_name': first_name_value(issuer, NameOID.COMMON_NAME),
            'issuer_organization': first_name_value(issuer, NameOID.ORGANIZATION_NAME),
            'issuer_dn': issuer.rfc4514_string(),
            'serial_number': str(cert.serial_number),
            'not_before': iso_datetime(not_before, cert.not_valid_before),
            'not_after': iso_datetime(not_after, cert.not_valid_after),
            'is_self_signed': subject == issuer,
        })

    return rows


def write_csv(rows, output_file):
    """Write rows to a CSV file with a stable field order."""
    with output_file.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def write_unique_presence_csv(rows):
    """Write distinct subject/issuer presence across all devices to one CSV."""
    df = pd.DataFrame(rows)
    unique_rows = []

    for role, column in [
        ('certificate_identity', 'certificate_identity'),
        ('verified_by', 'verified_by'),
    ]:
        grouped = (
            df.groupby(column, dropna=False)
            .agg(
                occurrence_count=('device', 'size'),
                device_count=('device', 'nunique'),
                devices=('device', lambda values: ', '.join(sorted(set(values)))),
            )
            .reset_index()
            .rename(columns={column: 'name'})
        )
        grouped.insert(0, 'role', role)
        unique_rows.append(grouped)

    unique_df = pd.concat(unique_rows, ignore_index=True)
    unique_df = unique_df.sort_values(['role', 'device_count', 'occurrence_count', 'name'], ascending=[True, False, False, True])
    output_file = OUTPUT_BASE / 'unique_identity_verifier_presence_all_devices.csv'
    unique_df.to_csv(output_file, index=False)
    print(f"Saved {len(unique_df)} unique values to {output_file}")


def main():
    """Extract per-device and combined identity views."""
    all_rows = []

    for device in DEVICES:
        device_rows = collect_device_rows(device)
        all_rows.extend(device_rows)

        device_output = OUTPUT_BASE / f'{device}_certificate_identities.csv'
        write_csv(device_rows, device_output)
        print(f"Saved {len(device_rows)} rows to {device_output}")

    combined_output = OUTPUT_BASE / 'all_devices_certificate_identities.csv'
    write_csv(all_rows, combined_output)
    print(f"Saved {len(all_rows)} rows to {combined_output}")
    write_unique_presence_csv(all_rows)


if __name__ == '__main__':
    main()