"""
Extract certificate metadata from all 10 IoT devices combined.
Tracks device source for each certificate.
"""

import csv
import hashlib
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Configuration
DEVICES = [
    'apple-tv', 'dlink', 'eufy', 'fire-tv', 'homepod',
    'riolink', 'sony-tv', 'tapo-c100', 'tapo-c200', 'xiaomi'
]
BASE_PATH = Path('/home/ab/update_traffic/controlled/dataset')
OUTPUT_PATH = Path('/home/ab/update_traffic/controlled/analysis_output/data')
OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
CERT_FOLDER_CANDIDATES = [
    'certificates',
    'certificate',
    'certificates_with_duplicate',
]

def compute_file_hash(filepath):
    """Compute SHA-256 hash of file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        sha256.update(f.read())
    return sha256.hexdigest()

def compute_cert_hash(cert_data):
    """Compute SHA-256 hash of certificate bytes."""
    sha256 = hashlib.sha256()
    sha256.update(cert_data)
    return sha256.hexdigest()


def resolve_certificate_folder(device):
    """Pick the best available non-iPhone certificate folder for a device."""
    device_base = BASE_PATH / device
    for folder_name in CERT_FOLDER_CANDIDATES:
        candidate = device_base / folder_name
        if candidate.exists() and candidate.is_dir():
            return candidate, folder_name
    return None, None

def extract_certificates():
    """Extract all certificates from all device folders."""
    data = []
    
    for device in DEVICES:
        cert_folder, source_folder = resolve_certificate_folder(device)
        if cert_folder is None:
            print(f"Warning: Certificate folder not found for {device}")
            continue
        
        cert_files = sorted(
            path for path in cert_folder.iterdir()
            if path.is_file() and path.suffix.lower() in {'.cer', '.crt', '.cert'}
        )
        print(
            f"Processing {device}: {len(cert_files)} certificate files "
            f"(source folder: {source_folder})"
        )
        
        for cert_file in cert_files:
            try:
                file_hash = compute_file_hash(cert_file)
                
                # Try DER first, then PEM
                with open(cert_file, 'rb') as f:
                    cert_data = f.read()
                cert_hash = compute_cert_hash(cert_data)
                
                try:
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                except Exception:
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                
                # Extract metadata
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                
                # Use UTC-aware datetime properties
                try:
                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                except AttributeError:
                    not_before = cert.not_valid_before
                    not_after = cert.not_valid_after
                
                serial = str(cert.serial_number)
                
                # Extract key info
                public_key = cert.public_key()
                key_type = type(public_key).__name__
                
                try:
                    key_size = public_key.key_size
                except AttributeError:
                    key_size = None
                
                # Extract signature algorithm OID - try dotted_string first, fallback to str()
                try:
                    sig_oid = cert.signature_algorithm_oid.dotted_string
                except AttributeError:
                    sig_oid = str(cert.signature_algorithm_oid)
                
                # Check if self-signed
                is_self_signed = subject == issuer
                
                data.append({
                    'device': device,
                    'filename': cert_file.name,
                    'file_sha256': file_hash,
                    'cert_fingerprint_sha256': cert_hash,
                    'subject': subject,
                    'issuer': issuer,
                    'not_before': not_before.isoformat(),
                    'not_after': not_after.isoformat(),
                    'serial_number': serial,
                    'public_key_type': key_type,
                    'public_key_size': key_size,
                    'signature_algorithm_oid': sig_oid,
                    'is_self_signed': is_self_signed,
                })
            
            except Exception as e:
                print(f"Error processing {cert_file}: {e}")
    
    # Write to CSV
    output_file = OUTPUT_PATH / 'certificate_summary_all_devices.csv'
    if data:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        print(f"\nSaved {len(data)} certificates to {output_file}")
    
    return data

if __name__ == '__main__':
    extract_certificates()
