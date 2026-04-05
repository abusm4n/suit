"""
Assess cryptographic strength for all 10 IoT devices combined.
Generates device-wise breakdowns and combined analysis.
"""

import csv
import pandas as pd
from datetime import datetime
from pathlib import Path

# Configuration
INPUT_FILE = Path('/home/ab/update_traffic/controlled/analysis_output/data/certificate_summary_all_devices.csv')
OUTPUT_PATH = Path('/home/ab/update_traffic/controlled/analysis_output/data')
DATASET_BASE = Path('/home/ab/update_traffic/controlled/dataset')
OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
CERT_FOLDER_CANDIDATES = [
    'certificates',
    'certificate',
    'certificates_with_duplicate',
]


def count_device_cert_files(device, folder_name):
    """Count .cer files for a device folder; return None when folder is missing."""
    folder = DATASET_BASE / device / folder_name
    if not folder.exists():
        return None
    return len([
        path for path in folder.iterdir()
        if path.is_file() and path.suffix.lower() in {'.cer', '.crt', '.cert'}
    ])


def count_device_cert_files_auto(device):
    """Count certificate files in the first available non-iPhone folder."""
    for folder_name in CERT_FOLDER_CANDIDATES:
        count = count_device_cert_files(device, folder_name)
        if count is not None:
            return count
    return None

def assess_strength(key_type, key_size):
    """Map (key_type, key_size) to NIST security strength."""
    if key_type == 'RSAPublicKey':
        if key_size == 1024:
            return 'BROKEN', 80
        elif key_size == 2048:
            return 'WEAK', 112
        elif key_size >= 3072:
            return 'STRONG', 128
        else:
            return 'UNKNOWN', 0
    elif key_type == 'EllipticCurvePublicKey':
        # Standard EC curves: P-256 (128), P-384 (192), P-521 (256)
        if key_size == 256:
            return 'STRONG', 128
        elif key_size == 384:
            return 'STRONG', 192
        elif key_size == 521:
            return 'STRONG', 256
        else:
            return 'UNKNOWN', key_size
    else:
        return 'UNKNOWN', 0

def format_pct(count, total):
    """Format percentage safely."""
    if total == 0:
        return '0%'
    return f"{(count / total * 100):.1f}%"

def analyze_strength(df):
    """Assess strength for all certificates."""
    df['strength_level'] = df.apply(
        lambda r: assess_strength(r['public_key_type'], r['public_key_size'])[0],
        axis=1
    )
    df['security_bits'] = df.apply(
        lambda r: assess_strength(r['public_key_type'], r['public_key_size'])[1],
        axis=1
    )
    
    # Parse dates
    df['not_before_dt'] = pd.to_datetime(df['not_before'])
    df['not_after_dt'] = pd.to_datetime(df['not_after'])
    df['validity_years'] = (df['not_after_dt'] - df['not_before_dt']).dt.days / 365.25
    
    # Expiration check (relative to analysis date) - make analysis date timezone-aware
    analysis_date = pd.Timestamp('2026-03-28', tz='UTC')
    df['is_expired'] = df['not_after_dt'] < analysis_date
    
    return df

def generate_analysis_csv(df):
    """Generate detailed per-certificate analysis."""
    analysis_df = df[[
        'device', 'filename', 'public_key_type', 'public_key_size',
        'strength_level', 'security_bits', 'validity_years', 'is_expired',
        'is_self_signed', 'subject', 'issuer'
    ]].copy()
    
    analysis_df.to_csv(OUTPUT_PATH / 'certificate_security_analysis_all_devices.csv', index=False)
    print(f"Saved per-certificate analysis to certificate_security_analysis_all_devices.csv")

def generate_device_summary(df):
    """Generate per-device summary statistics."""
    devices = sorted(df['device'].unique())
    device_stats = []
    
    for device in devices:
        device_df = df[df['device'] == device]

        # Folder-based counts:
        # - certificates_with_duplicate: total observed captures
        # - certificates: manual unique set
        total_with_duplicates = count_device_cert_files(device, 'certificates_with_duplicate')
        unique_certificates = count_device_cert_files_auto(device)

        # Fallbacks when a folder is missing
        if total_with_duplicates is None:
            total_with_duplicates = len(device_df)
        if unique_certificates is None:
            unique_certificates = len(device_df)

        self_signed = (device_df['is_self_signed']).sum()
        
        strength_counts = device_df['strength_level'].value_counts()
        broken = strength_counts.get('BROKEN', 0)
        weak = strength_counts.get('WEAK', 0)
        strong = strength_counts.get('STRONG', 0)

        earliest_expiry_date = device_df['not_after_dt'].min().date().isoformat()
        latest_expiry_date = device_df['not_after_dt'].max().date().isoformat()
        
        avg_validity = device_df['validity_years'].mean()
        avg_security_bits = device_df['security_bits'].mean()
        
        device_stats.append({
            'device': device,
            'total_certificates': total_with_duplicates,
            'unique_certificates': unique_certificates,
            'unique_serials': device_df['serial_number'].nunique(),
            'broken_strength': broken,
            'weak_strength': weak,
            'strong_strength': strong,
            'earliest_expiry_date': earliest_expiry_date,
            'latest_expiry_date': latest_expiry_date,
            'self_signed': self_signed,
            'avg_validity_years': round(avg_validity, 2),
            'avg_security_bits': round(avg_security_bits, 1),
        })
    
    device_df_out = pd.DataFrame(device_stats)
    device_df_out.to_csv(OUTPUT_PATH / 'certificate_device_summary.csv', index=False)
    print(f"Saved device summary to certificate_device_summary.csv")
    
    return device_df_out

def generate_overview(df):
    """Generate combined overview statistics."""
    total = len(df)
    unique_serials = df['serial_number'].nunique()
    unique_devices = df['device'].nunique()
    
    strength_counts = df['strength_level'].value_counts()
    broken = strength_counts.get('BROKEN', 0)
    weak = strength_counts.get('WEAK', 0)
    strong = strength_counts.get('STRONG', 0)
    
    expired = (df['is_expired']).sum()
    self_signed = (df['is_self_signed']).sum()
    long_validity = (df['validity_years'] > 5).sum()
    
    avg_validity = df['validity_years'].mean()
    median_validity = df['validity_years'].median()
    avg_security_bits = df['security_bits'].mean()
    
    overview = [{
        'metric': 'total_certificates',
        'value': total
    }, {
        'metric': 'unique_devices',
        'value': unique_devices
    }, {
        'metric': 'unique_serials',
        'value': unique_serials
    }, {
        'metric': 'broken_strength_count',
        'value': broken
    }, {
        'metric': 'broken_strength_pct',
        'value': format_pct(broken, total)
    }, {
        'metric': 'weak_strength_count',
        'value': weak
    }, {
        'metric': 'weak_strength_pct',
        'value': format_pct(weak, total)
    }, {
        'metric': 'strong_strength_count',
        'value': strong
    }, {
        'metric': 'strong_strength_pct',
        'value': format_pct(strong, total)
    }, {
        'metric': 'expired_count',
        'value': expired
    }, {
        'metric': 'expired_pct',
        'value': format_pct(expired, total)
    }, {
        'metric': 'self_signed_count',
        'value': self_signed
    }, {
        'metric': 'long_validity_5_plus_count',
        'value': long_validity
    }, {
        'metric': 'long_validity_5_plus_pct',
        'value': format_pct(long_validity, total)
    }, {
        'metric': 'avg_validity_years',
        'value': round(avg_validity, 2)
    }, {
        'metric': 'median_validity_years',
        'value': round(median_validity, 2)
    }, {
        'metric': 'avg_security_bits',
        'value': round(avg_security_bits, 1)
    }]
    
    overview_df = pd.DataFrame(overview)
    overview_df.to_csv(OUTPUT_PATH / 'certificate_security_overview_all_devices.csv', index=False)
    print(f"Saved combined overview to certificate_security_overview_all_devices.csv")
    
    return overview

def build_readme(overview_data, device_summary):
    """Generate executive summary README."""
    
    # Convert overview list to DataFrame if needed
    if isinstance(overview_data, list):
        overview_data = pd.DataFrame(overview_data)
    
    # Find values from overview
    overview_dict = {row['metric']: row['value'] for _, row in overview_data.iterrows()}
    
    readme = f"""# Certificate Analysis: All 10 IoT Devices Combined

**Analysis Date:** 2026-03-28  
**Dataset Scope:** Apple TV, D-Link, Eufy, Fire TV, HomePod, Riolink, Sony TV, Tapo C100, Tapo C200, Xiaomi  
**Total Certificates Analyzed:** {overview_dict['total_certificates']} across {overview_dict['unique_devices']} devices  

## Critical Findings

| Metric | Value | Status |
|--------|-------|--------|
| Total Certificates | {overview_dict['total_certificates']} | ✓ |
| 1024-bit RSA (BROKEN) | {overview_dict['broken_strength_count']} ({overview_dict['broken_strength_pct']}) | 🔴 CRITICAL |
| 2048-bit RSA (WEAK) | {overview_dict['weak_strength_count']} ({overview_dict['weak_strength_pct']}) | 🟡 Needs Migration |
| Strong Keys (3072+ RSA, P-256+ ECC) | {overview_dict['strong_strength_count']} ({overview_dict['strong_strength_pct']}) | 🟢 Modern |
| Expired Certificates | {overview_dict['expired_count']} ({overview_dict['expired_pct']}) | 🟡 Still Deployed |
| Long Validity (>5 years) | {overview_dict['long_validity_5_plus_count']} ({overview_dict['long_validity_5_plus_pct']}) | 🔴 Risk |
| Average Security Strength | {overview_dict['avg_security_bits']} bits | ⚠️ Below NIST 128-bit target |

## Per-Device Summary

"""
    for _, row in device_summary.iterrows():
        readme += f"""### {row['device'].upper()}

- Total (with duplicates): {row['total_certificates']} certificates
- Unique (manual): {row['unique_certificates']} certificates
- Unique Serials: {row['unique_serials']}
- Strength Levels: {row['broken_strength']} BROKEN, {row['weak_strength']} WEAK, {row['strong_strength']} STRONG
- Earliest Expiry Date: {row['earliest_expiry_date']}
- Latest Expiry Date: {row['latest_expiry_date']}
- Avg Validity: {row['avg_validity_years']} years
- Avg Security Bits: {row['avg_security_bits']} bits

"""
    
    readme += """## Overall Statistics

- Mean Certificate Validity: {:.2f} years
- Median Certificate Validity: {:.2f} years
- Self-Signed Certificates: {}

## Output Artifacts

- `certificate_summary_all_devices.csv` - Full certificate metadata with device tracking
- `certificate_security_analysis_all_devices.csv` - Per-certificate strength assessment
- `certificate_device_summary.csv` - Per-device statistics
- `certificate_security_overview_all_devices.csv` - Combined metrics

## Visualization Figures

- `key_size_distribution_all_devices.pdf` - Key size distribution across all devices
- `security_strength_pie_all_devices.pdf` - Overall security strength breakdown
- `algorithm_distribution_all_devices.pdf` - RSA vs EC distribution
- `device_comparison_key_size.pdf` - Per-device key size breakdown
- `device_comparison_strength.pdf` - Per-device strength levels
- `security_bits_boxplot_all_devices.pdf` - Security bits by key size
- `validity_analysis_all_devices.pdf` - Certificate validity periods
- `expired_by_device.pdf` - Expired certificates per device

## Method

Certificates were extracted from all 10 IoT device folders and analyzed for:
- Key type and size
- NIST security strength mapping (BROKEN/WEAK/STRONG)
- Expiration status
- Validity period
- Self-signed status

Security classifications follow NIST SP 800-57 Part 1 Rev.5:
- RSA-1024: BROKEN (80 bits)
- RSA-2048: WEAK (112 bits)
- RSA-3072+: STRONG (128+ bits)
- EC-P256+: STRONG (128+ bits)

""".format(overview_dict['avg_validity_years'], overview_dict['median_validity_years'],
           overview_dict['self_signed_count'])
    
    readme_file = OUTPUT_PATH / 'README_CERTIFICATE_ANALYSIS_ALL_DEVICES.md'
    with open(readme_file, 'w') as f:
        f.write(readme)
    print(f"Saved README to README_CERTIFICATE_ANALYSIS_ALL_DEVICES.md")

def main():
    """Run combined analysis pipeline."""
    if not INPUT_FILE.exists():
        print(f"Error: Input file not found at {INPUT_FILE}")
        return
    
    print("Loading certificate data...")
    df = pd.read_csv(INPUT_FILE)
    
    print(f"Analyzing {len(df)} certificates from {df['device'].nunique()} devices...")
    df = analyze_strength(df)
    
    print("Generating analysis outputs...")
    generate_analysis_csv(df)
    device_summary = generate_device_summary(df)
    overview = generate_overview(df)
    
    print("Generating README...")
    build_readme(overview, device_summary)
    
    print("\n✓ Combined analysis complete!")

if __name__ == '__main__':
    main()
