import json
import sys
from collections import Counter, defaultdict
import os

# Classification based on known TLS cipher suites (TLS 1.2 mainly)
# Source info: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4import json

# Classification based on known TLS cipher suites (TLS 1.2 mainly)

# Usage:
# python ciphersuite_nested_folder.py <folder_with_json_files>  
# The script will recursively search for .json files in the specified folder and its subfolders, process them, and print a summary of cipher suite categories and unique cipher suites found.
# 

SECURE = {
    '1301', '1302', '1303',  # TLS 1.3
    'c02f', 'c02b', 'c030', 'c02c', 'cca9', 'cca8', 'ccaa', '009f', '009e',
    'c0af', 'c0ad',  'c0ae', 'c0ac',
}
RECOMMENDED = {
    '009f', '009e',
    'c023', 'c027', 'c00a', 'c014', 'c009', 'c013',
}
WEAK = {
    '002f', '0033', '0035', '0039', '003c', '003d', '009c', '009d', '00a3', '0041', '0084', '0x00BA', '00c0', 'c09c', 'c0a0', 'c09d', 'c0a1', '0044', '0045', '0032', 'c026', '003f',
    '0087', '0088', 'c0a3', 'c09f', '00a2', 'c0a2', 'c09e', '006a', 'c073', 'c077', '00c4', '00c3', '0040', 'c072', 'c029', '00a5', '00a1', '0069', '0068', '0036', '00a4', '0031',
    'c076', '00be', '00bd', '00ba', '0038', 'c028', 'c028', '000a', 'c028', 'c024', 'c012', 'c008', '0016', '0067', '006b', '0037', '0086', '0085', '0069', '0036', '003e', '0043',
    '0013', 'c00f', 'c005', 'c00e', 'c004', 'c031', 'c02d' 'c029', 'c025', 'c032', 'c02e', 'c02a', 'c00d', 'c003', 'c02d', 'c026', '0068', '0037', '0086', '0085', '00a0', '0030',
     '0042', '0010', '000d', '0099', '0098', '0097', '0096', '009a', '0007',
}  
INSECURE = {
    '0000', '00ff', '0005','c011', 'c007', 'c00c', 'c002', '0004', '0015', '0012', '000f', '000c', '0009',
}

def classify_cipher_suite(hexcode: str) -> str:
    h = hexcode.lower()
    if h.startswith('0x'):
        h = h[2:]
    h = h.zfill(4)
    if h in SECURE:
        return 'Secure'
    elif h in RECOMMENDED:
        return 'Recommended'
    elif h in WEAK:
        return 'Weak'
    elif h in INSECURE:
        return 'Insecure'
    else:
        return 'Unknown'

def process_file(filename, category_counts, cipher_counts):
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                packet = json.loads(line)
            except json.JSONDecodeError:
                continue

            tls = packet.get('layers', {}).get('tls', {})
            cipher_list = []

            if isinstance(tls, dict):
                cipher_list = tls.get('tls_tls_handshake_ciphersuite_raw') or tls.get('tls_tls_handshake_ciphersuite')
                if cipher_list and isinstance(cipher_list, str):
                    cipher_list = cipher_list.split()
            elif isinstance(tls, list):
                for tls_entry in tls:
                    if isinstance(tls_entry, dict):
                        ciphers = tls_entry.get('tls_tls_handshake_ciphersuite_raw') or tls_entry.get('tls_tls_handshake_ciphersuite')
                        if ciphers:
                            if isinstance(ciphers, str):
                                cipher_list.extend(ciphers.split())
                            elif isinstance(ciphers, list):
                                cipher_list.extend(ciphers)

            if not cipher_list:
                continue

            for c in cipher_list:
                c = c.strip().lower()
                if not c:
                    continue
                if ',' in c:
                    parts = [p.strip() for p in c.split(',') if p.strip()]
                    for p in parts:
                        cat = classify_cipher_suite(p)
                        category_counts[cat] += 1
                        cipher_counts[p] += 1
                else:
                    cat = classify_cipher_suite(c)
                    category_counts[cat] += 1
                    cipher_counts[c] += 1

def main(root_dir):
    category_counts = Counter()
    cipher_counts = Counter()

    # Walk through all folders and subfolders for .json files
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            if fname.endswith(".json"):
                filepath = os.path.join(dirpath, fname)
                print(f"Processing {filepath}...")
                process_file(filepath, category_counts, cipher_counts)

    if not cipher_counts:
        print("No cipher suites found in input.")
        return

    # --- Summary of occurrences ---
    print("\nSummary of categories (occurrences):")
    for cat in ["Secure", "Recommended", "Weak", "Insecure", "Unknown"]:
        print(f"  {cat}: {category_counts[cat]}")

    # --- Unique cipher suite summary per category ---
    unique_by_category = defaultdict(set)
    for c in cipher_counts:
        cat = classify_cipher_suite(c)
        unique_by_category[cat].add(c)

    print("\nSummary of categories (unique cipher suites):")
    for cat in ["Secure", "Recommended", "Weak", "Insecure", "Unknown"]:
        print(f"  {cat}: {len(unique_by_category[cat])}")

    # --- Detailed unique cipher suites ---
    print("\nUnique cipher suites found:")
    for c, count in cipher_counts.most_common():
        cat = classify_cipher_suite(c)
        print(f"  {c} : {cat} ({count} occurrences)")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <folder_with_json_files>")
        sys.exit(1)
    main(sys.argv[1])
