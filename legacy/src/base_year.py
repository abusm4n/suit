import os
import json
import re
import csv

# Directory containing  CVE JSON files
# Directory to save the output CSV file



INPUT_DIR = './cve/all'
OUTPUT_CSV = './legacy/csv/all_base.csv'



def extract_year(cve_id_str):
    """
    Given a string like "CVE-2016-2809",
    return '2016'. Returns None if no match.
    """
    m = re.search(r'CVE-(\d{4})-', cve_id_str)
    return m.group(1) if m else None

def extract_base_score(cna_metrics):
    """
    Given the list under containers->cna->metrics,
    find the first CVSS v3 entry and return its baseScore.
    """
    for metric in cna_metrics:
        # look for any CVSSv3 key
        for key in ('cvssV3_0', 'cvssV3_1', 'cvssMetricV3'):
            if key in metric:
                score = metric[key].get('baseScore')
                if isinstance(score, (int, float)):
                    return score
    return None

def process_file(path):
    """
    Load a single JSON file and return a tuple (year, base_score, 'CVE')
    or None if any part is missing.
    """
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    cve_id = data.get('cveMetadata', {}).get('cveId', '').strip()
    year = extract_year(cve_id)
    metrics = data.get('containers', {}).get('cna', {}).get('metrics', [])
    base_score = extract_base_score(metrics)
    if year and base_score is not None:
        return year, base_score, 'update_traffic'
    return None

def main():
    rows = []
    for root, _, files in os.walk(INPUT_DIR):
        for fname in files:
            if not fname.lower().endswith('.json'):
                continue
            full_path = os.path.join(root, fname)
            rec = process_file(full_path)
            if rec:
                rows.append(rec)

    # write out CSV
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as csvf:
        writer = csv.writer(csvf)
        writer.writerow(['year', 'base', 'type'])
        writer.writerows(rows)

    print(f"Wrote {len(rows)} records to {OUTPUT_CSV}")

if __name__ == '__main__':
    main()
