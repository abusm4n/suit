import os
import csv
import glob
import pandas as pd

def process_entropy_file(filepath):
    """
    Reads a CSV file and computes the average of:
    - Shannon entropy
    - Rényi entropy
    - Tsallis entropy
    - Payload size (data_len)
    Only considers rows where data_type is NOT 'encrypted'.
    Ignores negative values.
    """
    shannon_list = []
    renyi_list = []
    tsallis_list = []
    data_len_list = []

    with open(filepath, 'r') as file:
        reader = csv.reader(file)
        header = next(reader, None)
        if not header:
            return 0, 0, 0, 0

        # Find column indices by name
        try:
            data_type_idx = header.index('data_type')
            data_len_idx = header.index('data_len')
            shannon_idx = header.index('entropy_shannon')
            renyi_idx = header.index('entropy_renyi')
            tsallis_idx = header.index('entropy_tsallis')
        except ValueError as e:
            print(f"Missing expected column in {filepath}: {e}")
            return 0, 0, 0, 0

        for row in reader:
            try:
                data_type = row[data_type_idx].strip().lower()
                if data_type == 'encrypted':
                    continue  # Skip encrypted rows

                data_len = float(row[data_len_idx])
                shannon = float(row[shannon_idx])
                renyi = float(row[renyi_idx])
                tsallis = float(row[tsallis_idx])

                if data_len >= 0:
                    data_len_list.append(data_len)
                if shannon >= 0:
                    shannon_list.append(shannon)
                if renyi >= 0:
                    renyi_list.append(renyi)
                if tsallis >= 0:
                    tsallis_list.append(tsallis)
            except (ValueError, IndexError):
                continue  # Skip malformed rows

    avg_len = sum(data_len_list) / len(data_len_list) if data_len_list else 0
    avg_shannon = sum(shannon_list) / len(shannon_list) if shannon_list else 0
    avg_renyi = sum(renyi_list) / len(renyi_list) if renyi_list else 0
    avg_tsallis = sum(tsallis_list) / len(tsallis_list) if tsallis_list else 0

    return avg_len, avg_shannon, avg_renyi, avg_tsallis

def process_folder(input_root, output_root):
    if not os.path.isdir(input_root):
        raise FileNotFoundError(f"Input folder does not exist: {input_root}")

    for root, dirs, files in os.walk(input_root):
        csv_files = [f for f in files if f.endswith('.csv')]
        if not csv_files:
            continue

        rel_path = os.path.relpath(root, input_root)
        output_dir = os.path.join(output_root, rel_path)
        os.makedirs(output_dir, exist_ok=True)
        output_csv = os.path.join(output_dir, 'entropy_summary.csv')

        results = []
        for csv_file in csv_files:
            filepath = os.path.join(root, csv_file)
            avg_len, avg_shannon, avg_renyi, avg_tsallis = process_entropy_file(filepath)

            # Skip files with all-zero averages
            if any([avg_len, avg_shannon, avg_renyi, avg_tsallis]):
                results.append({
                    'filename': csv_file,
                    'avg_data_len': avg_len,
                    'avg_shannon': avg_shannon,
                    'avg_renyi': avg_renyi,
                    'avg_tsallis': avg_tsallis
                })
            else:
                print(f"Skipped {csv_file} (all-zero or non-matching rows)")

        if results:
            df = pd.DataFrame(results)
            df.to_csv(output_csv, index=False)
            print(f"Summary written to {output_csv}")
        else:
            print(f"No valid rows in {root}, nothing written.")

if __name__ == '__main__':
    input_root = os.path.expanduser('~/update_traffic/dataset/entropy/iot-data')
    output_root = os.path.expanduser('~/update_traffic/dataset/unencrypted_average/iot-data')
    process_folder(input_root, output_root)
