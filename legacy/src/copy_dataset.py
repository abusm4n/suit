import os
import shutil

# Expand user (~) paths properly
def expand_path(path):
    return os.path.expanduser(path.strip())

# Path to the CSV file containing full file paths
csv_file_path = expand_path('~/update_traffic/update_keywords/update_related_pcaps.csv')

# Base path to preserve directory structure relative to this
base_path = expand_path('~/update_traffic/dataset/')

# Destination root where files will be copied
destination_root = expand_path('~/update_traffic/update_keywords/dataset')

# Make sure destination root exists
os.makedirs(destination_root, exist_ok=True)

with open(csv_file_path, 'r') as file:
    for line in file:
        original_path = expand_path(line)
        
        # Skip empty lines
        if not original_path:
            continue

        # Check if the file exists
        if os.path.isfile(original_path):
            # Compute relative path from base path
            rel_path = os.path.relpath(original_path, base_path)

            # Destination path
            destination_path = os.path.join(destination_root, rel_path)

            # Create destination directory if needed
            os.makedirs(os.path.dirname(destination_path), exist_ok=True)

            # Copy the file
            shutil.copy2(original_path, destination_path)
            print(f"Copied: {original_path} → {destination_path}")
        else:
            print(f"File not found: {original_path}")
