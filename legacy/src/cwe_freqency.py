import json
from collections import Counter
import os

# 

# Function to load JSON file
def load_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

# Function to extract CWE identifiers (ensures unique CWEs per file)
def extract_cwes(cve_data):
    cwes = set()  # Use a set to avoid counting the same CWE multiple times per file
    
    # Check if problemTypes data is present
    problemTypes_data = cve_data.get('containers', {}).get('cna', {}).get('problemTypes', [])
    
    for problemType in problemTypes_data:
        descriptions = problemType.get('descriptions', [])
        for description in descriptions:
            cwe = description.get('cweId')
            if cwe:
                cwes.add(cwe)  # Add to set, automatically handles duplicates
    
    return list(cwes)  # Convert back to list to return

# Function to count how many files do not contain any CWE identifiers
def count_files_without_cwe(cwe_count_per_file):
    return sum(1 for count in cwe_count_per_file if count == 0)

# Function to check if a file has multiple CWE identifiers
def has_multiple_cwe(cwes):
    return len(cwes) > 1

# Path to dataset folder
#dataset_folder = './cve/cipher_insecure'
#dataset_folder = './cve/cipher_weak'
#dataset_folder = './cve/weak'
#dataset_folder = './cve/insecure'
dataset_folder = './cve/all'





#dataset_folder = os.path.expanduser('~/update_traffic/cwe/cipher_insecure')

# Get list of JSON files in the dataset folder
json_files = [file for file in os.listdir(dataset_folder) if file.endswith('.json')]

# Initialize counter to accumulate CWE counts
total_cwe_counter = Counter()
# List to track the number of CWEs per file
cwe_count_per_file = []
# List to track files with multiple CWEs
files_with_multiple_cwes = []

# List to track files with zero CWEs
files_without_cwe = []

# Process each JSON file and accumulate CWE counts
for file_name in json_files:
    file_path = os.path.join(dataset_folder, file_name)
    cve_json = load_json_file(file_path)
    
    # Initialize counter for current file
    cwe_counter = Counter()
    
    # Skip files that couldn't be loaded
    if cve_json is None:
        print("None here")
        cwe_counter["None"] += 1
        # Accumulate counts to total counter
        total_cwe_counter += cwe_counter
        continue

    cwes = extract_cwes(cve_json)  # Extract unique CWEs per file
    cwe_count_per_file.append(len(cwes))  # Track number of CWEs in this file


    # Track files without CWE
    if len(cwes) == 0:
        files_without_cwe.append(file_name)
    
    # Check if the file has multiple CWEs and store its name
    if has_multiple_cwe(cwes):
        files_with_multiple_cwes.append(file_name)

    # Disable the printing when running the overall vulnerabilities
    #print(file_name, len(cwes))
    
    # Count CWE identifiers for current file
    # Disable the printing when running the overall vulnerabilities
    for cwe in cwes:
        #print(file_name, cwe)
        cwe_counter[cwe] += 1

    # Accumulate counts to total counter
    total_cwe_counter += cwe_counter

# Count how many files had zero CWEs
zero_cwe_count = count_files_without_cwe(cwe_count_per_file)

# Print the total frequency of each CWE identifier sorted by frequency
print("Total CWE Frequency:")
for cwe, count in total_cwe_counter.most_common():
    print(f"{cwe}: {count}")



# Disable some printing when running the overall vulnerabilities
print(f"Total JSON files found: {len(json_files)}")
print(f"TJSON files missing 'cweId' field: {zero_cwe_count}")
print(f"Total JSON files considered: {len(json_files)-zero_cwe_count}")



# Print files without CWE
print(f"Files missing 'cweId' field ({len(files_without_cwe)}):")
for file_name in files_without_cwe:
    print(file_name)

# Disable some printing when running the overall vulnerabilities
#print(f"Files with multiple CWEs: {len(files_with_multiple_cwes)}")
#for file_name in files_with_multiple_cwes:
 #   print(file_name)
