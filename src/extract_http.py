#!/usr/bin/env python3

#
# Extractor that is used for dumping PCAP file contents for the intl-iot dataset
# This tool dumps HTTP data only using tshark
# Author: Ahmad Usman
#  python3 src/extract_all.py ~/update_traffic/imc19_dataset/ ~/update_traffic/dataset/extracted_all/



import os
import argparse
import pathlib
import uuid
import pickle
import subprocess
from joblib import Parallel, delayed
import pyshark


#
parser = argparse.ArgumentParser(description='Analyze Packet Files')

# Add arguments for input directory and output directory
# The input directory is where the PCAP files are located, and the output directory is where the extracted objects will be saved
parser.add_argument('dir', type=str, help='Directory of pcaps to recursively search through')
parser.add_argument('out', type=str, help='Directory to dump result files to')

# Parse the command line arguments
# This will convert the input and output directory arguments to absolute paths
# This is useful for ensuring that the script works correctly regardless of the current working directory

args = parser.parse_args()
walk_dir = os.path.abspath(args.dir)
out_dir = os.path.abspath(args.out)
# Define the file extension for PCAP files
PCAP_EXT = '.pcap'

# Output directory
EXTRACTED_OBJS_DIR = out_dir
print("Extracting objects to ", EXTRACTED_OBJS_DIR)
# Create the output directory if it does not exist
pathlib.Path(EXTRACTED_OBJS_DIR).mkdir(parents=True, exist_ok=True)
# Initialize lists to hold file metadata and jobs for parallel processing
# This will hold metadata about the files processed, such as UUIDs, filenames, and file paths
# This will hold the jobs to be processed in parallel, including the job ID, directory UUID, filename, file path, and root segments of the directory structure
file_metadata = []
jobs = []


# Function to extract packets based on a display filter
# This function collects SSL handshake packets and their details
# It uses pyshark to read the PCAP file and applies the specified display filter
# It returns a list of dictionaries containing SSL handshake details and source IP addresses
def extract_packets_by_filter(packet_file, filter_exp):
    collected_packets = []
    packets = pyshark.FileCapture(packet_file, display_filter=filter_exp, use_json=True, custom_parameters=["-Y", "ssl.handshake.ciphersuites"])
    try:
        for pkt in packets:
            try:
                ip_src = pkt.ip.src if hasattr(pkt, 'ip') else None
                ssl_layer = pkt.ssl if hasattr(pkt, 'ssl') else None

                if ssl_layer and hasattr(ssl_layer, 'handshake_version') and hasattr(ssl_layer, 'handshake_type'):
                    handshake_version = ssl_layer.handshake_version
                    handshake_type = ssl_layer.handshake_type
                    ciphersuite = getattr(ssl_layer, 'handshake_ciphersuite', None)

                    collected_packets.append({
                        "SSL": {
                            'ssl.handshake.version': handshake_version,
                            'ssl.handshake.type': handshake_type,
                            'ssl.handshake.ciphersuite': ciphersuite
                        },
                        "IP": {
                            'ip.src': ip_src
                        }
                    })
            except Exception as e:
                print(f"[!] Packet parse error: {e}")
    finally:
        packets.close()
    return collected_packets


# Function to process each job in parallel
# This function extracts server and client hello packets from the PCAP file
# It constructs metadata based on the directory structure and the type of action (idle or not)
# It runs tshark to export HTTP objects to the specified output directory
# It returns a dictionary containing the metadata for the processed file 
# The metadata includes the UUID, dataset, region, device, action, server hello packets, client hello packets, and the path to the PCAP file

def do_export(job, job_count):
    dir_uuid = job['dir_uuid']
    filename = job['filename']
    file_path = job['filepath']
    root_segments = job['root_segments']
    root_segments_len = len(root_segments)

    if (job['job_id'] % 1000 == 0):
        print(job['job_id'], '/', job_count)

    is_idle = '/iot-idle/' in file_path

    server_hello_packets = extract_packets_by_filter(file_path, "ssl.handshake.type == 2")
    client_hello_packets = extract_packets_by_filter(file_path, "ssl.handshake.type == 1")

    if is_idle:
        metadata = {
            'uuid': dir_uuid,
            'dataset': root_segments[root_segments_len - 3],
            'region': root_segments[root_segments_len - 2],
            'device': root_segments[root_segments_len - 1],
            'server_hello_packets': server_hello_packets,
            'client_hello_packets': client_hello_packets,
            'action': "idle",
            'pcap': file_path
        }
    else:
        metadata = {
            'uuid': dir_uuid,
            'dataset': root_segments[root_segments_len - 4],
            'region': root_segments[root_segments_len - 3],
            'device': root_segments[root_segments_len - 2],
            'action': root_segments[root_segments_len - 1],
            'server_hello_packets': server_hello_packets,
            'client_hello_packets': client_hello_packets,
            'pcap': file_path
        }

    object_out_dir = os.path.join(EXTRACTED_OBJS_DIR, dir_uuid)
    os.makedirs(object_out_dir, exist_ok=True)  # Ensure output directory exists


    # This command extracts HTTP objects from the PCAP file and saves them to the specified directory
    # Suppress stdout and stderr to avoid cluttering the console
    # subprocess.run(["tshark", "-v"], check=True)  # Check if tshark is available
    # If tshark is not available, it will raise an error
    # If tshark is available, it will run the command to export HTTP objects
    # This is useful for extracting files transferred over HTTP in the PCAP file
    #

    try:
        subprocess.run([
            "tshark",
            "-nr", file_path,
            "--export-objects", f"http,{object_out_dir}"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Tshark failed on file {file_path} with error: {e}")

    return metadata





# Initialize job ID
# This variable is used to uniquely identify each job in the job list
# This will be incremented for each job added to the list
job_id = 0
# Build the job list for concurrent execution
for root, subdirs, files in os.walk(walk_dir):
    for filename in files:
        # Only process PCAP files
        if filename.lower().endswith(PCAP_EXT):
            file_path = os.path.join(root, filename)
            jobs.append({
                'job_id': job_id,
                'dir_uuid': str(uuid.uuid4()),
                'filename': filename,
                'filepath': file_path,
                'root_segments': root.split(os.sep)
            })
            job_id += 1

job_count = len(jobs)


# Print the total number of jobs to be processed
print("Begin parallel execution")
file_metadata = Parallel(n_jobs=5)(delayed(do_export)(job, job_count) for job in jobs)

with open(os.path.join(out_dir, 'file_metadata.pickle'), 'wb') as f:
    pickle.dump(file_metadata, f)
    print("The pickle has been tickled")
