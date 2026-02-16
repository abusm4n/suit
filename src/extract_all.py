#!/usr/bin/env python3

#
# Extractor that is used for dumping PCAP file contents for the intl-iot dataset
# This tool dumps full PCAP content as JSON and HTTP objects using tshark
# Author: Ahmad Usman
# Usage: python3 extract_all.py <input_pcap_directory> <output_directory>
#  python3 src/extract_all.py ~/update_traffic/imc19_dataset/ ~/update_traffic/dataset/extracted_all/


import os
import argparse
import pathlib
import uuid
import pickle
import subprocess
from joblib import Parallel, delayed
import pyshark


parser = argparse.ArgumentParser(description='Analyze Packet Files')

# Input directory with PCAP files, output directory for dumps
parser.add_argument('dir', type=str, help='Directory of pcaps to recursively search through')
parser.add_argument('out', type=str, help='Directory to dump result files to')

args = parser.parse_args()
walk_dir = os.path.abspath(args.dir)
out_dir = os.path.abspath(args.out)

PCAP_EXT = '.pcap'

EXTRACTED_OBJS_DIR = out_dir
print("Extracting objects to ", EXTRACTED_OBJS_DIR)
pathlib.Path(EXTRACTED_OBJS_DIR).mkdir(parents=True, exist_ok=True)

file_metadata = []
jobs = []

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
    os.makedirs(object_out_dir, exist_ok=True)

    # Dump entire PCAP as JSON for full packet details
    try:
        json_path = os.path.join(object_out_dir, filename + ".json")
        with open(json_path, "w") as json_out:
            subprocess.run([
                "tshark",
                "-r", file_path,
                "-T", "json"
            ], stdout=json_out, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Tshark JSON dump failed on file {file_path} with error: {e}")

    # Extract HTTP objects if any (optional)
    try:
        subprocess.run([
            "tshark",
            "-nr", file_path,
            "--export-objects", f"http,{object_out_dir}"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Tshark HTTP export failed on file {file_path} with error: {e}")

    return metadata


job_id = 0
for root, subdirs, files in os.walk(walk_dir):
    for filename in files:
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
print("Begin parallel execution")
file_metadata = Parallel(n_jobs=5)(delayed(do_export)(job, job_count) for job in jobs)

with open(os.path.join(out_dir, 'file_metadata.pickle'), 'wb') as f:
    pickle.dump(file_metadata, f)
    print("The pickle has been tickled")
