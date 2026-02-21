#!/usr/bin/env python3
#
# Extractor that is used for dumping PCAP file contents for the intl-iot dataset
# This tool dumps tls data only using tshark
# Author: Ahmad Usman

import os
import argparse
import pathlib
import uuid
import pickle
import json
from joblib import Parallel, delayed
import pyshark


import time

start = time.perf_counter()

parser = argparse.ArgumentParser(description='Analyze Packet Files')
parser.add_argument('dir', type=str, help='Directory of pcaps to recursively search through')
parser.add_argument('out', type=str, help='Directory to dump result files to')

args = parser.parse_args()
walk_dir = os.path.abspath(args.dir)
out_dir = os.path.abspath(args.out)

PCAP_EXT = '.pcap'
EXTRACTED_OBJS_DIR = out_dir
print("Extracting objects to:", EXTRACTED_OBJS_DIR)
pathlib.Path(EXTRACTED_OBJS_DIR).mkdir(parents=True, exist_ok=True)

def extract_tls_handshake(packet_file, handshake_type):
    collected_packets = []
    # We do NOT print detailed info here anymore
    try:
        packets = pyshark.FileCapture(
            packet_file,
            display_filter=f"tls.handshake.type == {handshake_type}",
            use_json=True
        )
        for pkt in packets:
            # Collect detailed layer info per packet
            packet_layers = []
            for layer in pkt.layers:
                # layer._all_fields is dict of all fields
                layer_info = {
                    "layer_name": layer.layer_name,
                    "fields": dict(layer._all_fields)
                }
                packet_layers.append(layer_info)

            ip_src = pkt.ip.src if hasattr(pkt, 'ip') else None
            tls_layer = pkt.tls if hasattr(pkt, 'tls') else None

            if tls_layer:
                collected_packets.append({
                    "layers": packet_layers,
                    "TLS": {
                        'tls.handshake.version': getattr(tls_layer, 'handshake_version', None),
                        'tls.handshake.type': getattr(tls_layer, 'handshake_type', None),
                        'tls.handshake.ciphersuite': getattr(tls_layer, 'handshake_ciphersuite', None)
                    },
                    "IP": {
                        'ip.src': ip_src
                    }
                })
        packets.close()
    except Exception as e:
        print(f"[!] Error processing {packet_file}: {e}")
    return collected_packets

def do_export(job, job_count):
    dir_uuid = job['dir_uuid']
    filename = job['filename']
    file_path = job['filepath']
    root_segments = job['root_segments']
    root_segments_len = len(root_segments)

    if (job['job_id'] % 100 == 0):
        print(f"Processing job {job['job_id']} / {job_count}: {filename}")

    is_idle = '/iot-data/' in file_path

    client_hello = extract_tls_handshake(file_path, 1)
    server_hello = extract_tls_handshake(file_path, 2)

    # Skip saving if no TLS handshake info
    if not client_hello and not server_hello:
        print(f"[!] No TLS handshake packets found in {file_path}")
        return None

    if is_idle:
        metadata = {
            'uuid': dir_uuid,
            'dataset': root_segments[root_segments_len - 3],
            'region': root_segments[root_segments_len - 2],
            'device': root_segments[root_segments_len - 1],
            'action': "idle",
        }
    else:
        metadata = {
            'uuid': dir_uuid,
            'dataset': root_segments[root_segments_len - 4],
            'region': root_segments[root_segments_len - 3],
            'device': root_segments[root_segments_len - 2],
            'action': root_segments[root_segments_len - 1],
        }

    metadata.update({
        'pcap': file_path,
        'client_hello_count': len(client_hello),
        'server_hello_count': len(server_hello)
    })

    # Create output folder and save TLS JSON if info exists
    object_out_dir = os.path.join(EXTRACTED_OBJS_DIR, dir_uuid)
    os.makedirs(object_out_dir, exist_ok=True)

    tls_out_path = os.path.join(object_out_dir, 'tls_handshake.json')
    with open(tls_out_path, 'w') as f:
        json.dump({
            'client_hello_packets': client_hello,
            'server_hello_packets': server_hello
        }, f, indent=2)

    return metadata

job_id = 0
jobs = []
for root, _, files in os.walk(walk_dir):
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
print(f"Total jobs to process: {job_count}")

file_metadata = Parallel(n_jobs=5)(delayed(do_export)(job, job_count) for job in jobs)

# Filter out jobs where no TLS data was found (None)
file_metadata = [m for m in file_metadata if m is not None]

with open(os.path.join(out_dir, 'file_metadata.pickle'), 'wb') as f:
    pickle.dump(file_metadata, f)
    print("[+] Metadata saved to file_metadata.pickle")

print("[+] TLS extraction completed.")


for i in range(1000000):
    pass
# ------------------------

end = time.perf_counter()
print(f"Time taken: {end - start:.4f} seconds")