import csv
import subprocess
from collections import defaultdict

# --- CONFIG ---
#pcap_file = "./controlled/dataset/tapo/tapo.pcapng"
#output_csv = "./controlled/stream/tapo_stream_sizes.csv"



#pcap_file = "./controlled/dataset/eufy/eufy.pcapng"
#output_csv = "./controlled/stream/eufy_stream_sizes.csv"



#pcap_file = "./controlled/dataset/xiaomi/xiaomi.pcapng"
#output_csv = "./controlled/stream/xiaomi_stream_sizes.csv"



#pcap_file = "./controlled/dataset/dlink/dlink.pcapng"
#output_csv = "./controlled/stream/dlink_stream_sizes.csv"



pcap_file = "./controlled/dataset/sony_tv/sony_tv.pcapng"
output_csv = "./controlled/stream/sony_tv_stream_sizes.csv"




include_megabytes = True   # set False if you do not want MB column

# --- RUN TSHARK ---
cmd = [
    "tshark",
    "-r", pcap_file,
    "-T", "fields",
    "-e", "tcp.stream",
    "-e", "frame.len"
]

print("Running tshark...")

process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

stream_bytes = defaultdict(int)

# --- PARSE TSHARK OUTPUT ---
for line in process.stdout:
    parts = line.strip().split()
    if len(parts) != 2:
        continue

    stream, frame_len = parts

    if not stream or not frame_len:
        continue

    try:
        stream = int(stream)
        frame_len = int(frame_len)
    except ValueError:
        continue

    stream_bytes[stream] += frame_len

# remove streams with zero total bytes
stream_bytes = {s: b for s, b in stream_bytes.items() if b > 0}

# --- WRITE CSV ---
print(f"Writing CSV: {output_csv}")

with open(output_csv, "w", newline="") as f:
    writer = csv.writer(f)

    # Header row
    if include_megabytes:
        writer.writerow(["stream", "bytes", "megabytes", "tuple"])
    else:
        writer.writerow(["stream", "bytes", "tuple"])

    # Data rows
    for s, b in sorted(stream_bytes.items()):
        mb = round(b / 1048576, 3) if include_megabytes else ""
        tuple_text = f"({s}, {b})"

        if include_megabytes:
            writer.writerow([s, b, mb, tuple_text])
        else:
            writer.writerow([s, b, tuple_text])

print("Done.")
