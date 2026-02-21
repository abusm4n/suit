#!/usr/bin/env python3
import os
import csv
import subprocess
import argparse
from collections import Counter


# Usage:
# python3 src/protocol_extraction.py --pcap ~/update_traffic/controlled/dataset/apple-tv/apple-tv.pcapng --limit 100 --output ~/update_traffic/controlled/dataset/apple-tv/protocols.csv
# 1. Write the input pcap file path and the output CSV file path in the main function.
# 2. Run the script. It will extract unique protocols from the pcap file and save the results to the specified CSV file.
# 3. The output CSV will have two columns: protocol and packet_count, sorted by packet_count in descending order.
# 4. For large files, the script uses tshark for efficiency. If tshark is not available or fails
# 

# Optional import for streaming fallback (Scapy may not be installed in all environments)
try:
    from scapy.all import PcapReader
    HAVE_SCAPY = True
except Exception:
    PcapReader = None
    HAVE_SCAPY = False


def extract_unique_protocols_tshark(pcap_file, limit=None):
    pcap_file = os.path.expanduser(pcap_file)
    proto_counter = Counter()

    try:
        # Request both the full frame.protocols and the Protocol column (better for identifying TLS/QUIC/etc.)
        cmd = ['tshark', '-r', pcap_file, '-T', 'fields', '-e', 'frame.protocols', '-e', '_ws.col.Protocol', '-E', 'separator=|']
        if limit:
            cmd.extend(['-c', str(limit)])

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            print(f"tshark error: {proc.stderr.strip()[:200]}")
            return None

        for line in proc.stdout.splitlines():
            if not line:
                continue
            # Fields are separated by our -E separator (|): first is frame.protocols, second is Protocol column
            cols = line.split('|')
            frame_field = cols[0].strip() if len(cols) > 0 else ''
            col_proto_field = cols[1].strip() if len(cols) > 1 else ''

            # frame.protocols is colon-separated (e.g. eth:ip:tcp:http)
            parts = [p.strip().lower() for p in frame_field.split(':') if p.strip()]
            for p in parts:
                proto_counter[p] += 1

            # _ws.col.Protocol may contain higher-level protocol tokens like "TLSv1.2" or "QUIC".
            # Prefer tokens from the Protocol column (Wireshark view). Extract versions when present.
            if col_proto_field:
                token_text = col_proto_field.lower()
                import re
                matched_any = False

                # TLS versions: TLSv1.2, TLS 1.3, etc.
                for m in re.finditer(r'tlsv?\.?\s*(\d+(?:\.\d+)?)', token_text):
                    proto_counter[f"tlsv{m.group(1)}"] += 1
                    matched_any = True

                # QUIC with optional version (e.g. QUIC/1)
                for m in re.finditer(r'quic(?:/v?(\d+(?:\.\d+)?))?', token_text):
                    ver = m.group(1)
                    if ver:
                        proto_counter[f"quicv{ver}"] += 1
                    else:
                        proto_counter['quic'] += 1
                    matched_any = True

                # HTTP versions: HTTP/2, HTTP/3, HTTP/1.1
                for m in re.finditer(r'http(?:/|v)?\s*(\d(?:\.\d+)?)', token_text):
                    proto_counter[f"http{m.group(1)}"] += 1
                    matched_any = True

                # Generic matches for TCP/UDP and common protocols
                if re.search(r'\btcp\b', token_text):
                    proto_counter['tcp'] += 1
                    matched_any = True
                if re.search(r'\budp\b', token_text):
                    proto_counter['udp'] += 1
                    matched_any = True
                for tok in ['dns', 'mdns', 'arp', 'dhcp', 'icmpv6', 'icmp', 'igmp', 'eapol']:
                    if re.search(rf'\b{tok}\b', token_text):
                        proto_counter[tok] += 1
                        matched_any = True

                if not matched_any:
                    # Fallback: split on separators and count remaining tokens (keeps versions if present)
                    token_text_clean = token_text.replace('/', ' ').replace(',', ' ').replace('(', ' ').replace(')', ' ')
                    for tok in token_text_clean.split():
                        if tok:
                            proto_counter[tok] += 1

        return proto_counter

    except FileNotFoundError:
        print("tshark not found; install it or use the streaming fallback")
        return None
    except Exception as e:
        print(f"tshark error: {e}")
        return None


def extract_unique_protocols_streaming(pcap_file, limit=None):
    pcap_file = os.path.expanduser(pcap_file)
    proto_counter = Counter()
    processed = 0
    if not HAVE_SCAPY:
        print("Scapy not available for streaming fallback. Install scapy or use tshark.")
        return None

    try:
        with PcapReader(pcap_file) as reader:
            for pkt in reader:
                processed += 1
                if limit and processed > limit:
                    break

                # Walk packet payload chain to gather layer names
                l = pkt
                seen = set()
                while l:
                    name = getattr(l, "name", None) or l.__class__.__name__
                    if name and name not in seen:
                        seen.add(name)
                        proto_counter[name] += 1
                    try:
                        # move to next layer
                        l = l.payload
                        if l is None or str(l) == '':
                            break
                    except Exception:
                        break

    except Exception as e:
        print(f"Error reading pcap: {e}")

    print(f"Processed {processed} packets (streaming)")
    return proto_counter


def save_protocols_csv(filename, proto_counter):
    filename = os.path.expanduser(filename)
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    sorted_protos = sorted(proto_counter.items(), key=lambda x: x[1], reverse=True)

    with open(filename, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['protocol', 'packet_count'])
        for proto, cnt in sorted_protos:
            w.writerow([proto, cnt])

    print(f"[Saved] {filename}")


def extract_unique_protocols(pcap_file, limit=None):
    print(f"Extracting protocols from: {pcap_file}")
    procs = extract_unique_protocols_tshark(pcap_file, limit=limit)
    if procs is not None:
        return procs
    return extract_unique_protocols_streaming(pcap_file, limit=limit)


def main():
    p = argparse.ArgumentParser(description='Extract unique protocols from a pcap/pcapng file')
    p.add_argument('--pcap', '-r', required=True, help='Path to pcap/pcapng file')
    p.add_argument('--limit', '-n', type=int, default=None, help='Limit packets for quick tests')
    p.add_argument('--output', '-o', default='protocols.csv', help='CSV output path')
    args = p.parse_args()

    protos = extract_unique_protocols(args.pcap, limit=args.limit)
    if protos is None:
        print('No protocols extracted (tshark failed and streaming fallback returned nothing)')
        return

    print('\n=== Protocols (top 50) ===')
    for proto, cnt in list(sorted(protos.items(), key=lambda x: x[1], reverse=True))[:50]:
        print(f"{proto}: {cnt}")

    save_protocols_csv(args.output, protos)


if __name__ == '__main__':
    main()
