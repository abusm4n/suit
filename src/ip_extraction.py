import os
import csv
from scapy.all import rdpcap, IP, IPv6
from collections import Counter


# This script extracts unique communication pairs (source and destination IPs) from a given PCAP file, along with the count of packets exchanged between each pair. The results are saved to a CSV file.
# Usage, write the input and the output file paths in the main function, and run the script. The output CSV will have three columns: source_ip, destination_ip, and packet_count.


def extract_unique_contacts(pcap_file, filter_ips=None):
    """
    Extract unique communication pairs with packet counts.
    
    Args:
        pcap_file (str): path to pcap file
        filter_ips (set, optional): only include pairs where src or dst is in this set
    Returns:
        Counter: {(src,dst): packet_count}
    """
    pcap_file = os.path.expanduser(pcap_file)
    packets = rdpcap(pcap_file)

    contact_counter = Counter()

    for pkt in packets:
        # IPv4
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if not filter_ips or src in filter_ips or dst in filter_ips:
                contact_counter[(src, dst)] += 1

        # IPv6
        if IPv6 in pkt:
            src6 = pkt[IPv6].src
            dst6 = pkt[IPv6].dst
            if not filter_ips or src6 in filter_ips or dst6 in filter_ips:
                contact_counter[(src6, dst6)] += 1

    return contact_counter


def save_contacts_csv(filename, contacts):
    filename = os.path.expanduser(filename)
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    # Sort by packet_count descending
    sorted_contacts = sorted(contacts.items(), key=lambda x: x[1], reverse=True)

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["source_ip", "destination_ip", "packet_count"])
        for (src, dst), count in sorted_contacts:
            writer.writerow([src, dst, count])

    print(f"[Saved] {filename}")


if __name__ == "__main__":
    # pcap_path = "~/update_traffic/controlled/dataset/tapo/tapo.pcapng"
    # filter_ips = {"10.42.0.173"}

    # pcap_path = "~/update_traffic/controlled/dataset/eufy/eufy.pcapng"
    # filter_ips = {"10.42.0.160"} 

    # pcap_path = "~/update_traffic/controlled/dataset/xiaomi/xiaomi.pcapng"
    # filter_ips = {"10.42.0.207"} 

    # pcap_path = "~/update_traffic/controlled/dataset/dlink/dlink.pcapng"
    #filter_ips = {"10.42.0.152"} 

    pcap_path = "~/update_traffic/controlled/dataset/apple-tv/apple-tv.pcapng"
    filter_ips = {"10.42.0.25"} 


 

    contacts = extract_unique_contacts(pcap_path, filter_ips=filter_ips)

    print("\n=== Unique Communication Pairs (filtered) ===")
    for (src, dst), count in sorted(contacts.items(), key=lambda x: x[1], reverse=True):
        print(f"{src} → {dst}   ({count} packets)")

    save_contacts_csv("~/update_traffic/controlled/dataset/apple-tv/ip_contacts.csv",contacts)
