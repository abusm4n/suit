import os
import csv
import subprocess
from collections import Counter
from scapy.all import PcapReader, IP, IPv6


# This script extracts unique communication pairs (source and destination IPs) from a given PCAP file, along with the count of packets exchanged between each pair. The results are saved to a CSV file.
# Usage, write the input and the output file paths in the main function, change the ip and saved location and run the script. The output CSV will have three columns: source_ip, destination_ip, and packet_count.
# For large files, uses tshark (Wireshark CLI tool) for efficiency. Fallback to streaming Scapy reader if needed.


def extract_unique_contacts_tshark(pcap_file, filter_ips=None):
    """
    Extract unique communication pairs using tshark (fast and memory-efficient).
    
    Args:
        pcap_file (str): path to pcap file
        filter_ips (set, optional): only include pairs where src or dst is in this set
    Returns:
        Counter: {(src,dst): packet_count}
    """
    pcap_file = os.path.expanduser(pcap_file)
    contact_counter = Counter()
    
    try:
        # Use tshark to extract src and dst IPs
        cmd = ['tshark', '-r', pcap_file, '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', 
               '-e', 'ipv6.src', '-e', 'ipv6.dst', '-E', 'separator=|']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print(f"Warning: tshark error - {result.stderr[:200]}")
            return extract_unique_contacts_streaming(pcap_file, filter_ips)
        
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split('|')
            
            # Check IPv4
            src, dst = parts[0].strip(), parts[1].strip()
            if src and dst:
                if not filter_ips or src in filter_ips or dst in filter_ips:
                    contact_counter[(src, dst)] += 1
            
            # Check IPv6
            src6, dst6 = parts[2].strip(), parts[3].strip()
            if src6 and dst6:
                if not filter_ips or src6 in filter_ips or dst6 in filter_ips:
                    contact_counter[(src6, dst6)] += 1
        
        return contact_counter
        
    except FileNotFoundError:
        print("tshark not found. Install with: sudo apt-get install tshark")
        print("Falling back to streaming reader...")
        return extract_unique_contacts_streaming(pcap_file, filter_ips)
    except Exception as e:
        print(f"tshark error: {e}. Using streaming reader...")
        return extract_unique_contacts_streaming(pcap_file, filter_ips)


def extract_unique_contacts_streaming(pcap_file, filter_ips=None):
    """
    Extract unique communication pairs using streaming reader (memory-efficient).
    Uses PcapReader instead of rdpcap to avoid loading entire file into memory.
    
    Args:
        pcap_file (str): path to pcap file
        filter_ips (set, optional): only include pairs where src or dst is in this set
    Returns:
        Counter: {(src,dst): packet_count}
    """
    pcap_file = os.path.expanduser(pcap_file)
    contact_counter = Counter()
    packet_count = 0

    try:
        with PcapReader(pcap_file) as reader:
            for pkt in reader:
                packet_count += 1
                if packet_count % 100000 == 0:
                    print(f"  Processed {packet_count} packets...")
                
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

    except Exception as e:
        print(f"Error reading pcap: {e}")
        
    print(f"Total packets processed: {packet_count}")
    return contact_counter


def extract_unique_contacts(pcap_file, filter_ips=None):
    """
    Extract unique communication pairs with packet counts.
    Automatically uses best available method (tshark > streaming reader).
    
    Args:
        pcap_file (str): path to pcap file
        filter_ips (set, optional): only include pairs where src or dst is in this set
    Returns:
        Counter: {(src,dst): packet_count}
    """
    print(f"Extracting IPs from: {pcap_file}")
    return extract_unique_contacts_tshark(pcap_file, filter_ips)


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

    #pcap_path = "~/update_traffic/controlled/dataset/fire-tv/fire-tv.pcapng"
    #filter_ips = {"10.42.0.23"} 


    #pcap_path = "~/update_traffic/controlled/dataset/riolink/riolink.pcapng"
    #filter_ips = {"10.42.0.170"} 

    #pcap_path = "~/update_traffic/controlled/dataset/tapo-c100/tapo-c100.pcapng"
    #filter_ips = {"10.42.0.135"}

    #pcap_path = "~/update_traffic/controlled/dataset/sony-tv/sony-tv.pcapng"
    #filter_ips = {"10.42.0.157"}




    #pcap_path = "~/update_traffic/controlled/dataset/apple-tv/apple-tv.pcapng"
    #filter_ips = {"10.42.0.25"} 

    pcap_path = "~/update_traffic/controlled/dataset/homepod/homepod.pcapng"
    filter_ips = {"10.42.0.79"} 

   
 

    contacts = extract_unique_contacts(pcap_path, filter_ips=filter_ips)

    print("\n=== Unique Communication Pairs (filtered) ===")
    for (src, dst), count in sorted(contacts.items(), key=lambda x: x[1], reverse=True):
        print(f"{src} → {dst}   ({count} packets)")

    save_contacts_csv("~/update_traffic/controlled/dataset/homepod/ip_contacts.csv",contacts)
