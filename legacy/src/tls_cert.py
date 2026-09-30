import subprocess
import json
import socket
import hashlib
import sys

# You need to have pyasn1, pyasn1-modules, and cryptography for X509 cert parsing,
# or adapt your cert parsing code accordingly. 
# For now, I'll keep a minimal cert hash + signature algorithm placeholder.

# Dummy SIG_ALG_MAPPING & cipher_suite_mapping (fill in with your real mappings)
SIG_ALG_MAPPING = {
    b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05': 'sha1WithRSAEncryption',  # Example OID bytes
    # Add more as needed
}

cipher_suite_mapping = {
    '1301': 'TLS_AES_128_GCM_SHA256',
    '1302': 'TLS_AES_256_GCM_SHA384',
    # Add more known cipher suites here
}

class PCAPParserApp:
    def __init__(self):
        self.encrypted_data = []
        self.cipher_suite_info = []
        self.certificates = []
        self.seen_cert_hashes = set()
        self.tshark_path = 'tshark'  # or full path if not in PATH

    def run_tshark_command(self, command):
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
            return result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            print(f"tshark error: {e.stderr}", file=sys.stderr)
            return []

    def process_tls_appdata(self, file_path, display_filter=''):
        command = [
            self.tshark_path,
            '-r', file_path,
            '-Y', f'tls.app_data&&{display_filter}' if display_filter else 'tls.app_data',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'tls.record.version',
            '-e', 'tls.app_data'
        ]
        lines = self.run_tshark_command(command)

        for line in lines:
            parts = line.split('\t')
            if len(parts) < 6:
                continue
            src_ip, dst_ip, sport, dport, version, data_hex = parts
            try:
                data = bytes.fromhex(data_hex)
                self.encrypted_data.append({
                    'proto': 'TLS',
                    'version': version,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'sport': sport,
                    'dport': dport,
                    'data': data
                })
            except ValueError:
                continue

    def process_ciphersuites(self, file_path, display_filter=''):
        command = [
            self.tshark_path,
            '-r', file_path,
            '-Y', f'tls.handshake.type==2&&{display_filter}' if display_filter else 'tls.handshake.type==2',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tls.handshake.ciphersuite'
        ]
        lines = self.run_tshark_command(command)

        for line in lines:
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            src_ip, dst_ip, suite = parts
            self.cipher_suite_info.append((src_ip, dst_ip, suite))

    def process_certificates(self, file_path, display_filter=''):
        command = [
            self.tshark_path,
            '-r', file_path,
            '-Y', f'tls.handshake.type==11&&{display_filter}' if display_filter else 'tls.handshake.type==11',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tls.handshake.certificate'
        ]
        lines = self.run_tshark_command(command)

        for line in lines:
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            src_ip, dst_ip, certs_hex = parts
            try:
                certs = certs_hex.split(',')
                for cert_hex in certs:
                    cert_der = bytes.fromhex(cert_hex)
                    self.process_single_cert(cert_der, src_ip, dst_ip)
            except ValueError:
                continue

    def process_single_cert(self, cert_der, src_ip, dst_ip):
        cert_hash = hashlib.sha256(cert_der).hexdigest()
        if cert_hash in self.seen_cert_hashes:
            return
        self.seen_cert_hashes.add(cert_hash)

        # For simplicity, skip deep cert parsing, just dummy sig alg
        sig_name = "UnknownAlg"

        self.certificates.append({
            'ip_pair': f"{src_ip} -> {dst_ip}",
            'cert': cert_der,
            'cert_hash': cert_hash,
            'sig_alg': sig_name
        })

    def process_esp_data(self, file_path, display_filter=''):
        command = [
            self.tshark_path,
            '-r', file_path,
            '-Y', f'esp{(" && " + display_filter) if display_filter else ""}',
            '-T', 'jsonraw'
        ]
        json_output = self.run_tshark_command(command)

        if not json_output:
            return

        try:
            json_str = ''.join(json_output)
            packets = json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}", file=sys.stderr)
            return

        for packet in packets:
            layers = packet.get("_source", {}).get("layers", {})
            esp_layer = layers.get("esp", {})
            ip_layer = layers.get("ip", {})
            esp_raw = layers.get("esp_raw", [""])[0] if "esp_raw" in layers else ""

            spi_hex = esp_layer.get("esp.spi_raw", [""])[0] if "esp.spi_raw" in esp_layer else ""
            seq_hex = esp_layer.get("esp.sequence_raw", [""])[0] if "esp.sequence_raw" in esp_layer else ""
            src_ip_hex = ip_layer.get("ip.src_raw", [""])[0] if "ip.src_raw" in ip_layer else ""
            dst_ip_hex = ip_layer.get("ip.dst_raw", [""])[0] if "ip.dst_raw" in ip_layer else ""

            try:
                spi = int(spi_hex.replace('0x', ''), 16) if spi_hex else 0
                seq = int(seq_hex.replace('0x', ''), 16) if seq_hex else 0
                data = bytes.fromhex(esp_raw.replace(':', ''))[8:] if esp_raw else b''
                src_ip = self.hex_to_ip(src_ip_hex)
                dst_ip = self.hex_to_ip(dst_ip_hex)

                self.encrypted_data.append({
                    'proto': 'ESP',
                    'spi': spi,
                    'seq': seq,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'data': data
                })
            except (ValueError, KeyError) as e:
                print(f"ESP data parse error: {e}", file=sys.stderr)
                continue

    def hex_to_ip(self, hex_str):
        hex_clean = hex_str.replace('0x', '').replace(':', '').strip()
        try:
            if len(hex_clean) == 8:
                addr_bytes = bytes.fromhex(hex_clean)
                return socket.inet_ntop(socket.AF_INET, addr_bytes)
            elif len(hex_clean) == 32:
                addr_bytes = bytes.fromhex(hex_clean)
                return socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                return hex_str
        except Exception:
            return hex_str

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tls_cert.py <pcap_file> [display_filter]")
        sys.exit(1)

    pcap_file = sys.argv[1]
    display_filter = sys.argv[2] if len(sys.argv) > 2 else ''

    parser = PCAPParserApp()

    print("[*] Processing TLS Application Data...")
    parser.process_tls_appdata(pcap_file, display_filter)

    print("[*] Processing TLS Cipher Suites...")
    parser.process_ciphersuites(pcap_file, display_filter)

    print("[*] Processing TLS Certificates...")
    parser.process_certificates(pcap_file, display_filter)

    print("[*] Processing ESP Data...")
    parser.process_esp_data(pcap_file, display_filter)

    print("\n=== Encrypted Data ===")
    for idx, entry in enumerate(parser.encrypted_data, 1):
        if entry['proto'] == 'TLS':
            print(f"TLS#{idx}: {entry['src_ip']}:{entry['sport']} -> {entry['dst_ip']}:{entry['dport']}, Version: {entry['version']}, Length: {len(entry['data'])} bytes")
        elif entry['proto'] == 'ESP':
            print(f"ESP#{idx}: SPI=0x{entry['spi']:08x}, Seq={entry['seq']}, {entry['src_ip']} -> {entry['dst_ip']}, Length: {len(entry['data'])} bytes")

    print("\n=== Cipher Suites ===")
    for src_ip, dst_ip, cs in parser.cipher_suite_info:
        cs_name = cipher_suite_mapping.get(cs[2:], "Unknown")
        print(f"{src_ip} -> {dst_ip}: {cs} ({cs_name})")

    print("\n=== Certificates ===")
    for cert in parser.certificates:
        print(f"{cert['ip_pair']} | SigAlg: {cert['sig_alg']} | Hash: {cert['cert_hash']}")

if __name__ == "__main__":
    main()
