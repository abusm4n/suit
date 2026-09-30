import pyshark

def extract_sni_from_tls(pcap_file):
    capture = pyshark.FileCapture(pcap_file, display_filter="ssl.handshake.extensions_server_name")
    sni_set = set()
    for pkt in capture:
        try:
            sni = pkt.ssl.handshake_extensions_server_name
            sni_set.add(sni)
        except AttributeError:
            continue
    return sni_set

snis = extract_sni_from_tls("/home/ab/update_traffic/update_keywords/dataset/iot-data/uk/allure-speaker/android_lan_audio_off/2019-05-04_19:52:11.65s.pcap")

print("Possible Applications (SNI):")
for s in snis:
    print(s)



   