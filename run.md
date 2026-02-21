
##  Arbitrary notes,




## ntopng
## High-Speed Web-based Traffic Analysis and Flow Collection
http://192.168.0.25:3000/


## Reducing the size of the actual dataset, this is not neceesary.

src/keyword_occurance.py ~/update_traffic/dataset/ ~/update_traffic/dataset/update_related_pcaps.csv
For extracting update-related network traffics.
Found 6,315 network traffic, this took  4:02:53 hours.

This script processed the 34,586 pcaps files, reduce it to 6,315









## Exracting encrypted and unecrypted packets from the dataset 


python3 src/extract_http.py ~/update_traffic/dataset/ ~/update_traffic/extracted/foldername
For extracting http traffics from pcap files
# adapt for tls, which is encrypted

# or foll as below
python3 src/extract_all.py ~/update_traffic/imc19_dataset/ ~/update_traffic/dataset/extracted_all/





python3 src/analysis.py  ~/update_traffic/extracted/
For analzying extracted pcap









## Checking and printing out the resuls from extractd keywords of update-related

python3 src/check_true_updates.py ~/update_traffic/extracted_iot-data/




python3 src/generatecharts.py  ~/update_traffic/tls_iot-data/  ~/update_traffic/output/








#####
Entropy
####




./intl-iot/encryption/encryption.sh  ~/update_traffic/update_keywords/dataset/iot-data/uk/allure-speaker/android_lan_audio_off/2019-05-04_19:52:11.65s.pcap ~/update_traffic/update_keywords/dataset/sample.csv ~/update_traffic/update_keywords/dataset/sample.json


 ./intl-iot/encryption/encryption.sh ~/update_traffic/controlled/dataset/eufy/eufy.pcapng ~/update_traffic/controlled/entropy/eufy.c
sv ~/update_traffic/controlled/entropy/eufy.json


./intl-iot/encryption/encryption.sh ~/update_traffic/controlled/dataset/dlink/dlink.pcapng ~/update_traffic/controlled/entropy/dlink.csv ~/update_traffic/controlled/entropy/dlink.json


####
or just run ./src/entropy.sh and modify the the file according to the desire file







####
https://ciphersuite.info/



Cipher suies and certificate: Examples
python3 src/ciphersuite.py /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/allure-speaker/2019-04-26_14\:06\:00.202s.json 
Cipher suite category counts:
  Secure: 70
  Recommended: 42
  Weak: 56
  Insecure: 7
  Unknown: 130

  ## for neested folders

  python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/uk/appletv/

Summary of categories (unique cipher suites):
  Secure: 9
  Recommended: 6
  Weak: 11
  Insecure: 1
  Unknown: 0





  python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/uk/roku-tv/

Summary of categories (unique cipher suites):
  Secure: 6
  Recommended: 6
  Weak: 66
  Insecure: 6
  Unknown: 0




python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/uk/echodot/

Summary of categories (unique cipher suites):
  Secure: 8
  Recommended: 6
  Weak: 52
  Insecure: 1
  Unknown: 0



python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/uk/samsungtv-wired/

Summary of categories (unique cipher suites):
  Secure: 8
  Recommended: 6
  Weak: 56
  Insecure: 7
  Unknown: 0

  Processing /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/samsungtv-wired/2019-04-26_13:44:15.226s.json...

Summary of categories (occurrences):
  Secure: 3387
  Recommended: 2922
  Weak: 27291
  Insecure: 505
  Unknown: 0

Summary of categories (unique cipher suites):
  Secure: 6
  Recommended: 6
  Weak: 56
  Insecure: 7
  Unknown: 0




python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/us/echoplus/

Summary of categories (unique cipher suites):
  Secure: 6
  Recommended: 6
  Weak: 67
  Insecure: 4
  Unknown: 0






python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/uk-vpn/honeywell-thermostat/
Summary of categories (occurrences):
  Secure: 10
  Recommended: 26
  Weak: 52
  Insecure: 0
  Unknown: 0

Summary of categories (unique cipher suites):
  Secure: 2
  Recommended: 6
  Weak: 13
  Insecure: 0
  Unknown: 0



python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/us/amcrest-cam-wired/


Summary of categories (occurrences):
  Secure: 28
  Recommended: 24
  Weak: 184
  Insecure: 4
  Unknown: 4

Summary of categories (unique cipher suites):
  Secure: 6
  Recommended: 6
  Weak: 46
  Insecure: 1
  Unknown: 1













python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/us/dlink-mov/


Summary of categories (occurrences):
  Secure: 63
  Recommended: 54
  Weak: 333
  Insecure: 63
  Unknown: 126

Summary of categories (unique cipher suites):
  Secure: 6
  Recommended: 6
  Weak: 37
  Insecure: 7
  Unknown: 14







python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/us/lgtv-wired/

Summary of categories (occurrences):
  Secure: 318
  Recommended: 252
  Weak: 2457
  Insecure: 165
  Unknown: 0

Summary of categories (unique cipher suites):
  Secure: 6
  Recommended: 6
  Weak: 67
  Insecure: 12
  Unknown: 0





python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/uk/t-wemo-plug/
Summary of categories (occurrences):
  Secure: 0
  Recommended: 0
  Weak: 1196
  Insecure: 92
  Unknown: 0

Summary of categories (unique cipher suites):
  Secure: 0
  Recommended: 0
  Weak: 12
  Insecure: 1
  Unknown: 0


"cweId": "CWE-310",
"cweId": "NVD-CWE-noinfo"






python3 src/ciphersuite_nested_folder.py /home/ab/update_traffic/dataset/entropy/iot-data/uk/allure-speaker/


  Summary of categories (occurrences):
  Secure: 346
  Recommended: 186
  Weak: 642
  Insecure: 31
  Unknown: 0

Summary of categories (unique cipher suites):
  Secure: 13
  Recommended: 6
  Weak: 42
  Insecure: 1
  Unknown: 0










## Extracting all the protocols from pcap
 
tshark -r ./controlled/dataset/tapo/tapo.pcapng -q -z io,phs

## With certain protocol
tshark -r ./controlled/dataset/tapo/tapo.pcapng -Y "ip.addr == 10.42.0.173" -T fields -e frame.protocols     | tr ':' '\n' | sort -u
tshark -r ./controlled/dataset/eufy/eufy.pcapng -Y "ip.addr == 10.42.0.160" -T fields -e frame.protocols     | tr ':' '\n' | sort -u
tshark -r ./controlled/dataset/eufy/eufi_full_updated.pcapng -T fields -e frame.protocols  | tr ':' '\n' | sort -u
tshark -r ./controlled/dataset/xiaomi/xiaomi.pcapng -Y "ip.addr == 10.42.0.207" -T fields -e frame.protocols     | tr ':' '\n' | sort -u






## Extract tls_
tshark -r ./controlled/dataset/xiaomi/xiaomi.pcapng -Y "ip.addr == 10.42.0.207"  -T fields -e tls.record.version | sort -u



tshark -r ./controlled/dataset/xiaomi/xiaomi.pcapng -Y "ip.addr == 10.42.0.207"     -T fields -e _ws.col.Protocol | sort -u

 tshark -r ./controlled/dataset/tapo/tapo.pcapng -Y "ip.addr == 10.42.0.173"     -T fields -e _ws.col.Protocol | sort -u
tshark -r ./controlled/dataset/eufy/eufy.pcapng -Y "ip.addr == 10.42.0.160"     -T fields -e _ws.col.Protocol | sort -u
tshark -r ./controlled/dataset/dlink/dlink.pcapng -Y "ip.addr == 10.42.0.152"     -T fields -e _ws.col.Protocol | sort -u
 tshark -r ./controlled/dataset/sony_tv/sony_tv.pcapng -Y "ip.addr == 10.42.0.157"     -T fields -e _ws.col.Protocol | sort -u



 ### extracting http files larger than 4 megabytes
  tshark -r ./controlled/dataset/tapo/tapo.pcapng -Y "http.content_length > 4000000"     -T fields -e http.content_length -e http.request.full_uri


### extracting file size, this works well
  tshark -r ./controlled/dataset/xiaomi/xiaomi.pcapng -Y "tcp && ip.addr == 10.42.0.207"     -T fields -e tcp.stream -e frame.len     | awk '{bytes[$1]+=$2} END {for(s in bytes) print "Stream", s, ":", bytes[s],"bytes"}'
  
