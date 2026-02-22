#!/bin/bash

#Usage: .src/entropy.sh 
#Usage: .src/entropy.sh [--skip-json]  if the the file is too large and you want to skip the json file generation, which can be time-consuming. The CSV file will still be generated as usual.]


# Parse command line arguments
if [[ $1 == "--skip-json" ]]; then
    skip_json=true
else
    skip_json=false
fi

#input_folder="${HOME}/update_traffic/controlled/dataset/apple-tv"  # Your device folder containing pcap files
#output_folder="${HOME}/update_traffic/controlled/entropy"         # Output folder



#input_folder="${HOME}/update_traffic/controlled/dataset/riolink"  # Your device folder containing pcap files
#output_folder="${HOME}/update_traffic/controlled/entropy"         # Output folder




#input_folder="${HOME}/update_traffic/controlled/dataset/homepod"  # Your device folder containing pcap files
#output_folder="${HOME}/update_traffic/controlled/entropy"         # Output folder





#input_folder="${HOME}/update_traffic/retrospective/selected/dlink-mov/data"  # Your device folder containing pcap files
#output_folder="${HOME}/update_traffic/retrospective/entropy"         # Output folder




input_folder="${HOME}/update_traffic/retrospective/imc19_dataset/iot-data/uk/t-philips-hub"  # Your device folder containing pcap files
output_folder="${HOME}/update_traffic/retrospective/entropy"         # Output folder




find "$input_folder" -type f \( -iname '*.pcap' -o -iname '*.pcapng' \) | while read -r pcapfile; do
  # Extract the device name from the input_folder basename
  device_name=$(basename "$input_folder")

  # Create output subfolder for the device
  device_output_folder="$output_folder/$device_name"
  mkdir -p "$device_output_folder"

  # Extract the base filename (strip the extension)
  base=$(basename "$pcapfile")
  base="${base%.*}"
  csvfile="$device_output_folder/${base}.csv"
  jsonfile="$device_output_folder/${base}.json"

  echo "Processing $pcapfile ..."
  
  if [[ $skip_json == true ]]; then
    # Skip JSON generation by using /dev/null directly
    ./intl-iot/encryption/encryption.sh "$pcapfile" "$csvfile" "/dev/null"
  else
    ./intl-iot/encryption/encryption.sh "$pcapfile" "$csvfile" "$jsonfile"
  fi
done
