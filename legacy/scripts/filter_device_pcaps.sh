#!/bin/bash
# Filter each device pcapng to only traffic involving the device's IP.
# Output: controlled/dataset/{device}/{device}_filtered.pcapng

set -e

DATASET="/home/ab/update_traffic/controlled/dataset"

declare -A DEVICES=(
    ["apple-tv/apple-tv.pcapng"]="10.42.0.25"
    ["dlink/dlink.pcapng"]="10.42.0.152"
    ["eufy/eufy.pcapng"]="10.42.0.160"
    ["fire-tv/fire-tv.pcapng"]="10.42.0.23"
    ["homepod/homepod.pcapng"]="10.42.0.79"
    ["riolink/riolink.pcapng"]="10.42.0.170"
    ["sony-tv/sony_tv.pcapng"]="10.42.0.157"
    ["tapo-c100/tapo-c100.pcapng"]="10.42.0.135"
    ["tapo-c200/tapo-c200.pcapng"]="10.42.0.173"
    ["xiaomi/xiaomi.pcapng"]="10.42.0.207"
)

for RELPATH in "${!DEVICES[@]}"; do
    IP="${DEVICES[$RELPATH]}"
    INPUT="${DATASET}/${RELPATH}"
    DIR=$(dirname "$INPUT")
    BASENAME=$(basename "$INPUT" .pcapng)
    OUTPUT="${DIR}/${BASENAME}_filtered.pcapng"

    if [[ ! -f "$INPUT" ]]; then
        echo "[SKIP] Not found: $INPUT"
        continue
    fi

    echo "[FILTER] $(basename $DIR) (${IP}) -> $(basename $OUTPUT)"
    tshark -r "$INPUT" -Y "ip.addr == ${IP}" -w "$OUTPUT" 2>/dev/null
    FRAMES=$(tshark -r "$OUTPUT" 2>/dev/null | wc -l)
    echo "         Wrote ${FRAMES} frames to $OUTPUT"
done

echo ""
echo "Done. Filtered pcapng files written alongside originals."
