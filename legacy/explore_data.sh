#!/bin/bash
# Data Exploration Script for IoT Update Traffic Analysis
# No dependencies required - uses standard Unix tools

echo ""
echo "█████████████████████████████████████████████████████████████████████"
echo "   IoT UPDATE TRAFFIC - DATA EXPLORATION"
echo "█████████████████████████████████████████████████████████████████████"

BASE_DIR="$HOME/update_traffic"

echo ""
echo "=========================================================================="
echo "ENTROPY DATA EXPLORATION"
echo "=========================================================================="
echo ""

ENTROPY_DIR="$BASE_DIR/controlled/entropy"
echo "Entropy CSV files in: $ENTROPY_DIR"
echo ""

find "$ENTROPY_DIR" -name "*.csv" -type f | while read file; do
    filename=$(basename "$file")
    lines=$(wc -l < "$file")
    size=$(du -h "$file" | awk '{print $1}')
    echo "  📄 $filename"
    echo "     Lines: $lines | Size: $size"
    echo "     Header: $(head -1 "$file" | cut -c1-80)"
    echo ""
done

echo ""
echo "=========================================================================="
echo "STREAM SIZE DATA EXPLORATION"
echo "=========================================================================="
echo ""

STREAM_DIR="$BASE_DIR/controlled/stream"
echo "Stream size CSV files in: $STREAM_DIR"
echo ""

find "$STREAM_DIR" -name "*.csv" -type f | while read file; do
    filename=$(basename "$file")
    lines=$(wc -l < "$file")
    size=$(du -h "$file" | awk '{print $1}')
    echo "  📄 $filename"
    echo "     Streams: $((lines - 1)) | Size: $size"
done

echo ""
echo ""
echo "=========================================================================="
echo "RAW DATASET EXPLORATION"
echo "=========================================================================="
echo ""

DATASET_DIR="$BASE_DIR/controlled/dataset"
echo "Device datasets in: $DATASET_DIR"
echo ""

for device_dir in $(ls -d "$DATASET_DIR"/*/ 2>/dev/null | xargs -n1 basename | sort); do
    device_path="$DATASET_DIR/$device_dir"
    pcap_count=$(find "$device_path" -name "*.pcap*" 2>/dev/null | wc -l)
    total_size=$(du -sh "$device_path" 2>/dev/null | awk '{print $1}')
    echo "  📁 $device_dir"
    echo "     PCAP files: $pcap_count | Total size: $total_size"
done

echo ""
echo ""
echo "=========================================================================="
echo "CVE DATA EXPLORATION"
echo "=========================================================================="
echo ""

CVE_DIR="$BASE_DIR/cve"
echo "CVE data in: $CVE_DIR"
echo ""

for folder in $(ls -d "$CVE_DIR"/*/ 2>/dev/null | xargs -n1 basename); do
    folder_path="$CVE_DIR/$folder"
    file_count=$(find "$folder_path" -type f 2>/dev/null | wc -l)
    echo "  📁 $folder/"
    echo "     Files: $file_count"
done

CSV_FILE="$BASE_DIR/csv/all_base.csv"
if [ -f "$CSV_FILE" ]; then
    echo ""
    echo "  📄 all_base.csv"
    lines=$(wc -l < "$CSV_FILE")
    size=$(du -h "$CSV_FILE" | awk '{print $1}')
    echo "     CVE entries: $((lines - 1)) | Size: $size"
    echo "     Header: $(head -1 "$CSV_FILE" | cut -c1-80)"
fi

echo ""
echo ""
echo "=========================================================================="
echo "FIRMWARE EXPLORATION"
echo "=========================================================================="
echo ""

FIRMWARE_DIR="$BASE_DIR/controlled/firmware"
echo "Firmware in: $FIRMWARE_DIR"
echo ""

for fw_dir in $(ls -d "$FIRMWARE_DIR"/*/ 2>/dev/null | xargs -n1 basename | sort); do
    fw_path="$FIRMWARE_DIR/$fw_dir"
    file_count=$(find "$fw_path" -type f 2>/dev/null | wc -l)
    total_size=$(du -sh "$fw_path" 2>/dev/null | awk '{print $1}')
    echo "  📁 $fw_dir"
    echo "     Files: $file_count | Size: $total_size"
done

echo ""
echo ""
echo "=========================================================================="
echo "SUMMARY"
echo "=========================================================================="
echo ""

echo "📊 Entropy packets by device:"
for device_csv in "$ENTROPY_DIR"/*.csv; do
    filename=$(basename "$device_csv")
    device_name=${filename%.*}
    lines=$(wc -l < "$device_csv")
    packets=$((lines - 1))
    printf "   %-15s %6d packets\n" "$device_name:" "$packets"
done

echo ""
echo "✅ Setup Complete!"
echo ""
echo "Next steps:"
echo "  1. Set up Python environment:"
echo "     python3 -m venv venv"
echo "     source venv/bin/activate"
echo "     pip install pandas seaborn matplotlib scikit-learn scipy"
echo ""
echo "  2. Run Experiment 1 (Entropy Comparison):"
echo "     jupyter notebook analysis_output/Experiment_1_Entropy_Comparison.ipynb"
echo "     OR"
echo "     python3 src/experiments/entropy_comparison.py"
echo ""
echo "  3. Review documentation:"
echo "     cat PROJECT_ANALYSIS.md        (Full project analysis)"
echo "     cat IMPLEMENTATION_SUMMARY.md  (What's been set up)"
echo "     cat GETTING_STARTED.md         (Setup guide)"
echo ""
echo "=========================================================================="
