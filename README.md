# Getting Started with IoT Update Traffic Analysis


For detailed experiment roadmap, see: **PROJECT_ANALYSIS_REVISED.md**

## Quick Setup

### Option 1: Using Python Virtual Environment (Recommended)

```bash
cd ~/update_traffic

# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# or on Windows:
# venv\Scripts\activate

# Install dependencies
pip install pandas seaborn matplotlib scikit-learn scipy numpy

# Run an experiment
python3 src/experiments/entropy_comparison.py
```

### Option 2: Using Conda

```bash
conda create -n iot-traffic python=3.10
conda activate iot-traffic
conda install pandas seaborn matplotlib scikit-learn scipy numpy
python3 src/experiments/entropy_comparison.py
```

---

## Available Experiments

### Experiment 1: Cross-Device Entropy Comparison ✓ READY
**File**: `src/experiments/entropy_comparison.py`
**Status**: Implemented and ready to run
**Outputs**:
- `analysis_output/data/entropy_statistics.csv` - Summary statistics
- `analysis_output/figures/entropy_boxplots.pdf` - Box plot comparison
- `analysis_output/figures/entropy_distributions.pdf` - Histogram distributions
- `analysis_output/figures/entropy_heatmap.pdf` - Heatmap of means
- `analysis_output/figures/entropy_violins.pdf` - Violin plots

**Run**:
```bash
python3 src/experiments/entropy_comparison.py
```

---

## Data Structure Overview

```
controlled/
├── dataset/          # Raw PCAP files (device traffic)
│   ├── apple-tv/
│   ├── dlink/
│   ├── eufy/
│   ├── fire_stick_tv/
│   ├── homepod/
│   ├── riolink/
│   ├── sony_tv/
│   ├── tapo_c100/
│   ├── tapo_c200/
│   └── xiaomi/
├── entropy/          # Entropy analysis results
│   ├── *_formatted.csv  # Processed entropy metrics
│   └── *.csv            # Raw entropy data
└── stream/           # TCP stream size analysis
    ├── dlink_stream_sizes.csv
    ├── eufy_stream_sizes.csv
    ├── sony_tv_stream_sizes.csv
    ├── tapo_stream_sizes.csv
    └── xiaomi_stream_sizes.csv

cve/                 # Vulnerability data
├── all/             # All CVEs
└── insecure/        # Filtered insecure CVEs

csv/
└── all_base.csv     # CVE base information
```

---

## Quick Data Exploration

### Entropy Data Sample
```python
import pandas as pd
import os

# Load entropy data
entropy_dir = os.path.expanduser("~/update_traffic/controlled/entropy")
df = pd.read_csv(f"{entropy_dir}/tapo.csv")

print(df.head())
print(df.describe())
```

### Stream Size Data Sample
```python
df_stream = pd.read_csv("~/update_traffic/controlled/stream/tapo_stream_sizes.csv")
print(df_stream.head())
```

### CVE Data Sample
```python
df_cve = pd.read_csv("~/update_traffic/csv/all_base.csv")
print(df_cve.head())
```

---

## Next Steps After Setup

1. **Run Experiment 1**: Generate cross-device entropy statistics
2. **Explore Results**: Review the CSV files and PDF plots
3. **Implement More Experiments**: Follow the proposed experiments in PROJECT_ANALYSIS.md

---

## Troubleshooting

### No virtual environment found
```bash
# Make sure you're in the project directory
cd ~/update_traffic
python3 -m venv venv
source venv/bin/activate
```

### Module not found errors
```bash
# Add current directory to Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Or install in editable mode
pip install -e .
```

### File not found errors
```bash
# Check that your working directory is correct
pwd  # should be /home/ab/update_traffic

# Check data exists
ls -la controlled/entropy/*.csv
```

---

## Project Structure

```
src/
├── experiments/              # NEW: Experiment scripts
│   └── entropy_comparison.py ✓
├── *.py                     # Original analysis scripts
├── run_all.sh
└── run_entropy.sh

analysis_output/             # NEW: Analysis results
├── data/                    # CSV files
├── figures/                 # PDF visualizations
└── notebooks/               # Jupyter notebooks (optional)

intl-iot/                    # Supporting code from IMC 2019
├── destination/
├── encryption/
├── model/
└── moniotr/
```

---

## Contact & References

- **Main Paper**: Update Traffic Analysis for IoT Devices
- **Supporting Work**: "Information Exposure From Consumer IoT Devices" (IMC 2019)
- **Lab**: MONIOTR Lab @ Northeastern University / Imperial College London

For more details, see `PROJECT_ANALYSIS.md` for proposed experiments and analysis roadmap.
