# SUIT — Security of Update-related IoT Traffic

This repository contains the artifact, data, and technical report accompanying the paper:

> **SUIT: Security of Update-related IoT Traffic**
<!-- > Ahmad B. Usman¹, Emre Süren², Mikael Asplund¹
> ¹ Linköping University, Sweden · ² KTH Royal Institute of Technology, Sweden  -->

A multidimensional, network-level analysis of how smart-home IoT devices receive
software updates, combining entropy-based encryption characterization, cipher-suite
evaluation, certificate security assessment, and vulnerability analysis.

---

## Overview

Software updates are essential for keeping IoT devices secure, yet the network-level
behavior and security of update *delivery* remain underexplored. We study the update
channel itself across two complementary datasets:

- **Controlled experiments** - 10 heterogeneous devices (streaming devices, smart
  assistants, network cameras) updated in a lab, with traffic captured via a
  Raspberry Pi 4 bridged access point (Wireshark / `tcpdump`).
- **Retrospective analysis** - the Mon(IoT)r testbed (81 devices, 26 models, 34,586
  experiments), used to assess generalizability at scale.

### Research questions

| RQ  | Focus |
|-----|-------|
| RQ1 | Update process characteristics - protocols, providers, server geography |
| RQ2 | Channel trustworthiness - authenticity, confidentiality (entropy), cryptographic strength (cipher-suites & certificates) |
| RQ3 | Vulnerability implications - mapping weak/insecure configurations to public CVE/CWE records |

### Key findings

See the paper and the technical report for full results and figures.

---

## Repository layout

```
.
├── src/                 # Analysis pipeline: entropy, cipher-suites, TLS/cert extraction, plots
│   ├── experiments/     # Entropy comparison experiments
│   └── retrospecitve/   # Retrospective (Mon(IoT)r) processing
├── scripts/             # Certificate strength analysis & visualization scripts
├── csv/                 # Aggregated result tables
├── cve/                 # CVE/CWE mapping data for RQ3
├── figures/             # Generated figures
├── reproducibility/     # Reproducibility helpers
├── technical_report/    # technical_report.pdf (full results)
├── explore_data.sh      # Quick data overview
├── requirements.txt     # Python dependencies
└── intl-iot/            # Mon(IoT)r tooling (git submodule)
```

> **Note.** Large/local data and the paper source are intentionally not tracked
> (see `.gitignore`): `controlled/`, `retrospective/`, `dataset/`, `latex/`, `doc/`,

---

## Getting started

```bash
# 1. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Initialize the Mon(IoT)r submodule (retrospective tooling)
git submodule update --init --recursive

# 4. Quick look at available data
./explore_data.sh
```

### Entropy metrics

Three metrics are computed over byte distributions of update-related payloads:
**Shannon**, **Rényi** (α = 2), and **Tsallis**. A normalized Shannon value
≥ 0.80 is used as an indicator of likely encryption.

### Certificate strength

Certificates are graded by NIST SP 800-57 security strength: RSA-1024 → ≤80-bit,
RSA-2048 → 112-bit, RSA-3072+/EC P-256+ → ≥128-bit.

---





## Contact

