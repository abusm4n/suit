# IoT Update Traffic Analysis - REVISED Project Analysis

## Research Paper Overview

**Title**: Update Traffic Analysis

**Objective**: Network-level analysis of IoT device update behavior to investigate patterns, encryption mechanisms, cipher-suite strength, and security implications.

**Key Research Questions**:
- **RQ1**: What are the patterns and frequency of IoT device software/firmware updates?
- **RQ2**: How trustworthy is the encryption applied to update-related traffic?
- **RQ3**: What are the security implications when vendors fail best cryptographic practices?
- **RQ4**: From which countries do IoT devices receive software updates?

---

## Current Project Status

### ✅ Completed Research
The paper present findings from:
- **10 controlled devices**: D-Link camera, Apple TV, D-Link, Eufy, Fire Stick, HomePod, Riolink, Sony TV, Tapo (C100 & C200), Xiaomi
- **34,586 experiments** captured in controlled lab setting (Mon(IoT)r testbed)
- **Retrospective analysis** on 81 devices, 26 models across US/UK
- **Traffic analysis framework** with entropy metrics and vulnerability mapping

### 📊 Available Data in Repository

**Entropy Analysis Results** (`controlled/entropy/`):
- Shannon, Rényi, Tsallis entropy metrics computed
- Both raw and formatted CSV outputs
- Device-specific entropy profiles (dlink, eufy, sony_tv, tapo, xiaomi)
- **Finding**: Entropy lower than expected for robust encryption; heterogeneous across devices

**Cipher Suite Analysis** (`src/ciphersuite.py`):
- Classified into: Secure, Recommended, Weak, Insecure, Unknown
- **Key Findings**:
  - Overall: 114,106 Secure | 53,572 Recommended | **244,675 Weak** | 34,714 Insecure | 5,955 Unknown
   - Weak/insecure suites are highly prevalent in **ClientHello offers**
   - Negotiated **ServerHello** suites are mostly Secure/Recommended, with non-zero weak/insecure negotiated cases on specific devices
  - Only single-digit to low-double-digit secure occurrences per device
   - See `retrospective/analysis_output/tls_feedback2_overall_summary.csv` and `retrospective/analysis_output/tls_feedback2_device_breakdown.csv`

**Stream Size Data** (`controlled/stream/`):
- TCP stream byte counts per device
- Flow-level traffic characteristics
- 5 device types analyzed

**Vulnerability Data** (`cve/`, `csv/all_base.csv`):
- 92 CVEs linked to weak/insecure cipher usage
- CVSS scores averaging 6.1 (range 2.6-9.8)
- Top CWEs: CWE-327 (broken crypto), CWE-310 (crypto issues), CWE-326 (inadequate encryption), CWE-295 (improper cert validation), CWE-757 (less-secure negotiation)
- **Trend**: Severity **increasing over past 5 years**

---

## Key Findings from Paper (to be Verified/Extended)

### Finding 1: High Proportion of Plaintext
- **~38% of identified update sessions** carried over plaintext channels
- **60.1% of flagged sessions** have unknown encryption status
- Need: Improved update detection heuristics

### Finding 2: Offer-vs-Negotiation Cipher Gap
- Weak/insecure suites far outnumber secure ones in **ClientHello offered lists**
- Negotiated (`ServerHello`) suites are mostly secure/recommended overall, but weak/insecure negotiated selections still occur for some devices
- Device heterogeneity: some devices (Roku TV, hub) show high weak counts; plugs/speakers show fewer
- Inconsistent security posture among vendors

### Finding 3: Entropy Profiles Are Informative
- **Per-device baselines matter** - entropy varies significantly by device
- **Tsallis entropy** produces highest values, most robust discriminator of encrypted payloads
- **Shannon & Rényi** provide complementary sensitivity
- Can be used for passive monitoring to flag suspicious sessions

### Finding 4: Vulnerability Progression
- Confidentiality most highly affected (impacted by weak ciphers)
- Network-based attack vectors dominate
- CVSS trend shows **increasing severity** in recent years
- Adversary capabilities: MITM attacks, brute-force, information theft, full system control

Methodological note:
`ClientHello` suites indicate capabilities/offers; security posture claims should be based primarily on negotiated `ServerHello` version and selected ciphersuite.

---

## Proposed Experiments (Revised Based on Paper)

### 🔴 **Experiment 1: Entropy Profile Baselines & Anomaly Detection**
**Goal**: Establish per-device entropy baselines and identify anomalous traffic

**Current State**: Entropy data computed but not analyzed for baselines

**Implementation**:
```python
For each device:
1. Load all entropy samples (Shannon, Rényi, Tsallis)
2. Compute baseline statistics (mean, std, 5th/95th percentiles)
3. Identify which metric is most discriminative per device
4. Flag sessions >2σ from mean as potential anomalies
5. Validate anomalies against cipher suite analysis
Output: Per-device baselines.csv, anomaly_reports/, entropy_profiles.pdf
```

**Scientific Value**: Tests Finding 3 (entropy baselines for monitoring)

---

### 🔴 **Experiment 2: Cipher Suite Prevalence & Security Posture Ranking**
**Goal**: Quantify weak vs secure cipher prevalence per device and rank devices by security

**Current State**: Classification done but not aggregated/compared

**Implementation**:
```python
1. Parse all PCAP files or use existing cipher counts
2. For each device:
   - Count: Secure, Recommended, Weak, Insecure, Unknown
   - Calculate percentages and ratios
   - Compute "Security Score" = (S + R/2) / (W + I)
3. Rank devices by security score
4. Analyze correlations:
   - Brand vs security
   - Device category vs security
   - Update frequency vs security
5. Statistical testing (ANOVA on security scores)
Output: device_security_rankings.csv, security_vs_device_category.pdf
```

**Scientific Value**: Tests Finding 2 (device heterogeneity in cipher suites)

**Corresponding Paper Section**: Section 4.4 (Ciphersuite Evaluation)

---

### 🟡 **Experiment 3: Encrypted vs Plaintext Update Coverage**
**Goal**: Measure what proportion of devices use plaintext for updates

**Current State**: Individual entropy files exist; 38% plaintext finding needs verification

**Implementation**:
```python
1. Classify each session as encrypted/plaintext/unknown
   - Encrypted: TLS/HTTPS traffic OR high entropy
   - Plaintext: HTTP traffic OR low entropy
   - Unknown: unclear classification
2. Calculate per-device encryption coverage %
3. Breakdown by PCAP source (controlled experiments, retrospective)
4. Compare: Secure ciphers vs weak/insecure ciphers
5. Output: encryption_coverage.csv with false positive/negative estimates
```

**Scientific Value**: Verifies/validates Finding 1 (38% plaintext claim)

**Challenges**: 60.1% unknown status - requires heuristics

---

### 🟡 **Experiment 4: CVE-to-Cipher Mapping & Vulnerability Timeline**
**Goal**: Link recorded cipher suites to known CVEs and show vulnerability trends

**Current State**: CVE data exists; mapping done conceptually but not validated

**Implementation**:
```python
1. Load all_base.csv with CVE data
2. For each device's cipher suite list:
   - Map to vulnerable ciphers (from NVD/ciphersuite.py)
   - Find matching CVEs
3. Extract CVSS scores, CWE, publication dates
4. Group by device, cipher strength class
5. Trend analysis: CVSS over time (validate increasing severity)
6. Attack vector analysis: Count network vs local vs physical
Output: cve_cipher_mapping.csv, vulnerability_trends.pdf, impact_breakdown.pdf
```

**Scientific Value**: Validates Finding 4 (CVSS trend increasing over 5 years)

**Corresponding Paper Section**: Section 4.5 (Vulnerability Implications)

---

### 🟢 **Experiment 5: Update Detection Heuristics Evaluation**
**Goal**: Improve update-session identification beyond keyword filtering

**Current State**: Keywords used (software, firmware, update, download) but 60.1% remain unknown

**Implementation**:
```python
1. Current method: keyword filtering in packet content
2. Proposed multi-signal approach:
   - Timing patterns (update ceremonies have characteristic durations)
   - Known update servers/domains (maintain database)
   - Flow sequences (connect → download → verify pattern)
   - Session correlation (paired up/download flows)
   - Packet size distributions (firmware > metadata)
3. Train classifier on manually labeled ground truth
4. Compare precision/recall vs pure keyword method
5. Cross-validate on devices with ground truth (Apple TV, Riolink)
Output: update_detection_metrics.csv, heuristic_comparison.pdf, classifier_model.pkl
```

**Scientific Value**: Addresses limitation about update detection false positives/negatives

**Challenges**: Requires manual labeling or instrumented devices

---

### 🟢 **Experiment 6: Geographic & Regional Analysis (RQ4)**
**Goal**: Answer RQ4 - from which countries do IoT devices fetch updates?

**Current State**: Data has UK/US variants; international analysis incomplete

**Implementation**:
```python
1. Use imc19_dataset directories (uk/, us/, uk-vpn/, us-vpn/)
2. Extract update destination IPs
3. Geolocate using MaxMind GeoLite2 or WHOIS
4. Identify update servers by country/AS
5. Analyze: regional differences in cipher strength, CVSS scores
6. VPN impact: Compare encryption quality uk vs uk-vpn, us vs us-vpn
7. Device behavior differences across regions
Output: update_servers_by_region.csv, regional_security_comparison.pdf, vpn_impact_analysis.pdf
```

**Scientific Value**: Fully answers RQ4 (geographic distribution)

**Related**: intl-iot/destination/analyze.py has geographic analysis framework

---

### 🟢 **Experiment 7: Device Category Security Analysis**
**Goal**: Rank device categories (camera, speaker, TV, lock) by update security

**Current State**: 10 devices studied; category-level patterns emerging but not formalized

**Implementation**:
```python
1. Categorize devices: Cameras (D-Link, Tapo, Riolink), Speakers (HomePod, Eufy), TV (Sony, Roku, Apple TV), Lock (Danalock), Plug (Smart Plug), etc.
2. For each category:
   - Aggregate cipher suite distributions
   - Average entropy profiles
   - Vulnerability exposure (# of CVEs, avg CVSS)
   - Plaintext usage rate
3. Statistical testing: Is security significantly different between categories?
4. Visualization: Category-level security scorecards
Output: device_category_analysis.csv, category_security_scorecard.pdf
```

**Scientific Value**: Identifies which device types are most/least secure

---

### 🟠 **Experiment 8: Instrumented Device Validation** (MORE INVOLVED)
**Goal**: Validate entropy thresholds and cipher negotiation in practice

**Current State**: Paper mentions this as future work; requires laboratory access

**Implementation**:
```python
Requires controlled lab setup:
1. Pick 2-3 devices to instrument (e.g., Tapo camera)
2. Set up MitM proxy to:
   - Log real TLS handshake offers/accepts
   - Monitor cipher negotiations with server
   - Capture update artifact (firmware binary)
   - Verify signature validation on-device
3. Run update 5-10x, log network traffic + on-device logs
4. Analyze:
   - Do weak cipher offers actually get negotiated?
   - What ciphers does device prefer vs server preference?
   - Does bad signature validation occur?
5. Validate entropy-based detection accuracy
Output: cipher_negotiation_analysis.csv, update_ceremony_logs/, findings_validation.md
```

**Challenge**: Requires lab access, MitM capability, device rooting/logging

---

## Recommended Implementation Roadmap

**Priority Order** (based on paper gaps & data availability):

1. **Experiment 1** (Easy, High Value) ✅ READY
   - Validate entropy findings (Finding 3)
   - Establish monitoring baselines
   - ~2 hours

2. **Experiment 2** (Easy, High Value)
   - Quantify cipher suite dominance (Finding 2)
   - Device security rankings
   - Directly answers RQ2
   - ~3 hours

3. **Experiment 3** (Medium)
   - Verify plaintext claim (Finding 1)
   - Classification heuristics
   - ~4 hours

4. **Experiment 4** (Medium)
   - Validate CVSS trend (Finding 4)
   - CVE mapping
   - ~5 hours

5. **Experiment 6** (Medium)
   - Answer RQ4 (geographic)
   - Regional analysis
   - ~4 hours

6. **Experiment 7** (Easy)
   - Device category analysis
   - Security scorecards
   - ~3 hours

7. **Experiment 5** (Hard)
   - Improve heuristics
   - ML-based detection
   - ~8 hours

8. **Experiment 8** (Very Hard)
   - Validation experiments
   - Requires lab setup
   - ~20 hours

---

## Alignment with Paper

| Paper Finding | Experiment | Validation |
|---|---|---|
| Finding 1: 38% plaintext | Exp 3 | Classification & coverage analysis |
| Finding 2: Weak dominance | Exp 2 | Cipher distribution & device ranking |
| Finding 3: Entropy baselines | Exp 1 | Per-device profiles & anomaly detection |
| Finding 4: CVSS trend | Exp 4 | CVE timeline & severity analysis |
| RQ1: Update patterns | Exp 5 | Improved detection heuristics |
| RQ2: Encryption trustworthiness | Exp 2, 4 | Cipher strength + vulnerability mapping |
| RQ3: Security implications | Exp 4, 7 | CVE analysis + category comparison |
| RQ4: Geographic origin | Exp 6 | Regional & server analysis |

---

## Data Organization

```
analysis_output/
├── data/
│   ├── entropy_baselines.csv              # Exp 1
│   ├── device_security_rankings.csv       # Exp 2
│   ├── encryption_coverage.csv            # Exp 3
│   ├── cve_cipher_mapping.csv             # Exp 4
│   ├── update_detection_metrics.csv       # Exp 5
│   ├── update_servers_by_region.csv       # Exp 6
│   └── device_category_analysis.csv       # Exp 7
│
└── figures/
    ├── entropy_profiles.pdf               # Exp 1
    ├── security_vs_device_category.pdf    # Exp 2
    ├── encryption_coverage.pdf            # Exp 3
    ├── vulnerability_trends.pdf           # Exp 4
    ├── update_detection_comparison.pdf    # Exp 5
    ├── regional_security_comparison.pdf   # Exp 6
    └── category_security_scorecard.pdf    # Exp 7
```

---

## Limitations to Address

From paper (Section 5):

1. **Dataset scope**: Only 81 devices, 26 models (US/UK)
   - **Mitigation**: Acknowledge limitations, compare to other studies

2. **Update detection**: Keywords miss ~60% of sessions
   - **Mitigation**: Exp 5 (multi-signal heuristics)

3. **Unknown encryption**: 60.1% sessions unclassified
   - **Mitigation**: Develop better classification in Exp 3

4. **Controlled vs real-world**: Lab may not reflect production
   - **Mitigation**: Validate with Mon(IoT)r retrospective data

---

## Next Steps

1. ✅ Read my paper after Emre and Miakel feedback (completed)
2. ✅ Understand current data & findings (completed)
3. 📋 Implement Experiment 1 (entropy baselines)
4. 📋 Implement Experiment 2 (cipher suite analysis)
5. 📋 Implement Experiment 3 (encryption coverage)
6. 📋 Continue with Exp 4-7 based on priority

---

**Dataset**: 34,586 controlled experiments + retrospective analysis
**Devices**: 10 controlled + 81 in retrospective (26 models)
**Status**: Paper complete; experiments to validate/extend findings
