# Earlier versions (not used by the current paper)

This folder keeps the code, figures and intermediate data of earlier versions of this
study, for reference. The current paper does not use any of it; its pipeline is in
`src/` and its data in `data/`.

| Folder | Contents |
|---|---|
| `src/` | extraction (`extract_*.py`, `protocol_extraction.py`), per-device entropy (`compute_entropy.py`, `*_average_entropy.py`, `entropy.sh`), hand-written cipher-suite classes (`ciphersuite.py`), CVE and CWE analysis (`base_year.py`, `cwe_freqency.py`, `impact_exploitability_severity.py`, `visualize_cwe.py`), plots |
| `src/retrospective/` | processing and heatmaps for the 2019 traces |
| `src/experiments/entropy_comparison.py` | entropy comparison between the two datasets |
| `scripts/` | certificate extraction, key-strength analysis and plots |
| `figures/`, `cve/`, `csv/` | figures, CVE records and CVE statistics of those versions |
| `data/controlled/` | per-device entropy and stream-size tables of the lab captures |
| `intl-iot/` | copy of the Mon(IoT)r analysis code ([NEU-SNS/intl-iot](https://github.com/NEU-SNS/intl-iot), see its `LICENSE.md`), called by `src/entropy.sh` |
| `explore_data.sh`, `requirements.txt` | data overview and the Python packages these scripts need |

## Why the current paper does not use these methods

- **Keyword selection of update traffic.** A capture counted as update-related if
  `update`, `firmware`, `software` or `download` occurred anywhere in its tshark
  dissection. Most such matches are protocol vocabulary, such as Wireshark's TCP
  window-update annotation or the STUN SOFTWARE attribute. The current pipeline identifies
  update traffic by confirmed update servers instead (`src/update_attribution/`).
- **Entropy as an encryption test.** Per-device averages were compared with a 0.8
  threshold. High entropy cannot separate encryption from compression. In addition,
  `src/encrypted_average_entropy.py` does not filter on the data type, so its
  "encrypted" and "unencrypted" averages are computed over the same packets.
- **Cipher suites.** The hand-written classes in `src/ciphersuite.py` put ECDHE-CBC suites
  under "recommended", TLS 1.3 suites under "secure" and the renegotiation signaling value
  `0x00FF` under "insecure". They were also applied to the suites devices offer rather
  than to those servers negotiate. The current pipeline uses a dated ciphersuite.info
  snapshot and negotiated suites.
- **Certificates.** The statistics covered every certificate in a capture: CA
  certificates, the cameras' own local TLS servers and update servers alike. The current
  pipeline analyzes only the leaf certificates of update servers.
- **CVE matching.** CVEs were matched to cipher names by keyword, which yields false
  positives and negatives. The current paper maps each observed weakness to its weakness
  class and a representative CVE by hand.

Most scripts use absolute paths of the original working copy (`~/update_traffic/...`), so
they do not run unchanged from this location.
