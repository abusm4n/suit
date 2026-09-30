# Over the Wire: IoT update delivery (artifact)

Code and data for the paper **"Over the Wire: A Network-Level Measurement of Consumer IoT
Update Delivery"** (under review; the authors are anonymized).

The paper studies how consumer IoT devices receive software updates over the network. It
analyzes the traffic of ten devices that we updated in our lab and a public dataset of IoT
traffic recorded in 2019 (the Mon(IoT)r traces, IMC 2019). It first separates update
traffic from everything else a device sends. It then examines each update channel
(protocol, TLS settings, server certificates and their revocation) together with the
protection inside the firmware image it delivers.

With this repository you can

1. **check every table and figure** from the derived data included here, in a few
   minutes and without the raw captures, and
2. **rerun the whole pipeline** from the raw captures, if you have them.

---

## Contents

- [Quick start](#quick-start)
- [What reproduces what](#what-reproduces-what)
- [Full reproduction from the raw captures](#full-reproduction-from-the-raw-captures)
- [Data](#data)
- [Repository layout](#repository-layout)
- [Method in brief](#method-in-brief)
- [Earlier versions](#earlier-versions)

---

## Quick start

No raw data is needed for these steps.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

make check      # shows what is installed and which raw data are present
make numbers    # prints the numbers behind Tables 1-6 and the key statements
make figures    # regenerates Figures 4-10 in latex/suit_acm_sigconf/fig/
make paper      # optional: builds the PDF
```

**Requirements:** Python 3.10 or newer, and a TeX installation with the `libertine`
package. The figure text is typeset in the paper's own fonts. `make paper` also needs
`latexmk` and `biber`.

We tested on Ubuntu 24.04 with Python 3.12, matplotlib 3.10, TeX Live 2023 and tshark 4.6.

---

## What reproduces what

All scripts are in `src/`; all outputs are in `data/derived/` unless noted.

| In the paper | Script | Output |
|---|---|---|
| Table 1: identifying update traffic | `update_attribution/controlled_attribution.py`, `update_attribution/retrospective_attribution.py` | `controlled/funnel.csv`, `retrospective/funnel.csv` |
| Table 2: cipher-suite categories | `update_attribution/ciphersuite_snapshot.py` | `data/reference/ciphersuite_info_2026-09-30.csv` |
| Table 3: how each device received its update | `update_attribution/controlled_attribution.py`, `image_protection/integrity_bitflip.py` | `controlled/flows.csv`, `tls_update.csv`, `leaf_certs.csv`; `image_protection/integrity_tiers.csv` |
| Table 4: update servers in the 2019 traces | `update_attribution/retrospective_attribution.py` | `retrospective/update_flows.csv`, `leaf_certs.csv` |
| Table 5: what unencrypted requests reveal | `update_attribution/exposure.py` | `*/exposure.csv` |
| Table 6: revocation checking | `update_attribution/revocation.py` | `*/revocation.csv` |
| Table 7: attack preconditions | written by hand from Tables 3-6 | – |
| Section 4.3: keyword-filter baseline | `update_attribution/keyword_baseline.py` | `retrospective/keyword_baseline.csv` |
| Section 5.2: local firmware push | `update_attribution/lan_push_check.py` | printed |
| Figures 4-10 | `update_attribution/figures.py` (reads `data/derived/`) | `latex/suit_acm_sigconf/fig/*.pdf` |
| Figure 3: analysis pipeline | TikZ code in `latex/suit_acm_sigconf/sec/3-methodology.tex` | – |
| Figures 1 and 2: setup and devices | drawing and photograph | `latex/suit_acm_sigconf/fig/` |

`make numbers` (`update_attribution/paper_numbers.py`) prints every table value and the
key numbers in the text straight from these files.

---

## Full reproduction from the raw captures

1. Get the raw data and put it where the table under [Data](#data) says.
2. Run `make derived`. It rebuilds everything in `data/derived/`. The tshark extractions
   are cached in `cache/`, so later runs take seconds.
3. Run `make lanpush numbers figures paper`.

`make help` lists the individual steps. Approximate first-run times on 12 cores:

| Step | Time |
|---|---|
| `make controlled` | 3 min |
| `make retrospective` | 15 min |
| `make keyword` (tshark JSON dissection of all 38,355 captures) | 45 min |
| `make entropy` | 3 min |
| `make exposure`, `make revocation`, `make images`, `make lanpush` | under 1 min each |

---

## Data

### Included: `data/`

| Folder | Contents |
|---|---|
| `data/reference/` | Inputs we curated or snapshotted: the update servers we confirmed by hand, with the evidence for each and the rejected candidates, and the dated ciphersuite.info API response with the table derived from it. |
| `data/derived/` | Per-flow and per-server tables written by the scripts. They are enough to regenerate every figure and table. |

[data/README.md](data/README.md) describes every file and column.

The derived tables hold per-flow metadata, TLS parameters and a few HTTP request lines. They
contain no transferred files, and device identifiers (MAC addresses and the subjects of
client certificates) are withheld.

### Not included: raw data

| Data | Size | How to obtain | Where to put it |
|---|---|---|---|
| Captures of our update experiments (10 devices, pcapng filtered to each device) | 3.5 GB | available on request | `controlled/dataset/<device>/<device>_filtered.pcapng` |
| Mon(IoT)r traces (IMC 2019), 38,355 pcaps | 13 GB | request access from the [Mon(IoT)r Lab](https://moniotrlab.ccis.neu.edu/imc19/) (data-sharing agreement) | `retrospective/imc19_dataset/{iot-data,iot-idle}/<region>/<device>/...` |
| Firmware images of the controlled devices | 10 GB | vendor download sites; the Tapo images can also be extracted from the captures | the paths in the `path` column of `data/derived/image_protection/integrity_tiers.csv` |

The Mon(IoT)r traces must not be redistributed; request them from their owners.

The folder names under `controlled/dataset/` follow our lab notes: `dlink`, `eufy`,
`riolink` and `xiaomi` hold d-link-cam, eufy-cam, reolink-cam and xiaomi-cam. The mapping
is in `src/update_attribution/paths.py`.

---

## Repository layout

```
.
├── README.md                  this file
├── Makefile                   one target per step (make help)
├── requirements.txt           Python dependencies
├── src/
│   ├── update_attribution/    update-traffic identification, TLS, certificates, revocation,
│   │                          entropy, exposure, figures and paper numbers (see its README)
│   └── image_protection/      integrity mechanism of firmware images (checksum or signature)
├── data/
│   ├── reference/             confirmed update servers, cipher-suite snapshot
│   └── derived/               outputs of src/: controlled/, retrospective/, image_protection/
├── latex/suit_acm_sigconf/    paper sources and the figures they include
└── legacy/                    code and results of earlier versions of this study (not used)

Local only (ignored by git): controlled/, retrospective/ (raw data), cache/ (tshark caches)
```

---

## Method in brief

1. **Identify update traffic by its servers, not by keywords.** Every hostname in DNS
   queries, TLS server names and HTTP Host headers, and every HTTP request URI, is matched
   against update patterns. We keep a candidate only if its content or the vendor's
   documentation shows that it serves update checks, metadata, authorization or images
   (`data/reference/confirmed_update_servers_*.csv`). Flows to these servers are update
   traffic. For comparison, `keyword_baseline.py` measures what a keyword filter selects
   instead.
2. **Protocol before entropy.** Encryption status comes from the protocol: a flow with a
   TLS handshake is encrypted, an HTTP flow is not. Entropy decides only for flows that
   protocol inspection cannot classify. Computed for all update flows, it shows that
   compressed images look like ciphertext.
3. **Negotiated TLS parameters are the exposure.** Offered suites are reported separately,
   because they mostly reflect library defaults. Suites are labeled with a dated
   ciphersuite.info snapshot; signaling values and GREASE are excluded.
4. **Leaf certificates of update servers only.** We record validity, key size and
   revocation support (OCSP/CRL pointers, stapling, lookups by the device).
5. **Channel together with image.** The integrity mechanism inside each image
   (checksum, signature, per-device authorization) decides whether a weak channel permits
   tampering.

[src/update_attribution/README.md](src/update_attribution/README.md) has the details.

---

## Earlier versions

`legacy/` keeps the code, figures and intermediate data of earlier versions of this
study: per-device entropy averages, hand-written cipher-suite classes, statistics over all
certificates in a capture, and CVE matching by keyword. The current paper does not use
them; [legacy/README.md](legacy/README.md) explains why.

## License and contact

Added upon publication (anonymized for review).
