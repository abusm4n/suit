# UpWire: IoT update delivery (artifact)

Code and derived data for the paper **"UpWire: A Network-Level Measurement of Consumer IoT
Update Delivery"** (under review; authors anonymized).

## Quick start


```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

make numbers    # prints the values behind Tables 1-6 and the key numbers in the text
make figures    # regenerates Figures 4-9 in latex/SUIT_SEC@SAC/fig/
```

Requires Python 3.10+ and a TeX installation with the `libertine` package (the figures use
the paper's fonts). Tested on Ubuntu 24.04 with Python 3.12.

## What reproduces what

Scripts are in `src/update_attribution/` unless noted; outputs are in `data/derived/`.

| In the paper | Script |
|---|---|
| Table 1: identifying update traffic | `controlled_attribution.py`, `retrospective_attribution.py` |
| Table 2: cipher-suite categories | `ciphersuite_snapshot.py` |
| Table 3: how each device received its update | `controlled_attribution.py`, `src/image_protection/integrity_bitflip.py` |
| Table 4: update servers in the 2019 traces | `retrospective_attribution.py` |
| Table 5: what unencrypted requests reveal | `exposure.py` |
| Table 6: revocation checks | `revocation.py` |
| Section 4.3: keyword-filter baseline | `keyword_baseline.py` |
| Section 5.2: local firmware push | `lan_push_check.py` |
| Figures 4-9 | `figures.py` |

## Data

- `data/reference/`: the confirmed update servers, with the evidence for each, and the dated
  ciphersuite.info snapshot.
- `data/derived/`: the tables written by the scripts; enough to regenerate every figure and
  table. [data/README.md](data/README.md) describes each file. Device identifiers (MAC
  addresses, client-certificate subjects) are withheld.

The raw data are not included: the captures of our update experiments (available on
request), the Mon(IoT)r traces (to be requested from the
[Mon(IoT)r Lab](https://moniotrlab.ccis.neu.edu/imc19/)), and the firmware images (vendor
download sites). With the raw data in the locations given in
`src/update_attribution/paths.py`, `make derived` rebuilds `data/derived/`; `make help`
lists all steps.
