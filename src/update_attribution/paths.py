"""Where the scripts in src/update_attribution read and write their files.

  raw captures (not in the repository, see README.md > Data)
    controlled/dataset/<device>/<device>_filtered.pcapng    our update experiments
    controlled/dataset/riolink/firmware/                     Reolink images (LAN-push check)
    retrospective/imc19_dataset/{iot-data,iot-idle}/         Mon(IoT)r traces (IMC 2019)
    retrospective/imc19_dataset_update/                      captures picked by the old
                                                             keyword filter (optional)
  reference inputs (in the repository)
    data/reference/                                          confirmed update servers,
                                                             ciphersuite.info snapshot
  derived data (in the repository; enough to regenerate every figure and table)
    data/derived/controlled/, data/derived/retrospective/
  caches (not in the repository; safe to delete, rebuilt on the next run)
    cache/
  paper figures
    latex/suit_acm_sigconf/fig/
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# raw data (not versioned)
RAW_CONTROLLED = REPO / 'controlled' / 'dataset'
RAW_RETRO = REPO / 'retrospective' / 'imc19_dataset'
RAW_RETRO_KEYWORD_SELECTION = REPO / 'retrospective' / 'imc19_dataset_update'
REOLINK_FIRMWARE = RAW_CONTROLLED / 'riolink' / 'firmware'

# reference inputs (versioned)
REFERENCE = REPO / 'data' / 'reference'
SERVERS_CONTROLLED = REFERENCE / 'confirmed_update_servers_controlled.csv'
SERVERS_RETRO = REFERENCE / 'confirmed_update_servers_retrospective.csv'
CIPHERSUITE_SNAPSHOT = REFERENCE / 'ciphersuite_info_2026-09-30.csv'

# derived data (versioned)
DERIVED_CONTROLLED = REPO / 'data' / 'derived' / 'controlled'
DERIVED_RETRO = REPO / 'data' / 'derived' / 'retrospective'

# caches (not versioned)
CACHE_CONTROLLED = REPO / 'cache' / 'controlled'
CACHE_RETRO_FIELDS = REPO / 'cache' / 'retrospective' / 'fields'
CACHE_KEYWORD = REPO / 'cache' / 'retrospective' / 'keyword_baseline_cache_v2.jsonl'

# paper figures
FIGURES = REPO / 'latex' / 'suit_acm_sigconf' / 'fig'

# controlled capture of each device (folder names follow the lab notes; the paper uses
# the names in the last column)
CONTROLLED_CAPTURES = {
    'apple-tv': 'apple-tv/apple-tv_filtered.pcapng', 'd-link-cam': 'dlink/dlink_filtered.pcapng',
    'eufy-cam': 'eufy/eufy_filtered.pcapng', 'fire-tv': 'fire-tv/fire-tv_filtered.pcapng',
    'homepod': 'homepod/homepod_filtered.pcapng', 'reolink-cam': 'riolink/riolink_filtered.pcapng',
    'sony-tv': 'sony-tv/sony_tv_filtered.pcapng', 'tapo-c100': 'tapo-c100/tapo-c100_filtered.pcapng',
    'tapo-c200': 'tapo-c200/tapo-c200_filtered.pcapng', 'xiaomi-cam': 'xiaomi/xiaomi_filtered.pcapng',
}


def require(*paths):
    """Stop with a clear message if raw inputs are missing, before any output is written,
    so that the versioned results in data/derived/ are never overwritten with empty tables."""
    missing = [p for p in paths if not p.exists()]
    if missing:
        sys.exit('missing raw data: ' + ', '.join(str(p.relative_to(REPO)) for p in missing) +
                 '\nSee README.md, "Data". The versioned results in data/derived/ were left unchanged.')
