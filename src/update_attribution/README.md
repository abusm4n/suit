# Update-traffic analysis

These scripts produce the tables, figures and numbers of the paper. They read raw captures
from `controlled/` and `retrospective/` (not in the repository), write their results to
`data/derived/`, and cache tshark extractions in `cache/`. All paths are defined in
`paths.py`. Run them from the repository root, directly or through the `Makefile`.

## Scripts

| Script | What it does | Needs raw data | Writes |
|---|---|---|---|
| `controlled_attribution.py` | Rebuilds the flows of our ten captures, assigns them to confirmed update servers, and records negotiated and offered TLS parameters and server leaf certificates | yes | `controlled/flows.csv`, `funnel.csv`, `tls_update.csv`, `offered_configs.csv`, `leaf_certs.csv` |
| `retrospective_attribution.py` | The same for the 38,355 Mon(IoT)r captures, plus the list of candidate update servers for manual confirmation | yes | `retrospective/funnel.csv`, `candidates.csv`, `update_flows.csv`, `offered_configs.csv`, `leaf_certs.csv` |
| `keyword_baseline.py` | Applies a keyword filter (update, firmware, software, download anywhere in the dissection) to every 2019 capture and records where the keywords occur | yes | `retrospective/keyword_baseline.csv` |
| `keyword_baseline_sample.py` | Checks a 300-capture sample of the captures selected by the original keyword filter | the old selection | printed |
| `entropy_by_channel.py` | Normalized Shannon entropy of the payload of every update flow, grouped by protection | yes | `controlled/entropy_by_channel.csv` |
| `exposure.py` | Device attributes disclosed by unencrypted update requests | yes | `*/exposure.csv` |
| `revocation.py` | Revocation sources in leaf certificates, OCSP stapling, revocation lookups by devices | yes | `*/revocation.csv` |
| `lan_push_check.py` | Entropy, file signatures and image-chunk matches of reolink-cam's local push | yes | printed |
| `ciphersuite_snapshot.py` | Builds the cipher-suite table from the dated ciphersuite.info response (`--fetch` downloads a new one) | no | `data/reference/ciphersuite_info_*.csv` |
| `figures.py` | Figures 4-10 | no | `latex/suit_acm_sigconf/fig/*.pdf` |
| `paper_numbers.py` | Prints the numbers behind Tables 1-6 and the key statements | no | printed |
| `tls_classes.py`, `paths.py` | Cipher-suite labels, file locations (imported by the others) | – | – |

The image-protection analysis is in `../image_protection/`.

## Method

1. **Candidates.** Every hostname in DNS queries, TLS server names (SNI) and HTTP Host
   headers, and every HTTP request URI, is matched against update patterns (`update`,
   `upgrade`, `firmware`, `fw`, `ota`, `download`, ...). In our own captures, the flows
   that carry most of the bytes during the update are candidates as well.
2. **Confirmation by hand.** A candidate is kept only if its content or the vendor's
   documentation shows that it serves update checks, metadata, authorization or images.
   Multi-purpose device APIs are kept with confidence `likely`. The decisions and the
   evidence for each are in `data/reference/confirmed_update_servers_*.csv`.
3. **Assignment.** A flow is update traffic if its SNI or Host header is a confirmed
   server; for TLS without SNI, the DNS name resolved for the server address is used
   instead. Some 2019 servers also require a URI pattern (`uri_regex`). A flow on the
   local network counts only if it carries the image, which `lan_push_check.py`
   verifies for reolink-cam.
4. **TLS.** Negotiated parameters come from the ServerHello, and offered suites from the
   ClientHello, summarized per distinct suite list with GREASE collapsed. Labels come from
   `tls_classes.py` (ciphersuite.info snapshot of 2026-09-30); signaling values (`0x00FF`,
   `0x5600`) and GREASE are not counted as cipher suites.
5. **Certificates.** Only the server's leaf certificate, i.e. the first certificate it
   sends, is analyzed. Client certificates of mutual TLS are reported separately, with
   their subjects withheld. TLS 1.3 encrypts certificates, so its leaves are not visible.

## Notes

- `retrospective_attribution.py` and `keyword_baseline.py` run in parallel (`--jobs`,
  default 12). The keyword scan dissects every capture with `tshark -T json` and streams
  the output line by line, because some 2019 captures are over 100 MB. Interrupted runs
  resume from `cache/retrospective/keyword_baseline_cache_v2.jsonl`.
- `keyword_baseline_sample.py` reads `retrospective/imc19_dataset_update/`, the 6,315
  captures picked by the original keyword filter of an earlier version. That selection
  cannot be recreated exactly; `keyword_baseline.py` applies the filter as stated to all
  captures instead.
