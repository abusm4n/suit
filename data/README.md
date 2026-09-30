# Data

Everything in this folder is versioned. The raw captures are not; see the top-level
README. Unless noted otherwise, a "flow" is a bidirectional TCP connection or UDP
conversation, and `stream` is tshark's stream index within the capture.

## reference/: curated inputs

| File | Contents |
|---|---|
| `confirmed_update_servers_controlled.csv` | Update servers of our captures: `device`, `endpoint` (hostname, or `LAN:<address>` for the local push), `role` (update check, metadata, catalog, personalization, image, ...), `confidence` (`confirmed`, or `likely` for multi-purpose device APIs), `evidence`. |
| `confirmed_update_servers_retrospective.csv` | Candidates in the 2019 traces with our decision: `endpoint`, `uri_regex` (a request URI must also match, where given), `role`, `decision` (`keep` or `reject`), `evidence` (why it was kept or rejected). |
| `ciphersuite_info_api_2026-09-30.json` | Unmodified response of `https://ciphersuite.info/api/cs/`, retrieved on 2026-09-30. |
| `ciphersuite_info_2026-09-30.csv` | Table derived from it by `src/update_attribution/ciphersuite_snapshot.py`: `hex`, `iana_name`, `openssl_name`, `security` (recommended, secure, weak, insecure), `tls_version`. |

## derived/controlled/: our ten update captures

| File | One row per | Columns |
|---|---|---|
| `flows.csv` | flow (2,219) | `device`, `proto`, `stream`, `remote` (peer address), `rport`, `lan`, `sni`, `http_host`, `dns_names` (names resolved to `remote`), `bytes_up`, `bytes_down`, `t0`, `t1` (epoch seconds), `endpoint` (confirmed update server; empty if not update traffic), `role`, `confidence`, `tls_version`, `suite`, `suite_label`, `offered_config` (hex list of offered suites) |
| `funnel.csv` | device | flows (`lan`, `wan`), update flows (`update_tls`, `update_http`, `update_lan`), `update_mb`, `update_share` (share of all bytes), `endpoints` |
| `tls_update.csv` | device, server and negotiated suite | `tls_version`, `suite`, `label`, `connections` |
| `offered_configs.csv` | distinct offered suite list | counts per category (`recommended`, `secure`, `weak`, `insecure`, `signal`), `insecure_names`, `offers_tls13` |
| `leaf_certs.csv` | server leaf certificate (TLS 1.2; TLS 1.3 hides it) | `endpoint`, `subject`, `issuer`, `key`, `not_before`, `not_after`, `validity_days`, `self_signed`, `connections` |
| `entropy_by_channel.csv` | update flow | normalized Shannon entropy of the first 2 MB sent by the server; `group` = how protocol inspection classifies the flow |
| `exposure.csv` | unencrypted update server | device attributes found in the requests: `model`, `hardware`, `installed`, `offered`, `build`, `region`, `mac` (present or not, never the value), `platform`, `example_request` |
| `revocation.csv` | device and TLS update server | `ocsp`, `crl` (sources named in the leaf; empty when TLS 1.3 hides the leaf), `staple_requested` and `stapled` (of `connections`; stapling is visible in TLS 1.2 only, see `tls12`), `captures_with_revocation_lookup`, `lookup_hosts` |

## derived/retrospective/: the 2019 Mon(IoT)r traces

| File | One row per | Columns |
|---|---|---|
| `funnel.csv` | metric | captures, distinct hostnames, captures with update traffic, update flows (TLS, HTTP), confirmed servers, device labels and models (Table 1) |
| `candidates.csv` | hostname or URI matching an update pattern | `candidate`, `devices` (label:count), `decision` |
| `update_flows.csv` | update flow (2,497) | `device`, `capture` (path inside the dataset), `stream`, `endpoint`, `role`, `proto`, `tls_version`, `suite`, `label`, `offered_config` |
| `leaf_certs.csv` | leaf certificate of an update server | `role` (`server`, or `client` for the mutual-TLS certificate of a device, whose subject is withheld), then as above |
| `offered_configs.csv` | device and offered suite list | as above |
| `keyword_baseline.csv` | capture selected by the keyword filter (6,537) | `capture`, `categories` (where the keywords occur: `tcp-window-update`, `stun`, `sip`, `ocsp`, `dns-name`, `app-content`, ...) |
| `exposure.csv`, `revocation.csv` | as for the controlled captures | |

## derived/image_protection/

| File | One row per | Columns |
|---|---|---|
| `integrity_tiers.csv` | firmware image of a controlled device (37) | `path` (relative to the repository), `container`, `integrity_primitive`, `tier`, `embedded_check_verified`, `detection_rate`, `forgeable`, `notes` |

The tiers map to the paper's terms as follows:

| Tier | Paper | Meaning |
|---|---|---|
| `IL1` | checksum only | keyless check such as CRC32 or MD5, which anyone can recompute after a modification |
| `IL2` | signed | signature that needs the vendor's private key |
| `IL2(ext)` | signed, authorized per device | installation also needs a per-device approval from the vendor (Apple) |
| `IL1+IL2` | signed | a keyless envelope check plus a signature |
| `?` | unknown | format not recognized; the integrity mechanism was not determined |
