# Image protection

`integrity_bitflip.py` determines how each firmware image of the controlled devices is
protected against modification (Section 5.4 and Figure 10 of the paper).

For each image it identifies the container format (u-boot uImage, TP-Link/Tapo,
Reolink `.pak`, Android OTA zip, Apple IPSW, NETGEAR `.chk`, TRX, MD5 sidecar, ...) and
locates the integrity field. It then runs two tests on an in-memory copy; the files on
disk are never modified:

- **detection:** flip payload bits and check whether the embedded field still matches;
- **forgeability:** flip a bit and repair the field using only public information, as an
  on-path attacker could, then re-run the check. A keyless checksum (CRC32, MD5) can be
  repaired; a signature cannot be without the vendor's private key.

```bash
python3 src/image_protection/integrity_bitflip.py                 # images of the controlled devices
python3 src/image_protection/integrity_bitflip.py DIR_OR_FILE ...  # any other images
```

The output, `data/derived/image_protection/integrity_tiers.csv`, is described in
`data/README.md`, together with how its tiers map to the paper's terms. The images are
vendor downloads and are not part of the repository; their file names are in the output.

The script checks structure, not trust: it does not validate signatures against the
vendors' root keys, and it cannot tell whether a device enforces the check before it
installs an image.
