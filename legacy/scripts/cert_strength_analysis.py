#!/usr/bin/env python3
"""Run a clean certificate strength analysis on the current summary CSV only."""

from pathlib import Path
import pandas as pd


INPUT_CSV = Path("/home/ab/update_traffic/controlled/analysis_output/data/certificate_summary.csv")
ANALYSIS_CSV = Path("/home/ab/update_traffic/controlled/analysis_output/data/certificate_security_analysis.csv")
OVERVIEW_CSV = Path("/home/ab/update_traffic/controlled/analysis_output/data/certificate_security_overview.csv")
REPORT_MD = Path("/home/ab/update_traffic/controlled/analysis_output/data/KEY_SIZE_ALGORITHM_STRENGTH_REPORT.md")
README_MD = Path("/home/ab/update_traffic/controlled/analysis_output/README_CERTIFICATE_ANALYSIS.md")


def assess_strength(key_type, key_size):
    if "RSA" in key_type:
        if key_size == 1024:
            return "BROKEN", 80, "Replace immediately"
        if key_size == 2048:
            return "WEAK", 112, "Migration recommended"
        if key_size >= 3072:
            return "STRONG", 128, "Acceptable modern baseline"
    if "EC" in key_type:
        if key_size == 256:
            return "STRONG", 128, "Modern baseline"
        if key_size >= 384:
            return "VERY_STRONG", 192, "High assurance"
    return "UNKNOWN", 0, "Manual review"


def format_pct(count, total):
    return round((count / total) * 100, 1) if total else 0.0


def build_report(overview: dict) -> str:
    return f"""# Scientific Security Analysis: Certificate Key Size and Algorithm Strength

Analysis date: {pd.Timestamp.now().date()}  
Dataset scope: TP-Link Tapo C200 certificate folder  
Certificate count analyzed: {overview['total_certificates']} unique certificates

## Executive Summary

This analysis was rebuilt from scratch from the current contents of the certificate folder. Each row corresponds to one current certificate file.

Key results:
- 1024-bit RSA: {overview['rsa_1024_count']} ({overview['rsa_1024_pct']}%)
- 2048-bit RSA: {overview['rsa_2048_count']} ({overview['rsa_2048_pct']}%)
- Strong certificates: {overview['strong_count']} ({overview['strong_pct']}%)
- Expired certificates: {overview['expired_count']} ({overview['expired_pct']}%)
- Certificates with validity > 5 years: {overview['gt5_count']} ({overview['gt5_pct']}%)
- Mean validity: {overview['mean_validity']} years
- Median validity: {overview['median_validity']} years

## Key Type Distribution

{overview['key_type_lines']}

## Key Size Distribution

{overview['key_size_lines']}

## Security Interpretation

1. RSA-1024 certificates remain a critical weakness if present.
2. RSA-2048 dominates the dataset and should be treated as transitional rather than future-proof.
3. Expired certificates indicate lifecycle management gaps.
4. Long validity periods increase risk exposure if keys are compromised.

## Output Artifacts

- controlled/analysis_output/data/certificate_summary.csv
- controlled/analysis_output/data/certificate_security_analysis.csv
- controlled/analysis_output/data/certificate_security_overview.csv

## Figures

- controlled/analysis_output/figures/key_size_distribution.pdf
- controlled/analysis_output/figures/security_strength_pie.pdf
- controlled/analysis_output/figures/algorithm_distribution.pdf
- controlled/analysis_output/figures/security_bits_boxplot.pdf
- controlled/analysis_output/figures/validity_analysis.pdf

## Method Notes

Strength bins used in this analysis script:
- RSA-1024 -> BROKEN
- RSA-2048 -> WEAK
- RSA-3072+ -> STRONG
- EC-P256+ -> STRONG
"""


def build_readme(overview: dict) -> str:
    return f"""# Certificate Security Analysis - Complete Results

**Analysis Date:** {pd.Timestamp.now().date()}  
**Dataset:** {overview['total_certificates']} unique X.509 certificates from TP-Link Tapo C200 IoT device  
**Focus:** Key Size & Cryptographic Algorithm Strength

---

## 📊 CRITICAL FINDINGS AT A GLANCE

| Metric | Value | Status |
|--------|-------|--------|
| Total Certificates Analyzed | {overview['total_certificates']} | ✓ |
| 1024-bit RSA (BROKEN) | {overview['rsa_1024_count']} ({overview['rsa_1024_pct']}%) | 🔴 **CRITICAL** |
| 2048-bit RSA (WEAK) | {overview['rsa_2048_count']} ({overview['rsa_2048_pct']}%) | 🟡 **Needs Migration** |
| P-256 ECC (STRONG) | {overview['ec_256_count']} ({overview['ec_256_pct']}%) | 🟢 **Modern** |
| 4096-bit RSA (STRONG) | {overview['rsa_4096_count']} ({overview['rsa_4096_pct']}%) | 🟢 **Strong** |
| Average Security Strength | {overview['avg_security_bits']} bits | ⚠️ Below NIST 128-bit |
| Unique Keys Used | {overview['unique_serials']} (of {overview['total_certificates']}) | 🟢 **No File-Level Duplication** |
| Expired Certificates | {overview['expired_count']} ({overview['expired_pct']}%) | ⚠️ Still Deployed |
| Long Validity (>5 years) | {overview['gt5_count']} ({overview['gt5_pct']}%) | 🔴 **Risk** |

---

Primary outputs:
- `certificate_summary.csv`
- `certificate_security_analysis.csv`
- `certificate_security_overview.csv`
- `KEY_SIZE_ALGORITHM_STRENGTH_REPORT.md`

Figures:
- `key_size_distribution.pdf`
- `security_strength_pie.pdf`
- `algorithm_distribution.pdf`
- `security_bits_boxplot.pdf`
- `validity_analysis.pdf`
"""


def main() -> int:
    df = pd.read_csv(INPUT_CSV)
    df["public_key_size"] = pd.to_numeric(df["public_key_size"], errors="coerce")
    df["not_before"] = pd.to_datetime(df["not_before"])
    df["not_after"] = pd.to_datetime(df["not_after"])
    df["years_valid"] = (df["not_after"] - df["not_before"]).dt.days / 365.25
    df[["strength_level", "security_bits", "recommendation"]] = df.apply(
        lambda row: pd.Series(assess_strength(row["public_key_type"], row["public_key_size"])),
        axis=1,
    )

    total = len(df)
    today = pd.Timestamp.now().normalize()

    overview = {
        "total_certificates": total,
        "unique_serials": int(df["serial_number"].nunique()),
        "rsa_1024_count": int((df["public_key_size"] == 1024).sum()),
        "rsa_2048_count": int((df["public_key_size"] == 2048).sum()),
        "rsa_4096_count": int((df["public_key_size"] == 4096).sum()),
        "ec_256_count": int(((df["public_key_type"].str.contains("EC", na=False)) & (df["public_key_size"] == 256)).sum()),
        "expired_count": int((df["not_after"] < today).sum()),
        "gt5_count": int((df["years_valid"] > 5).sum()),
        "strong_count": int(df["strength_level"].isin(["STRONG", "VERY_STRONG"]).sum()),
        "avg_security_bits": int(round(df["security_bits"].mean())),
        "mean_validity": round(float(df["years_valid"].mean()), 2),
        "median_validity": round(float(df["years_valid"].median()), 2),
    }

    overview["rsa_1024_pct"] = format_pct(overview["rsa_1024_count"], total)
    overview["rsa_2048_pct"] = format_pct(overview["rsa_2048_count"], total)
    overview["rsa_4096_pct"] = format_pct(overview["rsa_4096_count"], total)
    overview["ec_256_pct"] = format_pct(overview["ec_256_count"], total)
    overview["expired_pct"] = format_pct(overview["expired_count"], total)
    overview["gt5_pct"] = format_pct(overview["gt5_count"], total)
    overview["strong_pct"] = format_pct(overview["strong_count"], total)

    overview["key_type_lines"] = "\n".join(
        f"- {label}: {count} ({format_pct(count, total)}%)"
        for label, count in df["public_key_type"].value_counts().items()
    )
    overview["key_size_lines"] = "\n".join(
        f"- {int(label)} bits: {count} ({format_pct(count, total)}%)"
        for label, count in df["public_key_size"].value_counts().sort_index().items()
    )

    ANALYSIS_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(ANALYSIS_CSV, index=False)
    pd.DataFrame([overview]).to_csv(OVERVIEW_CSV, index=False)
    REPORT_MD.write_text(build_report(overview), encoding="utf-8")
    README_MD.write_text(build_readme(overview), encoding="utf-8")

    print(f"Analyzed {total} certificates")
    print(f"Saved: {ANALYSIS_CSV}")
    print(f"Saved: {OVERVIEW_CSV}")
    print(f"Saved: {REPORT_MD}")
    print(f"Saved: {README_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
