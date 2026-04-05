#!/usr/bin/env python3
"""Generate a fresh set of PDF-only certificate figures from current analysis outputs."""

from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


ANALYSIS_CSV = Path("/home/ab/update_traffic/controlled/analysis_output/data/certificate_security_analysis.csv")
SUMMARY_CSV = Path("/home/ab/update_traffic/controlled/analysis_output/data/certificate_summary.csv")
FIGURES_DIR = Path("/home/ab/update_traffic/controlled/analysis_output/figures")


def save_pdf(fig, name):
    path = FIGURES_DIR / f"{name}.pdf"
    fig.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {path}")


def main() -> int:
    sns.set_style("whitegrid")
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(ANALYSIS_CSV)
    summary = pd.read_csv(SUMMARY_CSV)

    fig, ax = plt.subplots(figsize=(10, 6))
    counts = df["public_key_size"].value_counts().sort_index()
    ax.bar(counts.index.astype(str), counts.values, color=["#1f77b4", "#d62728", "#ff7f0e", "#2ca02c"][: len(counts)])
    ax.set_xlabel("Key size (bits)")
    ax.set_ylabel("Certificates")
    ax.set_title("Certificate Key Size Distribution")
    save_pdf(fig, "key_size_distribution")

    fig, ax = plt.subplots(figsize=(8, 8))
    strength_counts = df["strength_level"].value_counts()
    ax.pie(strength_counts.values, labels=strength_counts.index, autopct="%1.1f%%", startangle=90)
    ax.set_title("Certificate Strength Distribution")
    save_pdf(fig, "security_strength_pie")

    fig, ax = plt.subplots(figsize=(8, 5))
    algo_counts = df["public_key_type"].value_counts()
    ax.bar(algo_counts.index, algo_counts.values, color=["#ff7f0e", "#2ca02c"][: len(algo_counts)])
    ax.set_ylabel("Certificates")
    ax.set_title("Certificate Algorithm Distribution")
    save_pdf(fig, "algorithm_distribution")

    fig, ax = plt.subplots(figsize=(10, 6))
    groups = df.groupby("public_key_size")["security_bits"].apply(list).to_dict()
    positions = sorted(groups.keys())
    ax.boxplot([groups[pos] for pos in positions], tick_labels=[str(int(pos)) for pos in positions], patch_artist=True)
    ax.set_xlabel("Key size (bits)")
    ax.set_ylabel("Security bits")
    ax.set_title("Security Bits by Key Size")
    save_pdf(fig, "security_bits_boxplot")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    ax1.hist(df["years_valid"], bins=15, color="steelblue", edgecolor="black")
    ax1.set_xlabel("Validity (years)")
    ax1.set_ylabel("Certificates")
    ax1.set_title("Certificate Validity Histogram")
    bins = pd.cut(df["years_valid"], bins=[0, 1, 3, 5, 10, 100], labels=["<1", "1-3", "3-5", "5-10", ">10"])
    counts = bins.value_counts().sort_index()
    ax2.pie(counts.values, labels=counts.index, autopct="%1.1f%%", startangle=90)
    ax2.set_title("Validity Duration Categories")
    save_pdf(fig, "validity_analysis")

    serial_counts = summary["serial_number"].value_counts()
    repeated = serial_counts[serial_counts > 1].head(10)
    if not repeated.empty:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh(range(len(repeated)), repeated.values, color="#d62728")
        ax.set_yticks(range(len(repeated)))
        ax.set_yticklabels([str(s)[:16] for s in repeated.index])
        ax.set_xlabel("Occurrences")
        ax.set_title("Repeated Certificate Serials")
        save_pdf(fig, "key_reuse_risk")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
