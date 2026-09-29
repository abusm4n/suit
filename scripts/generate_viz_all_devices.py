"""
Generate PDF visualizations for all 10 IoT devices combined certificate analysis.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# Configuration (paths relative to the repository root; this file is in scripts/)
REPO = Path(__file__).resolve().parents[1]
INPUT_ANALYSIS = REPO / 'controlled/analysis_output/data/certificate_security_analysis_all_devices.csv'
OUTPUT_FIGURES = REPO / 'controlled/analysis_output/figures'
OUTPUT_FIGURES.mkdir(parents=True, exist_ok=True)

# Plot styling
sns.set_theme(style='whitegrid', context='talk')
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 14
plt.rcParams['axes.titlesize'] = 20
plt.rcParams['axes.labelsize'] = 16
plt.rcParams['xtick.labelsize'] = 14
plt.rcParams['ytick.labelsize'] = 14
plt.rcParams['legend.fontsize'] = 14
plt.rcParams['legend.title_fontsize'] = 15


def style_axes(ax):
    """Apply consistent styling across figures."""
    ax.grid(axis='y', linestyle='--', alpha=0.35)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)


def key_size_color(key_size):
    """Map key sizes to security semantics (worst->best)."""
    # In this dataset, EC-256 is modern strength (similar to 128-bit security).
    if key_size == 1024:
        return '#d73027'  # worst (red)
    if key_size == 2048:
        return '#fdae61'  # transitional (amber)
    if key_size == 256:
        return '#66c2a5'  # strong ECC (teal)
    if key_size == 384:
        return '#3288bd'  # stronger ECC (blue)
    if key_size == 3072:
        return '#4daf4a'  # strong RSA baseline (green)
    if key_size == 4096:
        return '#1b7837'  # stronger RSA (dark green)
    return '#9e9e9e'      # unknown (gray)

def load_data():
    """Load analysis data."""
    return pd.read_csv(INPUT_ANALYSIS)

def plot_key_size_distribution(df):
    """Plot key size distribution across all devices."""
    fig, ax = plt.subplots(figsize=(12, 7))
    
    key_sizes = df['public_key_size'].value_counts().sort_index()
    colors = [key_size_color(k) for k in key_sizes.index]
    
    key_sizes.plot(kind='bar', ax=ax, color=colors, edgecolor='black', linewidth=1.2, width=0.92)
    #ax.set_title('Key Size Distribution (All 10 Devices)', fontweight='bold', pad=12)
    ax.set_xlabel('Key Size (bits)', fontsize=14)
    ax.set_ylabel('Count', fontsize=14)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
    ax.margins(x=0.01)
    style_axes(ax)
    
    # Add count labels on bars
    for i, v in enumerate(key_sizes):
        ax.text(i, v + 0.8, str(v), ha='center', va='bottom', fontweight='bold', fontsize=13)
    
    plt.tight_layout()
    plt.savefig(OUTPUT_FIGURES / 'key_size_distribution_all_devices.pdf', format='pdf', dpi=300)
    print("✓ Saved key_size_distribution_all_devices.pdf")
    plt.close()

def plot_security_strength_pie(df):
    """Plot overall security strength breakdown."""
    fig, ax = plt.subplots(figsize=(10, 8))
    
    strength_counts = df['strength_level'].value_counts()
    colors = {'STRONG': '#2ca02c', 'WEAK': '#ff7f0e', 'BROKEN': '#d62728', 'UNKNOWN': '#7f7f7f'}
    color_list = [colors.get(s, '#7f7f7f') for s in strength_counts.index]
    
    wedges, texts, autotexts = ax.pie(
        strength_counts, 
        labels=strength_counts.index, 
        autopct='%1.1f%%',
        colors=color_list,
        startangle=90,
        textprops={'fontsize': 13, 'fontweight': 'bold'}
    )
    
    ax.set_title('Overall Security Strength Distribution (All Devices)', fontsize=18, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(OUTPUT_FIGURES / 'security_strength_pie_all_devices.pdf', format='pdf', dpi=300)
    print("✓ Saved security_strength_pie_all_devices.pdf")
    plt.close()

def plot_algorithm_distribution(df):
    """Plot RSA vs EC distribution."""
    fig, ax = plt.subplots(figsize=(12, 7))
    
    algo_counts = df['public_key_type'].value_counts()
    # Map raw class names to short readable labels
    label_map = {'RSAPublicKey': 'RSA Public Key', 'ECPublicKey': 'Elliptic Curve Public Key'}
    algo_counts.index = [label_map.get(k, k) for k in algo_counts.index]
    colors = ['#1f77b4', '#ff7f0e']
    
    algo_counts.plot(kind='bar', ax=ax, color=colors, edgecolor='black', linewidth=1.2, width=0.90)
    ax.set_ylabel('Certificate Count', fontsize=14)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
    ax.margins(x=0.01)
    style_axes(ax)
    
    # Add count labels
    for i, v in enumerate(algo_counts):
        ax.text(i, v + 1.5, str(v), ha='center', va='bottom', fontweight='bold', fontsize=13)
    
    plt.tight_layout()
    plt.savefig(OUTPUT_FIGURES / 'algorithm_distribution_all_devices.pdf', format='pdf', dpi=300)
    print("✓ Saved algorithm_distribution_all_devices.pdf")
    plt.close()

def plot_device_comparison_key_size(df):
    """Plot per-device key size breakdown."""
    fig, ax = plt.subplots(figsize=(16, 8.5))
    
    # Create pivot table: device x key_size
    pivot_table = pd.crosstab(df['device'], df['public_key_size'])
    pivot_table = pivot_table.sort_index()
    
    pivot_table.plot(
        kind='bar', ax=ax, stacked=False, edgecolor='white', linewidth=0.8,
        width=0.98, color=[key_size_color(k) for k in pivot_table.columns]
    )
    # ax.set_title('Key Size Distribution by Device', fontweight='bold', pad=12)
    ax.set_xlabel('')
    ax.set_ylabel('Certificate Count', fontsize=14)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=35, ha='right')
    ax.margins(x=0.002)
    style_axes(ax)
    ax.legend(title='Key Size (bits)', loc='upper right', frameon=True)
    
    plt.tight_layout()
    plt.savefig(OUTPUT_FIGURES / 'device_comparison_key_size.pdf', format='pdf', dpi=300)
    print("✓ Saved device_comparison_key_size.pdf")
    plt.close()

def plot_device_comparison_strength(df):
    """Plot per-device strength levels."""
    fig, ax = plt.subplots(figsize=(16, 8.5))
    
    pivot_table = pd.crosstab(df['device'], df['strength_level'])
    pivot_table = pivot_table.sort_index()
    
    # Ensure columns are in order
    col_order = ['BROKEN', 'WEAK', 'STRONG', 'UNKNOWN']
    for col in col_order:
        if col not in pivot_table.columns:
            pivot_table[col] = 0
    pivot_table = pivot_table[col_order]
    
    colors = {'BROKEN': '#d62728', 'WEAK': '#ff7f0e', 'STRONG': '#2ca02c', 'UNKNOWN': '#7f7f7f'}
    bar_colors = [colors.get(c, '#7f7f7f') for c in pivot_table.columns]
    
    pivot_table.plot(
        kind='bar', ax=ax, stacked=False, color=bar_colors, edgecolor='white',
        linewidth=0.8, width=0.98
    )
    ax.set_title('Security Strength Levels by Device', fontweight='bold', pad=12)
    ax.set_xlabel('')
    ax.set_ylabel('Certificate Count', fontsize=14)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=35, ha='right')
    ax.margins(x=0.002)
    style_axes(ax)
    ax.legend(title='Strength Level', loc='upper right', frameon=True)
    
    plt.tight_layout()
    plt.savefig(OUTPUT_FIGURES / 'device_comparison_strength.pdf', format='pdf', dpi=300)
    print("✓ Saved device_comparison_strength.pdf")
    plt.close()

def plot_security_bits_boxplot(df):
    """Plot the per-device distribution of certificate security strength.

    One box per device (unique certificates, NIST SP 800-57 bits) with the
    individual certificates overlaid, and the 80/112/128-bit NIST levels as
    dashed lines. Sized for one ACM two-column figure (3.33 in wide), so the
    fonts print at their nominal size when included at \\linewidth.
    """
    devices = sorted(df['device'].unique())
    data = [df.loc[df['device'] == d, 'security_bits'].to_numpy() for d in devices]
    rng = np.random.default_rng(0)  # fixed seed: reproducible jitter

    with plt.rc_context({
        'font.size': 7, 'axes.labelsize': 7, 'xtick.labelsize': 6.5,
        'ytick.labelsize': 6.5, 'legend.fontsize': 6, 'axes.linewidth': 0.6,
    }):
        fig, ax = plt.subplots(figsize=(3.4, 2.1))
        bp = ax.boxplot(
            data, positions=range(len(devices)), widths=0.55, patch_artist=True,
            showfliers=False, medianprops=dict(color='black', linewidth=1.0),
            whiskerprops=dict(linewidth=0.7), capprops=dict(linewidth=0.7),
            boxprops=dict(linewidth=0.7),
        )
        for patch in bp['boxes']:
            patch.set_facecolor('#9ecae1')
            patch.set_alpha(0.8)
        for i, vals in enumerate(data):
            x = i + rng.uniform(-0.18, 0.18, len(vals))
            ax.scatter(x, vals, s=5, color='#08519c', alpha=0.55, linewidths=0, zorder=3)

        for bits, color, label in [
            (80, '#d62728', '80 bits (disallowed)'),
            (112, '#ff7f0e', '112 bits (transitional)'),
            (128, '#2ca02c', '128 bits (acceptable)'),
        ]:
            ax.axhline(y=bits, color=color, linestyle='--', linewidth=0.9, label=label, zorder=1)

        ax.set_xticks(range(len(devices)))
        ax.set_xticklabels(devices, rotation=35, ha='right')
        ax.set_xlim(-0.6, len(devices) - 0.4)
        ax.set_ylim(60, 205)
        ax.set_yticks([80, 112, 128, 160, 192])
        ax.set_ylabel('Security strength (bits)')
        # Upper right is empty (those devices stay at or below 128 bits); keeps
        # apple-tv's 192-bit (P-384) certificates visible on the left.
        ax.legend(loc='upper right', frameon=True, framealpha=0.9, ncol=1,
                  handlelength=1.8, borderpad=0.3, labelspacing=0.25)
        ax.grid(axis='y', linestyle=':', alpha=0.35)
        ax.grid(axis='x', visible=False)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

        fig.tight_layout(pad=0.2)
        fig.savefig(OUTPUT_FIGURES / 'security_bits_boxplot_all_devices.pdf', format='pdf')
        plt.close(fig)
    print("✓ Saved security_bits_boxplot_all_devices.pdf")

def plot_validity_analysis(df):
    """Plot certificate validity periods."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Histogram
    ax1.hist(df['validity_years'], bins=30, color='#1f77b4', edgecolor='black', alpha=0.7)
    ax1.set_title('Distribution of Certificate Validity Periods', fontsize=16, fontweight='bold')
    ax1.set_xlabel('Validity Period (years)', fontsize=14)
    ax1.set_ylabel('Count', fontsize=14)
    ax1.axvline(df['validity_years'].mean(), color='red', linestyle='--', linewidth=2, label=f"Mean: {df['validity_years'].mean():.1f}y")
    ax1.axvline(df['validity_years'].median(), color='green', linestyle='--', linewidth=2, label=f"Median: {df['validity_years'].median():.1f}y")
    ax1.legend()
    
    # Pie chart: >5 years vs <=5 years
    long_validity_count = (df['validity_years'] > 5).sum()
    short_validity_count = len(df) - long_validity_count
    
    ax2.pie([long_validity_count, short_validity_count], 
            labels=[f'>5 years\n({long_validity_count})', f'≤5 years\n({short_validity_count})'],
            autopct='%1.1f%%', colors=['#ff7f0e', '#2ca02c'],
            startangle=90, textprops={'fontsize': 13, 'fontweight': 'bold'})
    ax2.set_title('Certificates by Validity Period', fontsize=16, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(OUTPUT_FIGURES / 'validity_analysis_all_devices.pdf', format='pdf', dpi=300)
    print("✓ Saved validity_analysis_all_devices.pdf")
    plt.close()

def plot_expired_by_device(df):
    """Plot expired certificates per device."""
    fig, ax = plt.subplots(figsize=(14, 7.5))
    
    expired_by_device = df.groupby('device')['is_expired'].agg(['sum', 'count'])
    expired_by_device.columns = ['expired', 'total']
    expired_by_device['active'] = expired_by_device['total'] - expired_by_device['expired']
    expired_by_device = expired_by_device.sort_index()
    
    expired_by_device[['active', 'expired']].plot(
        kind='bar', ax=ax, stacked=True, color=['#2ca02c', '#d62728'],
        edgecolor='white', linewidth=0.8, width=0.94
    )
    
    ax.set_xlabel('')
    ax.set_ylabel('Certificate Count', fontsize=16)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=35, ha='right', fontsize=15)
    ax.tick_params(axis='x', which='both', bottom=True, length=5, width=1.2)
    ax.margins(x=0)
    style_axes(ax)
    ax.legend(['Active', 'Expired'], loc='upper right', fontsize=14)
    
    # Add percentage labels
    for i, (device, row) in enumerate(expired_by_device.iterrows()):
        total = row['total']
        expired_pct = (row['expired'] / total * 100) if total > 0 else 0
        ax.text(i, total + 1, f"{expired_pct:.0f}%", ha='center', fontweight='bold', fontsize=14)
    
    plt.tight_layout()
    plt.savefig(OUTPUT_FIGURES / 'expired_by_device.pdf', format='pdf', dpi=300)
    print("✓ Saved expired_by_device.pdf")
    plt.close()

def main():
    """Generate all visualizations."""
    print("Loading data...")
    df = load_data()
    
    print("Generating visualizations...")
    plot_key_size_distribution(df)
    plot_security_strength_pie(df)
    plot_algorithm_distribution(df)
    plot_device_comparison_key_size(df)
    plot_device_comparison_strength(df)
    plot_security_bits_boxplot(df)
    plot_validity_analysis(df)
    plot_expired_by_device(df)
    
    print("\n✓ All visualizations complete!")

if __name__ == '__main__':
    main()
