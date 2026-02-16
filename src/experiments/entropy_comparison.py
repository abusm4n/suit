#!/usr/bin/env python3
"""
Experiment 1: Cross-Device Entropy Comparison Study

Analyzes entropy metrics across 10 smart IoT devices to identify
security and randomness differences in network traffic patterns.
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from scipy import stats

# Configuration
ENTROPY_DIR = os.path.expanduser("~/update_traffic/controlled/entropy")
OUTPUT_DIR = os.path.expanduser("~/update_traffic/analysis_output")
FIGURES_DIR = os.path.join(OUTPUT_DIR, "figures")
DATA_DIR = os.path.join(OUTPUT_DIR, "data")

# Create output directories
Path(FIGURES_DIR).mkdir(parents=True, exist_ok=True)
Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

# Device names to process (10 smart IoT devices)
DEVICES = [
    'apple-tv',
    'dlink',
    'eufy',
    'fire-tv',
    'homepod',
    'riolink',
    'sony_tv',
    'tapo_c100',
    'tapo_c200',
    'xiaomi'
]
METRICS = ['entropy_shannon', 'entropy_renyi', 'entropy_tsallis']

def load_entropy_data(device_name):
    """Load entropy CSV for a device from device folder or formatted CSV"""
    # Try device-specific folder first (e.g., /controlled/entropy/apple-tv/*.csv)
    device_folder = os.path.join(ENTROPY_DIR, device_name)
    if os.path.isdir(device_folder):
        csv_files = list(Path(device_folder).glob("*.csv"))
        if csv_files:
            try:
                df = pd.read_csv(csv_files[0])
                # Ensure entropy columns are numeric and valid
                for metric in METRICS:
                    if metric in df.columns:
                        df[metric] = pd.to_numeric(df[metric], errors='coerce')
                        df[metric] = df[metric].mask(df[metric] < 0, np.nan)
                return df, f"device folder"
            except Exception as e:
                print(f"Error reading from device folder {device_name}: {e}")
    
    # Try formatted CSV (legacy support for older device names)
    formatted_path = os.path.join(ENTROPY_DIR, f"{device_name}_formatted.csv")
    if os.path.exists(formatted_path):
        try:
            df = pd.read_csv(formatted_path)
            # Ensure entropy columns are numeric and valid
            for metric in METRICS:
                if metric in df.columns:
                    df[metric] = pd.to_numeric(df[metric], errors='coerce')
                    df[metric] = df[metric].mask(df[metric] < 0, np.nan)
            return df, "formatted CSV"
        except Exception as e:
            print(f"Error reading formatted {device_name}: {e}")
    
    return None, None

def compute_statistics(df, device_name):
    """Compute comprehensive statistics for a device"""
    stats_dict = {'device': device_name}
    
    for metric in METRICS:
        if metric in df.columns:
            col = df[metric]
            col = pd.to_numeric(col, errors='coerce')
            col = col[col >= 0]  # Remove invalid values
            
            short_name = metric.split('_')[1]  # 'shannon', 'renyi', 'tsallis'
            stats_dict[f'{short_name}_mean'] = col.mean()
            stats_dict[f'{short_name}_std'] = col.std()
            stats_dict[f'{short_name}_min'] = col.min()
            stats_dict[f'{short_name}_max'] = col.max()
            stats_dict[f'{short_name}_median'] = col.median()
            stats_dict[f'{short_name}_q25'] = col.quantile(0.25)
            stats_dict[f'{short_name}_q75'] = col.quantile(0.75)
            stats_dict[f'{short_name}_count'] = col.count()
    
    return stats_dict

def main():
    print("=" * 80)
    print("Cross-Device Entropy Comparison Study - 10 Smart IoT Devices")
    print("=" * 80)
    
    # Step 1: Load and process data
    print("\n[1] Loading entropy data for all devices (10 devices)...")
    device_data = {}
    all_entropy = []
    
    for device in DEVICES:
        df, source = load_entropy_data(device)
        if df is not None:
            device_data[device] = df
            print(f"  ✓ {device:15} - {len(df):8,} packets from {source}")
            
            # Prepare for combined analysis
            df['device'] = device
            all_entropy.append(df)
        else:
            print(f"  ✗ {device:15} - Not found")
    
    # Combine all data
    combined_df = pd.concat(all_entropy, ignore_index=True)
    
    # Step 2: Compute statistics per device
    print("\n[2] Computing entropy statistics per device...")
    stats_list = []
    for device in DEVICES:
        if device in device_data:
            stat_dict = compute_statistics(device_data[device], device)
            stats_list.append(stat_dict)
    
    stats_df = pd.DataFrame(stats_list)
    stats_df.to_csv(os.path.join(DATA_DIR, "entropy_statistics.csv"), index=False)
    print(f"  ✓ Statistics saved to entropy_statistics.csv")
    print("\nSummary Statistics (Shannon entropy means):")
    summary_cols = stats_df[['device', 'shannon_mean', 'shannon_std', 'shannon_count']]
    print(summary_cols.to_string(index=False))
    
    # Step 3: Statistical testing
    print("\n[3] Performing statistical tests...")
    
    # ANOVA: Are entropy means significantly different across devices?
    shannon_groups = [device_data[d]['entropy_shannon'].dropna().values 
                      for d in DEVICES if d in device_data]
    f_stat, p_value = stats.f_oneway(*shannon_groups)
    print(f"\n  Shannon Entropy ANOVA:")
    print(f"    F-statistic: {f_stat:.4f}")
    print(f"    P-value: {p_value:.2e}")
    print(f"    Significant difference: {'YES' if p_value < 0.05 else 'NO'}")
    
    # Step 4: Create visualizations
    print("\n[4] Creating visualizations...")
    
    # Figure 1: Box plots (3 rows, adjust columns for 10 devices)
    fig, axes = plt.subplots(3, 1, figsize=(16, 12))
    
    for idx, metric in enumerate(['entropy_shannon', 'entropy_renyi', 'entropy_tsallis']):
        name = metric.split('_')[1].capitalize()
        
        # Prepare data
        plot_data = []
        labels = []
        for device in DEVICES:
            if device in device_data:
                vals = device_data[device][metric].dropna()
                vals = vals[vals >= 0]
                plot_data.append(vals)
                labels.append(device)
        
        # Box plot
        bp = axes[idx].boxplot(plot_data, labels=labels, patch_artist=True)
        for patch in bp['boxes']:
            patch.set_facecolor('lightblue')
        axes[idx].set_ylabel('Entropy Value', fontsize=11)
        axes[idx].set_title(f'{name} Entropy Distribution (10 Devices)', fontsize=12, fontweight='bold')
        axes[idx].grid(True, alpha=0.3, axis='y')
        axes[idx].tick_params(axis='x', rotation=45)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "entropy_boxplots.pdf"), dpi=300, bbox_inches='tight')
    print("  ✓ Saved: entropy_boxplots.pdf")
    plt.close()
    
    # Figure 2: Distribution histograms (3 rows x 10 columns)
    fig, axes = plt.subplots(3, 10, figsize=(20, 10))
    
    for metric_idx, metric in enumerate(METRICS):
        name = metric.split('_')[1].capitalize()
        for device_idx, device in enumerate(DEVICES):
            ax = axes[metric_idx, device_idx]
            if device in device_data:
                vals = device_data[device][metric].dropna()
                vals = vals[vals >= 0]
                ax.hist(vals, bins=30, color='steelblue', edgecolor='black', alpha=0.7)
                ax.set_title(f'{device}\n({name})', fontsize=9)
                ax.set_xlabel('Entropy', fontsize=8)
                if device_idx == 0:
                    ax.set_ylabel('Freq', fontsize=8)
                ax.grid(True, alpha=0.3, axis='y')
                ax.tick_params(labelsize=7)
    
    plt.suptitle('Entropy Distributions - 10 Devices', fontsize=14, fontweight='bold', y=0.995)
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "entropy_distributions.pdf"), dpi=300, bbox_inches='tight')
    print("  ✓ Saved: entropy_distributions.pdf")
    plt.close()
    
    # Figure 3: Heatmap of mean entropy values
    heatmap_data = stats_df[['device', 'shannon_mean', 'renyi_mean', 'tsallis_mean']].set_index('device')
    heatmap_data.columns = ['Shannon', 'Rényi', 'Tsallis']
    
    plt.figure(figsize=(10, 8))
    sns.heatmap(heatmap_data.T, annot=True, fmt='.4f', cmap='RdYlGn', 
                cbar_kws={'label': 'Entropy Value'}, linewidths=1, linecolor='gray')
    plt.title('Mean Entropy Values by Device (10 Devices)', fontsize=12, fontweight='bold')
    plt.xlabel('Device', fontsize=11)
    plt.ylabel('Entropy Metric', fontsize=11)
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "entropy_heatmap.pdf"), dpi=300, bbox_inches='tight')
    print("  ✓ Saved: entropy_heatmap.pdf")
    plt.close()
    
    # Figure 4: Violin plots for Shannon entropy across all 10 devices
    fig, ax = plt.subplots(figsize=(14, 6))
    
    violin_data = []
    for device in DEVICES:
        if device in device_data:
            vals = device_data[device]['entropy_shannon'].dropna()
            vals = vals[vals >= 0]
            # Sample if too many points for clarity
            sample_size = min(500, len(vals))
            for v in np.random.choice(vals, sample_size, replace=False):
                violin_data.append({'Device': device, 'Shannon Entropy': v})
    
    violin_df = pd.DataFrame(violin_data)
    sns.violinplot(data=violin_df, x='Device', y='Shannon Entropy', ax=ax, palette='Set2')
    ax.set_ylabel('Shannon Entropy', fontsize=11)
    ax.set_xlabel('Device', fontsize=11)
    ax.set_title('Shannon Entropy Distribution (10 Devices) - Violin Plot', fontsize=12, fontweight='bold')
    ax.grid(True, alpha=0.3, axis='y')
    ax.tick_params(axis='x', rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "entropy_violins.pdf"), dpi=300, bbox_inches='tight')
    print("  ✓ Saved: entropy_violins.pdf")
    plt.close()
    
    # Figure 5: Scatter plot comparing two metrics
    fig, ax = plt.subplots(figsize=(10, 8))
    
    colors = plt.cm.tab10(np.linspace(0, 1, len(DEVICES)))
    for device_idx, device in enumerate(DEVICES):
        if device in device_data:
            x = device_data[device]['entropy_shannon'].dropna()
            y = device_data[device]['entropy_renyi'].dropna()
            # Align arrays
            common_idx = np.intersect1d(x.index, y.index)
            if len(common_idx) > 0:
                x_aligned = device_data[device].loc[common_idx, 'entropy_shannon']
                y_aligned = device_data[device].loc[common_idx, 'entropy_renyi']
                ax.scatter(x_aligned, y_aligned, alpha=0.5, s=30, label=device, color=colors[device_idx])
    
    ax.set_xlabel('Shannon Entropy', fontsize=11)
    ax.set_ylabel('Rényi Entropy', fontsize=11)
    ax.set_title('Shannon vs Rényi Entropy Correlation (10 Devices)', fontsize=12, fontweight='bold')
    ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=9)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "entropy_scatter_correlation.pdf"), dpi=300, bbox_inches='tight')
    print("  ✓ Saved: entropy_scatter_correlation.pdf")
    plt.close()
    
    # Step 5: Summary report
    print("\n[5] Generating summary report...")
    
    with open(os.path.join(DATA_DIR, "entropy_analysis_report.txt"), "w") as f:
        f.write("=" * 80 + "\n")
        f.write("CROSS-DEVICE ENTROPY ANALYSIS REPORT - 10 SMART IOT DEVICES\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total devices analyzed: {len([d for d in DEVICES if d in device_data])}\n")
        f.write(f"Devices: {', '.join(DEVICES)}\n")
        f.write(f"Total packets processed: {len(combined_df):,}\n")
        f.write(f"Entropy metrics: Shannon, Rényi, Tsallis\n\n")
        
        f.write("DEVICE DATA SUMMARY\n")
        f.write("-" * 80 + "\n")
        for device in DEVICES:
            if device in device_data:
                f.write(f"  {device:15} - {len(device_data[device]):8,} packets\n")
        f.write("\n")
        
        f.write("STATISTICAL FINDINGS\n")
        f.write("-" * 80 + "\n")
        f.write(f"Shannon Entropy ANOVA F-statistic: {f_stat:.4f}\n")
        f.write(f"Shannon Entropy ANOVA P-value: {p_value:.2e}\n")
        f.write(f"Significant device differences: {'YES (p < 0.05)' if p_value < 0.05 else 'NO (p >= 0.05)'}\n\n")
        
        f.write("DEVICE RANKINGS (by Shannon Entropy Mean)\n")
        f.write("-" * 80 + "\n")
        ranked = stats_df[['device', 'shannon_mean', 'shannon_std', 'shannon_count']].sort_values('shannon_mean', ascending=False)
        for idx, row in ranked.iterrows():
            f.write(f"  {idx+1:2}. {row['device']:15} - Mean: {row['shannon_mean']:.6f} ± {row['shannon_std']:.6f} (n={int(row['shannon_count']):,})\n")
        f.write("\n")
        
        f.write("DETAILED STATISTICS (All Metrics)\n")
        f.write("-" * 80 + "\n")
        for col in stats_df.columns:
            if col != 'device':
                f.write(f"{col}:\n")
        f.write(stats_df.to_string(index=False))
        f.write("\n\n")
        
        f.write("INTERPRETATION\n")
        f.write("-" * 80 + "\n")
        f.write("Higher entropy values indicate more randomness/encryption in traffic.\n")
        f.write("Lower entropy may indicate structured patterns, plaintext, or compression.\n")
        f.write("Different devices may show distinct entropy patterns based on their\n")
        f.write("communication protocols and encryption mechanisms.\n\n")
        
        f.write("OUTPUTS GENERATED\n")
        f.write("-" * 80 + "\n")
        f.write("Data files:\n")
        f.write("  - entropy_statistics.csv\n")
        f.write("Figures:\n")
        f.write("  - entropy_boxplots.pdf\n")
        f.write("  - entropy_distributions.pdf\n")
        f.write("  - entropy_heatmap.pdf\n")
        f.write("  - entropy_violins.pdf\n")
        f.write("  - entropy_scatter_correlation.pdf\n")
    
    print("  ✓ Report saved to entropy_analysis_report.txt")
    
    print("\n" + "=" * 80)
    print("✓ Analysis Complete!")
    print("=" * 80)
    print(f"\nOutputs saved to:")
    print(f"  Data: {DATA_DIR}/")
    print(f"  Figures: {FIGURES_DIR}/")


if __name__ == "__main__":
    main()
