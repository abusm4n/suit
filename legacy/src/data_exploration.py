#!/usr/bin/env python3
"""
Data Exploration Utility

Quick script to explore and understand the available data in the
IoT Update Traffic repository.
"""

import os
import pandas as pd
import numpy as np
from pathlib import Path

class DataExplorer:
    def __init__(self):
        self.base_dir = os.path.expanduser("~/update_traffic")
        self.entropy_dir = os.path.join(self.base_dir, "controlled/entropy")
        self.stream_dir = os.path.join(self.base_dir, "controlled/stream")
        self.dataset_dir = os.path.join(self.base_dir, "controlled/dataset")
        self.firmware_dir = os.path.join(self.base_dir, "controlled/firmware")
        self.cve_dir = os.path.join(self.base_dir, "cve") 
        self.csv_dir = os.path.join(self.base_dir, "csv")
    
    def explore_entropy_data(self):
        """Explore entropy CSV files"""
        print("\n" + "="*70)
        print("ENTROPY DATA EXPLORATION")
        print("="*70)
        
        csv_files = [f for f in os.listdir(self.entropy_dir) if f.endswith('.csv')]
        print(f"\nEntropy CSV files found: {len(csv_files)}")
        
        for csv_file in sorted(csv_files):
            path = os.path.join(self.entropy_dir, csv_file)
            df = pd.read_csv(path)
            print(f"\n📄 {csv_file}")
            print(f"   Shape: {df.shape[0]} rows × {df.shape[1]} columns")
            print(f"   Columns: {', '.join(df.columns.tolist())}")
            print(f"   Size: {os.path.getsize(path) / 1024:.1f} KB")
            if df.shape[0] > 0:
                print(f"   Sample:\n{df.head(2).to_string(index=False)}")
    
    def explore_stream_data(self):
        """Explore stream size CSV files"""
        print("\n" + "="*70)
        print("STREAM SIZE DATA EXPLORATION")
        print("="*70)
        
        csv_files = [f for f in os.listdir(self.stream_dir) if f.endswith('.csv')]
        print(f"\nStream size CSV files found: {len(csv_files)}")
        
        for csv_file in sorted(csv_files):
            path = os.path.join(self.stream_dir, csv_file)
            df = pd.read_csv(path)
            print(f"\n📄 {csv_file}")
            print(f"   Shape: {df.shape[0]} rows × {df.shape[1]} columns")
            print(f"   Columns: {', '.join(df.columns.tolist())}")
            print(f"   Size: {os.path.getsize(path) / 1024:.1f} KB")
            if df.shape[0] > 0:
                print(f"   Sample:\n{df.head(2).to_string(index=False)}")
    
    def explore_cve_data(self):
        """Explore CVE data"""
        print("\n" + "="*70)
        print("CVE DATA EXPLORATION")
        print("="*70)
        
        # Check CVE directories
        for folder in os.listdir(self.cve_dir):
            folder_path = os.path.join(self.cve_dir, folder)
            if os.path.isdir(folder_path):
                files = os.listdir(folder_path)
                print(f"\n📁 {folder}/")
                print(f"   Files: {len(files)}")
                if files:
                    print(f"   Sample files: {', '.join(files[:3])}")
        
        # Check base CVE CSV
        base_path = os.path.join(self.csv_dir, "all_base.csv")
        if os.path.exists(base_path):
            df = pd.read_csv(base_path)
            print(f"\n📄 all_base.csv")
            print(f"   Shape: {df.shape[0]} rows × {df.shape[1]} columns")
            print(f"   Columns: {', '.join(df.columns.tolist())}")
            print(f"   Size: {os.path.getsize(base_path) / 1024:.1f} KB")
            if df.shape[0] > 0:
                print(f"   Sample:\n{df.head(2).to_string(index=False)}")
    
    def explore_dataset(self):
        """Explore raw dataset directory"""
        print("\n" + "="*70)
        print("RAW DATASET EXPLORATION")
        print("="*70)
        
        devices = os.listdir(self.dataset_dir)
        print(f"\nDevices in dataset: {len(devices)}")
        print(f"Device names: {', '.join(sorted([d for d in devices if os.path.isdir(os.path.join(self.dataset_dir, d))])[:10])}")
        
        total_size = 0
        pcap_count = 0
        for device in devices:
            device_path = os.path.join(self.dataset_dir, device)
            if os.path.isdir(device_path):
                for file in os.listdir(device_path):
                    if file.endswith('.pcap') or file.endswith('.pcapng'):
                        pcap_count += 1
                        total_size += os.path.getsize(os.path.join(device_path, file))
        
        print(f"\nTotal PCAP files: {pcap_count}")
        print(f"Total dataset size: {total_size / (1024**3):.2f} GB")
    
    def explore_firmware(self):
        """Explore firmware directory"""
        print("\n" + "="*70)
        print("FIRMWARE EXPLORATION")
        print("="*70)
        
        items = os.listdir(self.firmware_dir)
        dirs = [d for d in items if os.path.isdir(os.path.join(self.firmware_dir, d))]
        
        print(f"\nFirmware directories: {len(dirs)}")
        for d in dirs[:10]:
            path = os.path.join(self.firmware_dir, d)
            # Count files recursively
            file_count = sum([len(files) for _, _, files in os.walk(path)])
            print(f"  • {d} - {file_count} files")
    
    def data_statistics(self):
        """Provide data statistics summary"""
        print("\n" + "="*70)
        print("DATA STATISTICS SUMMARY")
        print("="*70)
        
        # Entropy statistics
        print("\nEntropy Data:")
        entropy_files = {}
        for device in ['dlink', 'eufy', 'sony_tv', 'tapo', 'xiaomi']:
            formatted_path = os.path.join(self.entropy_dir, f"{device}_formatted.csv")
            raw_path = os.path.join(self.entropy_dir, f"{device}.csv")
            
            if os.path.exists(formatted_path):
                df = pd.read_csv(formatted_path)
                entropy_files[device] = len(df)
            elif os.path.exists(raw_path):
                df = pd.read_csv(raw_path)
                entropy_files[device] = len(df)
        
        for device, count in sorted(entropy_files.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {device:12} - {count:6,} packets")
        
        # Stream statistics
        print("\nStream Size Data:")
        for csv_file in sorted(os.listdir(self.stream_dir)):
            if csv_file.endswith('.csv'):
                df = pd.read_csv(os.path.join(self.stream_dir, csv_file))
                device = csv_file.replace('_stream_sizes.csv', '')
                print(f"  • {device:12} - {len(df):6,} streams")
    
    def run_all(self):
        """Run all exploration methods"""
        print("\n" + "█"*70)
        print("   IoT UPDATE TRAFFIC - DATA EXPLORATION UTILITY")
        print("█"*70)
        
        self.explore_entropy_data()
        self.explore_stream_data()
        self.explore_cve_data()
        self.explore_dataset()
        self.explore_firmware()
        self.data_statistics()
        
        print("\n" + "="*70)
        print("EXPLORATION COMPLETE")
        print("="*70)
        print("\nNow you can:")
        print("  1. Run Experiment 1 (Entropy Comparison)")
        print("     → python3 src/experiments/entropy_comparison.py")
        print("     → jupyter notebook analysis_output/Experiment_1*.ipynb")
        print("\n  2. Explore data manually:")
        print("     → import pandas as pd")
        print(f"     → df = pd.read_csv('{self.entropy_dir}/tapo.csv')")
        print("     → df.describe()")
        print("\n  3. Review documentation:")
        print("     → Read PROJECT_ANALYSIS.md for experiment ideas")
        print("     → Read GETTING_STARTED.md for setup help")


if __name__ == "__main__":
    explorer = DataExplorer()
    explorer.run_all()
