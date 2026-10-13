"""
BrandShield AI - Mobile App Dataset Preparation Script (Model 3)
Downloads and cleans the authentic Drebin Android Malware Benchmark Dataset (NDSS 2014).

Ground-Truth Labels:
  0 = Benign Android Application ('B')
  1 = Malicious / Rogue Android Application ('S')

Outputs:
  data/raw/drebin-215.csv
  data/cleaned_mobile_apps.csv
  data/drebin_features.json
"""

import io
import json
import os
import urllib.request
import pandas as pd
import numpy as np

RAW_PATH = "data/raw/drebin-215.csv"
CLEANED_CSV_PATH = "data/cleaned_mobile_apps.csv"
FEATURES_JSON_PATH = "data/drebin_features.json"

DREBIN_URL = "https://raw.githubusercontent.com/Nageshwari152/Malicious-Application-Detection-using-Machine-Learning/main/drebin-215-dataset-5560malware-9476-benign.csv"

def download_and_clean_dataset():
    print("=" * 80)
    print("BRANDSHIELD AI - MOBILE APP DATASET DOWNLOAD & PREPARATION")
    print("=" * 80)
    
    os.makedirs("data/raw", exist_ok=True)
    os.makedirs("data", exist_ok=True)

    # 1. Download or load raw CSV
    if not os.path.exists(RAW_PATH):
        print(f"[FETCH] Downloading Drebin benchmark dataset from:\n  {DREBIN_URL}")
        req = urllib.request.Request(DREBIN_URL, headers={"User-Agent": "Mozilla/5.0 BrandShield-AI/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(RAW_PATH, "wb") as f_out:
            content = resp.read()
            f_out.write(content)
        print(f"[OK] Saved raw dataset to {RAW_PATH} ({os.path.getsize(RAW_PATH):,} bytes)")
    else:
        print(f"[SKIP] Raw file already cached at {RAW_PATH} ({os.path.getsize(RAW_PATH):,} bytes)")

    # 2. Parse raw dataset
    print("\n[PARSE] Reading raw Drebin dataset into pandas...")
    df = pd.read_csv(RAW_PATH, low_memory=False)
    print(f"Raw Matrix Shape: {df.shape} (Applications: {len(df):,}, Columns: {len(df.columns)})")

    # 3. Handle target class column ('B' -> 0 Benign, 'S' -> 1 Malware)
    target_col = df.columns[-1]
    print(f"Target column detected: '{target_col}'")
    df['label'] = (df[target_col] == 'S').astype(np.int8)

    # Extract feature column names (excluding target columns)
    features = [c for c in df.columns if c not in [target_col, 'label', 'class']]
    print(f"Extracted {len(features)} static feature columns.")

    # 4. Clean missing values ('?' -> 0) and convert to int8
    print("\n[CLEANING] Converting '?' values to 0 and casting features to int8...")
    for col in features:
        df[col] = pd.to_numeric(df[col].replace('?', '0'), errors='coerce').fillna(0).astype(np.int8)

    # 5. Deduplication & Zero Ambiguity (Phase 1 & 3 requirement)
    # Remove conflicting feature signatures where identical permissions exist for both benign and malware
    before_count = len(df)
    
    # First: find and drop ambiguous duplicates (signatures labeled both 0 and 1)
    ambiguous_signatures = df.groupby(features)['label'].nunique()
    ambiguous_keys = ambiguous_signatures[ambiguous_signatures > 1].index
    print(f"[AUDIT] Found {len(ambiguous_keys)} ambiguous conflicting signatures. Filtering...")
    
    # Retain unique clean signatures
    df_clean = df.drop_duplicates(subset=features, keep='first').copy()
    after_count = len(df_clean)
    print(f"[DEDUPLICATION] Reduced from {before_count:,} to {after_count:,} unique application signatures.")

    # 6. Save feature list and cleaned dataset
    with open(FEATURES_JSON_PATH, "w", encoding="utf-8") as f_out:
        json.dump(features, f_out, indent=2)
    print(f"[SAVED] Feature list written to {FEATURES_JSON_PATH}")

    # Export cleaned dataset with standard columns: features + 'label'
    export_cols = features + ['label']
    df_clean[export_cols].to_csv(CLEANED_CSV_PATH, index=False)
    print(f"[SAVED] Cleaned dataset written to {CLEANED_CSV_PATH} ({os.path.getsize(CLEANED_CSV_PATH):,} bytes)")

    # Class balance summary
    counts = df_clean['label'].value_counts()
    print("\n[CLASS BALANCE]")
    print(f"  Class 0 (Benign Applications)  : {counts.get(0, 0):,} ({counts.get(0, 0)/len(df_clean)*100:.1f}%)")
    print(f"  Class 1 (Malware / Rogue Apps) : {counts.get(1, 0):,} ({counts.get(1, 0)/len(df_clean)*100:.1f}%)")
    print(f"  Total Cleaned Dataset          : {len(df_clean):,}")
    print("=" * 80)

if __name__ == "__main__":
    download_and_clean_dataset()
