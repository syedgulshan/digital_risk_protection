"""
BrandShield AI - Social Profile Dataset Preparation Script
Fetches and cleans genuine and spam social profiles from the Cresci et al. (2017) benchmark dataset.

Ground-Truth Labels:
  0 = Genuine Human Account
  1 = Social Spambot / Fake Impersonator Account

Output:
  data/cleaned_social_profiles.csv (combined, deduplicated dataset with standard schema)
"""

import os
import urllib.request
import pandas as pd

RAW_DIR = "data/social_raw"
CLEANED_CSV_PATH = "data/cleaned_social_profiles.csv"

DATASET_URLS = {
    "genuine_users.csv": "https://raw.githubusercontent.com/ashu273k/TrustNet/master/Datasets/genuine_users.csv",
    "spam_user.csv": "https://raw.githubusercontent.com/ashu273k/TrustNet/master/Datasets/spam_user.csv"
}

def download_raw_files():
    """Ensure raw benchmark files exist in data/social_raw/."""
    os.makedirs(RAW_DIR, exist_ok=True)
    for fname, url in DATASET_URLS.items():
        dest = os.path.join(RAW_DIR, fname)
        if not os.path.exists(dest):
            print(f"[FETCH] Downloading {fname} from {url}...")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 BrandShield-AI/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp, open(dest, "wb") as f_out:
                f_out.write(resp.read())
            print(f"[OK] Saved {fname} ({os.path.getsize(dest):,} bytes)")
        else:
            print(f"[SKIP] {fname} already cached ({os.path.getsize(dest):,} bytes)")

def clean_and_prepare_dataset():
    """Clean, standardize, and export labeled social profiles."""
    download_raw_files()
    
    gen_path = os.path.join(RAW_DIR, "genuine_users.csv")
    spam_path = os.path.join(RAW_DIR, "spam_user.csv")
    
    print("\n[PROCESS] Reading raw CSVs...")
    gen_df = pd.read_csv(gen_path, low_memory=False)
    spam_df = pd.read_csv(spam_path, low_memory=False)
    
    print(f"Raw Genuine Profiles: {len(gen_df):,}")
    print(f"Raw Spam Profiles   : {len(spam_df):,}")
    
    # Assign standard binary ground truth: 0 = Genuine, 1 = Spam
    gen_df['label'] = 0
    spam_df['label'] = 1
    
    # Standard columns of interest
    cols = [
        'id', 'screen_name', 'name', 'description', 'followers_count', 
        'friends_count', 'statuses_count', 'favourites_count', 'listed_count',
        'default_profile', 'default_profile_image', 'verified', 'label'
    ]
    
    # Filter to standard columns (safely filling missing)
    for c in cols:
        if c not in gen_df.columns:
            gen_df[c] = None
        if c not in spam_df.columns:
            spam_df[c] = None
            
    gen_clean = gen_df[cols].copy()
    spam_clean = spam_df[cols].copy()
    
    # Combine
    combined = pd.concat([gen_clean, spam_clean], ignore_index=True)
    
    # Drop rows without screen_name
    combined = combined.dropna(subset=['screen_name'])
    combined['screen_name'] = combined['screen_name'].astype(str).str.strip()
    
    # Global deduplication by unique ID and screen_name
    before_len = len(combined)
    combined = combined.drop_duplicates(subset=['id'], keep='first')
    combined = combined.drop_duplicates(subset=['screen_name'], keep='first')
    after_len = len(combined)
    print(f"[DEDUPLICATION] Dropped {before_len - after_len} duplicate records. Retained {after_len:,} profiles.")
    
    # Class balance summary
    counts = combined['label'].value_counts()
    print("\n[CLASS BALANCE]")
    print(f"  Class 0 (Genuine Human Accounts) : {counts.get(0, 0):,} ({counts.get(0, 0)/len(combined)*100:.1f}%)")
    print(f"  Class 1 (Spambots / Impersonators): {counts.get(1, 0):,} ({counts.get(1, 0)/len(combined)*100:.1f}%)")
    print(f"  Total Valid Profiles             : {len(combined):,}")
    
    os.makedirs(os.path.dirname(CLEANED_CSV_PATH), exist_ok=True)
    combined.to_csv(CLEANED_CSV_PATH, index=False)
    print(f"\n[DONE] Saved cleaned dataset to {CLEANED_CSV_PATH}")

if __name__ == "__main__":
    clean_and_prepare_dataset()
