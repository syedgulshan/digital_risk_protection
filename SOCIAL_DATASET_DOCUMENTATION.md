# Cresci et al. (2017) Social Profile & Bot Benchmark Dataset

## 1. Academic Origin and Source
The BrandShield AI Social Profile Machine Learning detection model is trained on the benchmark dataset published by **Stefano Cresci et al.** from the Institute for Informatics and Telematics (IIT), National Research Council (CNR), Pisa, Italy.

- **Primary Publication:**
  > Stefano Cresci, Roberto Di Pietro, Marinella Petrocchi, Angelo Spognardi, and Maurizio Tesconi.  
  > *"The Paradigm-Shift of Social Spambots: Evidence, Theories, and Tools for the Arms Race."*  
  > In **Proceedings of the 26th International Conference on World Wide Web Companion (WWW '17)**, pp. 963–972, 2017.  
  > DOI: [10.1145/3041021.3055135](https://doi.org/10.1145/3041021.3055135)

- **Official Repository & Project:**
  - CNR IIT MIB (Malignant Accounts Corpus) Project: `http://mib.projects.iit.cnr.it/`
  - Mirrored research subsets: `ashu273k/TrustNet` repository (`genuine_users.csv`, `spam_user.csv`).

---

## 2. License and Terms of Use
- **License Type:** Research & Academic Open Access.
- **Permitted Uses:** Academic research, security benchmarking, algorithm reproducibility, and educational cyber defense demonstrations.
- **Privacy Protections:** The dataset uses publicly scraped historical account metadata without capturing private direct messages, email addresses, phone numbers, or passwords.

---

## 3. Dataset Composition and Class Distribution

| Subset / Class | Raw Records | Cleaned & Deduplicated | Percentage | Ground-Truth Label |
| :--- | :--- | :--- | :--- | :--- |
| **Genuine Human Accounts** (`genuine_users.csv`) | 3,474 | 3,474 | 77.8% | `0` (Genuine Human) |
| **Social Spambot Accounts** (`spam_user.csv`) | 991 | 991 | 22.2% | `1` (Spam / Fake Account) |
| **Total Combined Dataset** | **4,465** | **4,465** | **100.0%** | Binary Classification |

### Data Split & Zero Leakage Protocol
To prevent data leakage and inflated evaluation metrics:
- **Training Set (80%):** 3,572 profiles (2,779 genuine, 793 spam) stored in memory with 30% random metadata masking for fairness.
- **Held-Out Test Set (20%):** 893 profiles (695 genuine, 198 spam) saved persistently to [`data/test_social_samples.csv`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/data/test_social_samples.csv).
- **Leakage Verification:** `set(train_ids) ∩ set(test_ids) = ∅` (0 overlapping IDs or screen names).

---

## 4. Feature Extraction Schema (29 Extracted Features)

All 29 features are computed deterministically via [`profile_features.py`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/profile_features.py):

| # | Feature Name | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 1 | `username_length` | Float | Character length of normalized handle (excluding `@`). |
| 2 | `username_digits` | Float | Count of numeric digit characters in handle. |
| 3 | `username_digit_ratio` | Float | Proportion of digits relative to handle length (`digits / max(len, 1)`). |
| 4 | `username_letters` | Float | Count of alphabetic characters in handle. |
| 5 | `username_letter_ratio` | Float | Proportion of letters relative to handle length. |
| 6 | `username_special_chars` | Float | Count of punctuation characters (`_`, `-`, `.`). |
| 7 | `username_entropy` | Float | Shannon entropy measuring character distribution unpredictability. |
| 8 | `username_has_consecutive_digits` | Binary (0/1) | Flag indicating $\ge 3$ consecutive digits in handle. |
| 9 | `username_suspicious_keyword_count`| Float | Matches against known impersonator keywords (`support`, `help`, `official`, etc.). |
| 10 | `name_length` | Float | Character length of profile display name. |
| 11 | `name_digits` | Float | Count of digits in display name. |
| 12 | `name_digit_ratio` | Float | Proportion of digits relative to display name length. |
| 13 | `name_special_chars` | Float | Count of special symbols in display name. |
| 14 | `name_word_count` | Float | Number of whitespace-separated tokens in display name. |
| 15 | `name_username_similarity` | Float (0.0-1.0) | RapidFuzz token sort ratio comparing display name to handle. |
| 16 | `bio_length` | Float | Character length of profile biography. |
| 17 | `bio_word_count` | Float | Word count of profile biography. |
| 18 | `bio_lure_keyword_count` | Float | Matches against urgency lures (`dm for help`, `telegram`, `airdrop`, `instant refund`). |
| 19 | `bio_has_url` | Binary (0/1) | Flag indicating destination links or domain references in bio. |
| 20 | `has_bio` | Binary (0/1) | Flag indicating presence of non-empty biography. |
| 21 | `metadata_present` | Binary (0/1) | Indicator showing whether numerical follower telemetry was supplied. |
| 22 | `statuses_count_log` | Float | Log-transformed post count: `log1p(statuses_count)`. |
| 23 | `followers_count_log` | Float | Log-transformed follower count: `log1p(followers_count)`. |
| 24 | `friends_count_log` | Float | Log-transformed following/friend count: `log1p(friends_count)`. |
| 25 | `favourites_count_log` | Float | Log-transformed likes given: `log1p(favourites_count)`. |
| 26 | `listed_count_log` | Float | Log-transformed public list memberships: `log1p(listed_count)`. |
| 27 | `reputation_ratio` | Float (0.0-1.0) | Network reputation ratio: `followers / max(followers + friends, 1.0)`. |
| 28 | `default_profile` | Binary (0/1) | Flag indicating unmodified default platform theme. |
| 29 | `default_profile_image` | Binary (0/1) | Flag indicating default silhouette / avatar placeholder. |

---

## 5. Fairness & Safe Missing-Field Safeguards

### Requirement 5 Enforcement:
> *"Handle missing platform-specific fields safely. Do not assume that low follower counts, new accounts, or lack of verification prove fraud."*

1. **Unverified Status is Never Fraud Evidence:**
   In the genuine benchmark split, over 99.6% of verified human accounts lacked a platform blue badge (`verified = NaN`). The model explicitly excludes verification status as a positive indicator of malice.
2. **Neutral Median Imputation:**
   When an analyst inputs a handle without follower or friend counts, the feature extractor sets `metadata_present = 0.0` and imputes neutral population medians (`followers = 324`, `friends = 319`, `reputation_ratio = 0.50`).
3. **Training Data Augmentation (30% Masking):**
   30% of training samples have their numerical metadata masked during training, forcing decision trees to learn robust lexical and semantic signals rather than over-relying on follower metrics.

---

## 6. Actual Measured Benchmark Results

Evaluated on **893 held-out test profiles** (695 genuine human accounts, 198 social spambots):

| Metric | Full Telemetry (Metadata Mode) | Lexical-Only Mode (Masked Metadata) |
| :--- | :--- | :--- |
| **Accuracy** | **98.32%** (878 / 893 correct) | **85.67%** (765 / 893 correct) |
| **Precision** | **96.92%** (189 / 195) | **65.09%** (151 / 232) |
| **Recall** | **95.45%** (189 / 198) | **76.26%** (151 / 198) |
| **F1-Score** | **96.18%** | **70.23%** |
| **ROC-AUC** | **98.85%** (0.9885) | **90.33%** (0.9033) |

### Confusion Matrix (Full Telemetry Mode):
- **True Negatives (TN):** `689` (Genuine accounts correctly recognized as genuine)
- **False Positives (FP):** `6` (Genuine accounts flagged as spam suspects)
- **False Negatives (FN):** `9` (Spambots misclassified as genuine)
- **True Positives (TP):** `189` (Spambots correctly identified)

---

## 7. Known Limitations & Operating Boundaries

1. **Platform Architecture Domain Shift:**
   The Cresci 2017 dataset was gathered from Twitter's v1.1 API. Modern platforms (Threads, Instagram, Telegram) feature different handle constraints and bio lengths.
2. **Evolution of Spambot Tactics:**
   Automated campaigns continually adapt handle naming strategies. Statistical patterns from 2017 must be supplemented by real-time RapidFuzz Brand Registry matching.
3. **Non-Conclusive Legal Status:**
   Machine learning predictions represent statistical likelihood, not legal proof of trademark infringement or criminal fraud. Definitive impersonation enforcement requires cross-referencing with authorized corporate Brand Registry records.
