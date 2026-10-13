# BrandShield AI — Phishing URL Dataset Documentation

## 1. Overview & Provenance
To train a machine learning model for detecting phishing URLs, BrandShield AI utilizes verified, publicly available cybersecurity research datasets rather than synthetic or simulated data.

The training corpus is compiled from two established open-source cybersecurity repositories:

1. **Legitimate / Benign URLs Source:**
   - **Origin:** University of New Brunswick (UNB) — Canadian Institute for Cybersecurity (CIC).
   - **Dataset Citation:** *CIC-URL-2016 Dataset* (Mamun et al., Canadian Institute for Cybersecurity).
   - **Repository Mirror:** [Shreya Gopal Phishing Website Detection Corpus](https://github.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/tree/master/DataFiles/1.Benign_list_big_final.csv).
   - **Description:** Real-world legitimate URLs crawled across top-ranking Alexa and educational/corporate domains.
   - **License:** Open Access for academic, research, and cybersecurity education.

2. **Phishing / Malicious URLs Source:**
   - **Origin:** PhishTank Open Anti-Phishing Community Archive (`online-valid.csv`).
   - **Provider:** OpenDNS / Cisco Systems / PhishTank.
   - **Repository Mirror:** [PhishTank Verified Active Dataset](https://github.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/tree/master/DataFiles/2.online-valid.csv).
   - **Description:** Human-verified and automated-consensus malicious phishing URLs targeting banking institutions, social platforms, cloud providers, and digital wallets.
   - **License:** PhishTank Open Data Developer Agreement (permitted for defensive security applications).

---

## 2. Label Definitions
The model frames URL analysis as a binary classification task:

| Class Value | Canonical Label | Semantic Meaning |
| :--- | :--- | :--- |
| **`0`** | `BENIGN` | Legitimate, normal web address without structural phishing indicators. |
| **`1`** | `PHISHING` | Malicious or deceptive web address designed for credential harvesting, social engineering, or brand spoofing. |

---

## 3. Data Cleaning & Preprocessing Protocol
Before training, the dataset undergoes strict data hygienic procedures:

1. **URL Normalization:**
   - Trimming leading/trailing whitespace.
   - Stripping surrounding quotes or control characters.
   - Enforcing explicit scheme formatting (`http://` prefix prepended if protocol is omitted).
2. **De-duplication:**
   - Global string deduplication across both datasets to prevent duplicate and near-duplicate leakage between training and testing sets.
   - URL hash tracking to eliminate collisions.
3. **Class Balancing & Sampling:**
   - Balances legitimate and phishing classes (e.g., 5,000 to 10,000 verified samples per class for efficient and accurate training).
4. **Train / Test Partitioning:**
   - 80% Training Set, 20% Held-out Test Set.
   - Stratified sampling preserving class proportions (`random_state=42`).
   - Zero overlap: Held-out test samples are never exposed to the model during training.

---

## 4. Feature Engineering
Feature extraction is handled exclusively by [`ml_features.py`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/ml_features.py), ensuring 100% parity between training time and real-time Flask inference:

- **Lexical Dimensions:** URL total length, hostname length, path length, query length.
- **Subdomain Analysis:** Number of subdomains, presence of excessive dot delimiters.
- **Transport Security:** Presence of HTTPS protocol.
- **Host Obfuscation:** Detection of raw IPv4/IPv6 address in destination host.
- **Character Distribution:** Digit count, digit-to-length ratio, letter ratio, special character counts (`@`, `-`, `_`, `=`, `?`, `&`, `%`, `~`).
- **Encoding Anomalies:** Detection of percent-encoded sequences (`%20`, `%3D`, etc.).
- **URL Shorteners:** Recognition of known redirector domains (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
- **Information Entropy:** Shannon entropy calculation measuring randomness of URL string (identifies algorithmic DGA patterns).
- **Target Lures:** Count of high-risk phishing keywords (`login`, `verify`, `banking`, `secure`, `webscr`, `account`, `admin`).

---

## 5. Model Architecture
- **Algorithm:** `RandomForestClassifier` (scikit-learn ensemble).
- **Hyperparameters:** `n_estimators=100`, `max_depth=20`, `min_samples_split=5`, `class_weight='balanced'`, `random_state=42`.
- **Artifact:** Saved as `models/phishing_rf_model.joblib`.
- **Metrics Evaluated:** Accuracy, Precision, Recall, F1-Score, ROC-AUC, and Confusion Matrix on held-out test data.

---

## 6. Critical Limitations & Defense-in-Depth Rationale
Lexical machine learning is an essential detection pillar, but has well-documented cybersecurity limitations:

1. **Compromised Legitimate Domains:** Attackers who compromise a legitimate WordPress or university site will have benign domain lexical characteristics.
2. **Social Media Profiles:** A clean domain (`x.com`, `instagram.com`) does NOT guarantee that the individual account handle is authentic.
3. **Shortened URLs:** Lexical analysis flags shortener usage, but cannot inspect destination landing pages without safe unshortening.

**BrandShield Defense-in-Depth Solution:**
The ML model's output is strictly segregated as an independent intelligence signal alongside:
- **VirusTotal API v3:** Real-time multi-vendor reputation intelligence.
- **RapidFuzz Brand Registry:** Levenshtein and token-set similarity matching against official corporate handles.
- **Deterministic Heuristic Rules:** Specific cybersecurity signal scoring.
