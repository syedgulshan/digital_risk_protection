# 🛡️ BrandShield AI — Digital Risk Protection Platform
> **ByteXL Hackathon Challenge 3 Prototype**  
> Automated Brand Impersonation, Social Scams, Phishing Links & Rogue Mobile App Detection

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Backend-Flask%203.0-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Threat Intel](https://img.shields.io/badge/Threat%20Intel-VirusTotal%20API%20v3-blueviolet.svg)](https://docs.virustotal.com/reference/overview)
[![Fuzzy Engine](https://img.shields.io/badge/Matching-RapidFuzz%203.14-orange.svg)](https://github.com/maxbachmann/RapidFuzz)
[![Database](https://img.shields.io/badge/Database-SQLite%20(Parameterized)-green.svg)](https://www.sqlite.org/)
[![UI Style](https://img.shields.io/badge/Theme-Cyber%20Navy%20Dark-indigo.svg)](#design-system)

---

## 📌 Executive Summary & Problem Resolution

### 🎯 Key Bug Resolved: Fake vs. Genuine Profile URL Disambiguation
Previously, fake social profile URLs (e.g. `https://x.com/apexbank_scam_support`) and genuine profile URLs (e.g. `https://x.com/apexbank`) produced the exact same score because link checkers only inspected the top-level domain (`x.com`), which is always clean.

**How BrandShield AI now solves this:**
1. **Profile URL Slug Extraction:** Automatically decomposes social profile URLs across Twitter/X, Instagram, LinkedIn, Telegram, Facebook, TikTok, YouTube, Threads, and GitHub.
2. **RapidFuzz Brand Registry Comparison:** Extracts the account slug from the URL path and cross-checks it against registered corporate official handles (`official_handles`) and brand names.
3. **Domain vs. Profile Reputation Disambiguation (Rule 8):** Clearly differentiates between the host platform's clean domain reputation and the individual account's authenticity.
4. **Result Distinction:**
   - `https://x.com/apexbank` with ApexBank $\rightarrow$ **LOW RISK** (Verified official handle match).
   - `https://x.com/apexbank_scam_support` with ApexBank $\rightarrow$ **HIGH RISK** (Impersonating handle with unauthorized support lure keywords).

---

## 🔑 API Keys & Environment Configuration

BrandShield AI uses a `.env` file for secure credentials. **API keys are NEVER hardcoded or exposed in client-side HTML, JavaScript, logs, or Git.**

### 1. VirusTotal API v3 (Required for live external reputation lookups)
- **Purpose:** Checks URL and domain reputation across 85+ threat intelligence vendors.
- **Documentation:** [VirusTotal API v3 Overview](https://docs.virustotal.com/reference/overview)
- **Get a Free Key:** Register for free at [VirusTotal Community](https://www.virustotal.com/gui/join-us). Free tier provides 4 requests/min and 500 requests/day.
- **Variable Name:** `VIRUSTOTAL_API_KEY`

### 2. Google Gemini API (Optional for natural language bio explanations)
- **Purpose:** Provides executive natural-language threat summaries of suspicious bio descriptions.
- **Get a Free Key:** Generate an API key at [Google AI Studio](https://aistudio.google.com/).
- **Variable Name:** `GEMINI_API_KEY`
- *Note:* Gemini is only used as an explainer and **never as the sole fraud detector**.

### 3. Setting up `.env`
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Edit `.env` and insert your keys:
```env
VIRUSTOTAL_API_KEY=your_actual_virustotal_api_key_here
GEMINI_API_KEY=your_optional_gemini_api_key_here
FLASK_SECRET_KEY=brandshield-ai-hackathon-secure-secret-key-2026
```
*(If `VIRUSTOTAL_API_KEY` is left blank, the application functions normally using the local deterministic heuristic engine without crashing or fabricating fake API data.)*

---

## ⚡ Quick Start Guide (Windows PowerShell)

Follow these exact commands in **Windows PowerShell** to install dependencies, train the ML model, run tests, and launch the platform:

### 1. Open Windows PowerShell and navigate to the project root
```powershell
cd c:\Users\HP\OneDrive\Desktop\bytexl
```

### 2. (Optional) Create and activate a Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Required Dependencies
```powershell
python -m pip install -r requirements.txt
```

### 4. Train the Real Machine Learning Detection Models
Downloads authentic public datasets, cleans records, extracts features, and fits the scikit-learn `RandomForestClassifier` pipelines:
```powershell
# 1. Train URL Phishing Detection Model (10,000 URLs: UNB CIC-URL + PhishTank)
python train_model.py

# 2. Train Social Profile Impersonation/Bot Model (4,465 Profiles: Cresci et al. 2017)
python train_social_model.py

# 3. Train Mobile App Risk Analysis Model (7,257 Signatures: Drebin NDSS 2014)
python train_mobile_model.py
```
*Expected Outputs:*
- **URL Model:** `Accuracy: 97.75% | Precision: 98.09% | Recall: 97.40% | F1: 97.74% | ROC-AUC: 99.85%` $\to$ Saved to `models/phishing_rf_model.joblib`
- **Social Profile Model:** `Accuracy: 98.32% | Precision: 96.92% | Recall: 95.45% | F1: 96.18% | ROC-AUC: 98.85%` $\to$ Saved to `models/social_rf_model.joblib`
- **Mobile App Model:** `Accuracy: 95.73% | Precision: 88.95% | Recall: 93.60% | F1: 91.22% | ROC-AUC: 98.80%` $\to$ Saved to `models/mobile_app_model.joblib`

### 5. Evaluate the Trained Models on Held-out Test Data
Inspect complete classification reports, confusion matrices, and ROC-AUC scores on strictly unseen held-out test data:
```powershell
# Evaluate URL Phishing Model (2,000 held-out test URLs)
python evaluate_model.py

# Evaluate Social Profile Model (893 held-out test profiles)
python evaluate_social_model.py

# Evaluate Mobile App Risk Model (1,452 held-out test application profiles)
python evaluate_mobile_model.py
```

### 6. Run the Automated Test Suites
Run all dedicated ML pipeline tests and the overarching platform test suite:
```powershell
# 1. URL Phishing Machine Learning Tests (9 tests)
python -m unittest test_ml.py

# 2. Social Profile Machine Learning Tests (9 tests)
python -m unittest test_social_ml.py

# 3. Mobile App Machine Learning Tests (10 tests)
python -m unittest test_mobile_ml.py

# 4. Complete Platform Integration Test Suite (7 tests)
python test_platform.py
```

### 7. Launch the Web Application
```powershell
python app.py
```
*Expected Output:*
```text
 * Running on http://127.0.0.1:5000
```

### 8. Open in Browser
Visit **`http://127.0.0.1:5000/`** in any web browser.

---

## 🤖 Real Machine Learning Phishing Detection Pipeline

BrandShield AI incorporates a **trained `RandomForestClassifier`** for real-time lexical phishing detection without synthetic or fabricated data.

### 1. Public Training Dataset & Provenance
- **Legitimate / Benign URLs Source:** University of New Brunswick (UNB) — Canadian Institute for Cybersecurity (`CIC-URL-2016` dataset, Mamun et al.).
- **Phishing URLs Source:** PhishTank Open Anti-Phishing Community Database (`online-valid.csv`).
- **Dataset Size:** 10,000 verified unique URLs (5,000 Benign [Class 0], 5,000 Phishing [Class 1]).
- **License / Terms:** Open Access for academic research and defensive cybersecurity applications.
- **Detailed Documentation:** See [`DATASET_DOCUMENTATION.md`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/DATASET_DOCUMENTATION.md).

### 2. Lexical Feature Engineering ([`ml_features.py`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/ml_features.py))
Extracts 26 structural and statistical dimensions **offline without network traffic**:
- **Geometry:** URL length, hostname length, path length, query length.
- **Subdomains & Dots:** Number of subdomains, dot counts, excessive nesting.
- **Protocol & Transport:** HTTPS presence, port anomalies, cleartext HTTP.
- **Host Obfuscation:** Detection of raw IPv4/IPv6 addresses in destination host.
- **Character Distribution:** Digit count, digit ratio, letter ratio, special character counts (`@`, `-`, `_`, `=`, `?`, `&`, `%`, `~`).
- **Encoding Anomalies:** Percent-encoded hex tokens (`%20`, `%3D`, etc.).
- **URL Shorteners:** Recognition of redirector domains (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
- **Shannon Entropy:** Information entropy measuring string randomness (DGA pattern recognition).
- **Target Lures:** High-risk credential and security keywords (`login`, `verify`, `banking`, `secure`, `webscr`, `account`, `admin`).

### 3. Measured Held-Out Test Set Performance (Unseen Data)
Tested on 2,000 held-out test URLs with **zero train/test data leakage**:

| Evaluation Metric | Measured Score | Evaluation Notes |
| :--- | :--- | :--- |
| **Accuracy** | **97.75%** | 1,955 correct out of 2,000 held-out URLs |
| **Precision** | **98.09%** | Low false positive rate on legitimate URLs |
| **Recall** | **97.40%** | Catches 97.4% of evasive phishing URLs |
| **F1-Score** | **97.74%** | Harmonic mean of precision and recall |
| **ROC-AUC** | **99.85%** | Area under ROC curve demonstrating strong separability |
| **Confusion Matrix** | `TN=981, FP=19, FN=26, TP=974` | Full breakdown stored in `models/model_metrics.json` |

### 4. Defense-in-Depth Separation
The ML model functions as an independent detection pillar alongside:
- **VirusTotal API v3:** Real-time multi-vendor reputation intelligence.
- **RapidFuzz Brand Registry:** Levenshtein and token-set similarity matching against official corporate handles.
- **Deterministic Heuristic Rules:** Specific cybersecurity signal scoring.
- **Rule 8 Social Platform Notice:** Explicitly reminds security analysts that a clean domain reputation on a social platform (e.g. `x.com`) does NOT authenticate the profile handle.

---

## 👥 Real Machine Learning Social Profile Detection Pipeline

BrandShield AI incorporates a **separate, dedicated `RandomForestClassifier`** trained specifically for social profile bot, spam, and impersonation detection.

### 1. Public Training Dataset & Provenance
- **Dataset:** Cresci et al. (2017) Twitter Bot/Spam Benchmark Dataset (*"The Paradigm-Shift of Social Spambots: Evidence, Theories, and Tools for the Arms Race"*, ACM WWW 2017).
- **Source:** CNR IIT MIB (Malignant Accounts Corpus) & open research mirrors.
- **Dataset Size:** 4,465 authentic user accounts (3,474 Genuine Humans [Class 0], 991 Social Spambots [Class 1]).
- **License / Terms:** Research Open Access.
- **Detailed Documentation:** See [`SOCIAL_DATASET_DOCUMENTATION.md`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/SOCIAL_DATASET_DOCUMENTATION.md).

### 2. Profile Feature Engineering ([`profile_features.py`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/profile_features.py))
Extracts 29 numerical features capturing lexical, behavioral, and metadata signals:
- **Handle Structure:** Length, digits, digit ratio, letters, letter ratio, punctuation count, Shannon entropy, $\ge 3$ consecutive digits.
- **Impersonator & Urgency Keywords:** Matches against support, help, official, claim, giveaway, refund, kyc, and alert keywords.
- **Display Name Alignment:** Name length, token count, special characters, and RapidFuzz token similarity between display name and handle.
- **Bio Characteristics:** Bio length, word count, urgency lure matches (`dm for help`, `telegram`, `airdrop`, `instant refund`), external URLs.
- **Account Metadata Safeguards:** Log-scaled post, follower, friend, like, and list counts, network reputation ratio (`followers / (followers + friends)`), default theme and avatar flags.
- **Fairness Guarantee (Requirement 5):** When an analyst inputs a handle without follower counts, the feature extractor sets `metadata_present = 0.0` and imputes neutral population medians. Lack of followers or verification status is **never** assumed to prove fraud.

### 3. Measured Held-Out Test Set Performance (Unseen Data)
Tested on 893 held-out test profiles (695 genuine human accounts, 198 social spambots) with **zero train/test data leakage**:

| Evaluation Metric | Full Metadata Telemetry | Lexical-Only Mode (Missing Metadata) |
| :--- | :--- | :--- |
| **Accuracy** | **98.32%** (878 / 893 correct) | **85.67%** (765 / 893 correct) |
| **Precision** | **96.92%** (189 / 195) | **65.09%** (151 / 232) |
| **Recall** | **95.45%** (189 / 198) | **76.26%** (151 / 198) |
| **F1-Score** | **96.18%** | **70.23%** |
| **ROC-AUC** | **98.85%** (0.9885) | **90.33%** (0.9033) |
| **Confusion Matrix** | `TN=689, FP=6, FN=9, TP=189` | Full breakdown stored in `models/social_model_metrics.json` |

### 4. Architectural Separation Guarantee
The Social Profile ML model is loaded and stored separately from the URL model:
- URL Model Artifact: [`models/phishing_rf_model.joblib`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/models/phishing_rf_model.joblib)
- Social Profile Model Artifact: [`models/social_rf_model.joblib`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/models/social_rf_model.joblib)
- URL Inference Engine: [`ml_detector.py`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/ml_detector.py)
- Social Profile Inference Engine: [`social_profile_detector.py`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/social_profile_detector.py)
- In the UI and database, `profile_ml_findings` and `ml_findings` are kept strictly separate.

---

## 📱 Real Machine Learning Mobile App Risk Analysis Pipeline (Model 3)

BrandShield AI integrates a dedicated **`RandomForestClassifier`** trained on static Android manifest permissions and API signatures to detect malicious rogue APKs and trojanized mobile applications.

### 1. Public Training Dataset & Provenance
- **Dataset Name:** Drebin Android Malware Benchmark (NDSS 2014).
- **Authors:** Daniel Arp, Michael Spreitzenbarth, Malte Hübner, Hugo Gascon, Konrad Rieck.
- **Publication:** *DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket.* Proceedings of the Network and Distributed System Security Symposium (NDSS), 2014.
- **Dataset Size:** 7,257 unique application feature signatures after exact deduplication (5,537 Benign [Class 0], 1,720 Malware [Class 1]).
- **Detailed Documentation:** See [`MOBILE_APP_DATASET_DOCUMENTATION.md`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/MOBILE_APP_DATASET_DOCUMENTATION.md).

### 2. Static Manifest Feature Space ([`mobile_app_features.py`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/mobile_app_features.py))
Evaluates 215 static manifest dimensions **100% offline without downloading or executing APK files**:
- **Dangerous Permissions:** `SEND_SMS`, `READ_SMS`, `READ_PHONE_STATE`, `CAMERA`, `ACCESS_FINE_LOCATION`, `RECORD_AUDIO`, `INSTALL_PACKAGES`, `SYSTEM_ALERT_WINDOW`, `BIND_DEVICE_ADMIN`.
- **Suspicious API Signatures:** `attachInterface`, `android.os.Binder`, `onServiceConnected`, `transact`, `bindService`, `TelephonyManager.getDeviceId`, `TelephonyManager.getSubscriberId`.
- **System Actions & Receivers:** `BOOT_COMPLETED`, `PACKAGE_ADDED`, `PACKAGE_REPLACED`, `BATTERY_LOW`.
- **Package Lexical Inspection:** Detects cracked/mod lures (`mod`, `crack`, `unlimited`, `hack`, `injector`).

### 3. Measured Held-Out Test Set Performance (Unseen Data)
Tested on **1,452 unseen held-out applications** with zero data leakage:

| Evaluation Metric | Measured Score | Evaluation Notes |
| :--- | :---: | :--- |
| **Accuracy** | **95.73%** | 1,390 out of 1,452 unseen samples correctly classified |
| **Precision (Malware)** | **88.95%** | 322 true positives / 362 predicted positives |
| **Recall (Sensitivity)** | **93.60%** | 322 malware detected / 344 actual malware |
| **F1-Score** | **91.22%** | Harmonic mean of precision and recall |
| **ROC-AUC** | **98.80%** | Area under the Receiver Operating Characteristic curve |
| **Confusion Matrix** | `TN=1068, FP=40, FN=22, TP=322` | Full breakdown stored in `models/mobile_app_metrics.json` |

### 4. Architectural Separation Guarantee
The platform strictly isolates all three machine learning models:
- **Model 1 (Phishing URLs):** [`models/phishing_rf_model.joblib`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/models/phishing_rf_model.joblib) $\to$ [`ml_detector.py`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/ml_detector.py) $\to$ Column `ml_findings`
- **Model 2 (Social Profiles):** [`models/social_rf_model.joblib`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/models/social_rf_model.joblib) $\to$ [`social_profile_detector.py`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/social_profile_detector.py) $\to$ Column `profile_ml_findings`
- **Model 3 (Mobile Apps):** [`models/mobile_app_model.joblib`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/models/mobile_app_model.joblib) $\to$ [`mobile_app_detector.py`](file:///c:/Users/HP/OneDrive/Desktop/bytexl/mobile_app_detector.py) $\to$ Column `app_ml_findings`

---

## 🧪 How to Test Each Detection Result

The platform provides 1-click preset buttons on each inspection page for easy evaluation:

### 1. Test Social Profile URLs (Genuine vs. Fake)
- Go to: **`http://127.0.0.1:5000/link-checker`**
- **Test Case A (Genuine Profile URL):**
  - Brand: `ApexBank`
  - URL: `https://x.com/apexbank`
  - *Result:* **`LOW RISK`** (Score: 4/100). Recognized as authorized handle `@apexbank`.
- **Test Case B (Fake Impersonator Profile URL):**
  - Brand: `ApexBank`
  - URL: `https://x.com/apexbank_scam_support`
  - *Result:* **`HIGH RISK`** (Score: 75/100). Flagged for unauthorized brand stem and lure keywords `support` on legitimate platform `x.com`.

### 2. Test a Known-Safe Corporate Portal
- Go to: **`http://127.0.0.1:5000/link-checker`** (or click Preset 1)
- Brand: `VertexHealth`
- URL: `https://portal.vertexhealth.org/patient/login`
- *Result:* **`LOW RISK`** (Score: 3/100). Matches verified domain registry `vertexhealth.org` with valid HTTPS.

### 3. Test a Suspicious Look-alike Compound Domain
- Go to: **`http://127.0.0.1:5000/link-checker`** (or click Preset 4)
- Brand: `ApexBank`
- URL: `http://apexbank-login-secure.xyz/ebanking/verify`
- *Result:* **`HIGH RISK`** (Score: 94/100). Multi-factor flag: look-alike compound domain, high-risk `.xyz` TLD, insecure HTTP, and credential harvest path `/ebanking/verify`.

### 4. Test a Raw IP Credential Harvester
- Go to: **`http://127.0.0.1:5000/link-checker`** (or click Preset 5)
- Brand: `ApexBank`
- URL: `http://192.168.1.105:8080/apexbank/login`
- *Result:* **`HIGH RISK`** (Score: 88/100). Flagged for bare IP hostname, non-standard port `8080`, and credential login path.

### 5. Test Social Profile Handle / URL Discrepancy (Masquerading)
- Go to: **`http://127.0.0.1:5000/social-checker`** (or click Preset 3)
- Brand: `ApexBank`
- Username: `@apexbank` *(claims to be official)*
- Profile URL: `https://x.com/apexbank_fake_desk` *(routes to rogue account)*
- *Result:* **`HIGH RISK`** (Score: 75/100). Flagged for **Profile URL & Username Discrepancy (Masquerading)**.

---

## 📊 Standardized Risk Categories

The platform strictly differentiates 4 standardized risk categories:

| Category | Score Range | Meaning |
|---|---|---|
| **HIGH RISK** | 70 – 100 | Strong, multi-factor evidence of malicious intent or brand impersonation. |
| **SUSPICIOUS** | 40 – 69 | Multiple warning indicators requiring human review / watchlist addition. |
| **LOW RISK** | 0 – 39 | Limited or no warning indicators found; asset matches official registry. |
| **UNKNOWN / INSUFFICIENT DATA** | Indeterminate | Malformed input or missing brand context preventing reliable assessment. |

---

## 🗂️ Summary of Modified & Added Files

| File | Purpose of Modification |
|---|---|
| `virustotal.py` *(New)* | VirusTotal API v3 integration with base64 urlsafe IDs, caching, error handling (401, 404, 429, timeouts), and social platform domain disambiguation. |
| `gemini_explainer.py` *(New)* | Optional secondary Gemini API natural-language explainer for suspicious profile descriptions (never used as sole fraud detector). |
| `ml_detector.py` *(New)* | Model 1 inference engine for real-time lexical phishing URL detection with singleton caching. |
| `ml_features.py` *(New)* | Model 1 feature extractor computing 26 URL lexical and structural dimensions. |
| `train_model.py` / `evaluate_model.py` *(New)* | Model 1 training pipeline (UNB + PhishTank) and held-out evaluation runner. |
| `social_profile_detector.py` *(New)* | Model 2 inference engine for social bot/impersonation detection with RapidFuzz brand matching. |
| `profile_features.py` *(New)* | Model 2 feature extractor computing 29 profile metadata and bio lure signals. |
| `train_social_model.py` / `evaluate_social_model.py` *(New)* | Model 2 training pipeline (Cresci 2017) and held-out evaluation runner. |
| `mobile_app_detector.py` *(New)* | Model 3 inference engine for mobile app malware/risk detection with RapidFuzz developer verification. |
| `mobile_app_features.py` *(New)* | Model 3 feature extractor computing 215 Drebin Android manifest permissions and API signatures. |
| `download_mobile_dataset.py` *(New)* | Downloads Drebin Android dataset, cleans missing values, and deduplicates identical signatures. |
| `train_mobile_model.py` / `evaluate_mobile_model.py` *(New)* | Model 3 training pipeline (Drebin NDSS 2014) and held-out evaluation runner. |
| `MOBILE_APP_DATASET_DOCUMENTATION.md` *(New)* | Complete provenance, license, schema, and benchmark documentation for Model 3. |
| `test_mobile_ml.py` *(New)* | Automated test suite (10 unit tests) for Model 3 feature extraction, fairness, inference, and persistence. |
| `test_social_ml.py` *(New)* | Automated test suite (9 unit tests) for Model 2 feature extraction, fairness, inference, and persistence. |
| `test_ml.py` *(New)* | Automated test suite (9 unit tests) for Model 1 URL phishing detection. |
| `test_platform.py` *(Updated)* | Overarching platform integration test suite covering link, social, app, and brand endpoints. |
| `detector.py` *(Updated)* | Unified detection orchestrator integrating Model 1, Model 2, and Model 3 into separate, non-overlapping channels. |
| `database.py` *(Updated)* | SQLite schema migrations adding `ml_findings`, `profile_ml_findings`, and `app_ml_findings` columns. |
| `app.py` *(Updated)* | Flask application injecting ML status badges, routing scans, and exposing `/api/ml-metrics`, `/api/social-ml-metrics`, and `/api/app-ml-metrics`. |

---

## 🔒 Security Guarantees

1. **Zero-Execution Sandbox:** User-submitted links are inspected strictly through syntactic string parsing and threat database queries; they are **never fetched or loaded**.
2. **Credential Safety:** API keys are read exclusively from environment variables in `.env` and excluded via `.gitignore`.
3. **No Fabricated Data:** When `VIRUSTOTAL_API_KEY` is not configured, the platform clearly indicates this in the UI and proceeds using deterministic local heuristics without generating fake vendor flags.
4. **Rate Limit Protection:** In-memory and SQLite caching prevents redundant requests for the same URL or domain, conserving your free VirusTotal public quota.
