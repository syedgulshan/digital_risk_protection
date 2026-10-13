# Mobile Application Risk Analysis Dataset Documentation (Model 3)

## BrandShield AI — Digital Risk Protection Platform
**Component:** Model 3 (Android Mobile Application Malware & Risk Classifier)  
**Academic Benchmark:** Drebin Android Malware Dataset (NDSS 2014)  
**Document Version:** 1.0.0  
**Classification:** Public Benchmark / Static Manifest & API Signature Analysis  

---

## 1. Dataset Provenance & Attribution

- **Dataset Name:** Drebin Android Malware Benchmark
- **Primary Authors:** Daniel Arp, Michael Spreitzenbarth, Malte Hübner, Hugo Gascon, Konrad Rieck
- **Academic Publication:**  
  *DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket.*  
  Proceedings of the Network and Distributed System Security Symposium (NDSS), 2014.  
  DOI: `10.14722/ndss.2014.23247`
- **Institutions:** University of Göttingen, TU Braunschweig, University of Erlangen-Nuremberg, Computer Emergency Response Team (CERT-Bund)
- **Public Repository / Distribution:** Hugging Face & Academic Research mirrors (`arunpshaji/drebin-android-malware-dataset`, `datasets/drebin`)
- **License:** Open Research & Academic Evaluation License (Permitted for educational, research, and non-commercial risk evaluation).

---

## 2. Collection Methodology & Dataset Ground Truth

The Drebin benchmark was created to advance machine learning on static Android manifest permissions, API calls, and intent filters without requiring dynamic APK execution in an emulated sandbox.

- **Raw Collection:** 15,036 application records spanning 215 static manifest features and API method signatures.
- **Benign Samples:** Applications collected from the Google Play Store across various categories (Finance, Utilities, Productivity, Games, Tools).
- **Malware Samples:** Verified malicious Android samples collected by the Drebin research consortium, spanning 178 malware families (e.g., FakeInstaller, DroidKungFu, Plankton, GinMaster, BaseBridge, Opfake, Kmin).
- **Ground Truth Verification:** Malware samples were cross-verified using multiple commercial antivirus engines on VirusTotal; benign samples exhibited zero detections across all engines.

---

## 3. Data Cleaning, Preprocessing & Deduplication

To ensure industrial-grade generalization and eliminate data leakage, the following preprocessing steps were applied:

1. **Missing Value Sanitization:** Replaced missing marker characters (`?`, `nan`, null) with `0.0`.
2. **Conflicting Label Resolution:** Identified and purged 3 contradictory records where identical feature vectors were labeled both benign and malicious.
3. **Exact Feature Deduplication:**
   - Raw records: 15,036 apps.
   - Deduped signatures: **7,257 unique application feature signatures**.
   - **Benign Apps (Class 0):** 5,537 samples (76.3%)
   - **Malware Apps (Class 1):** 1,720 samples (23.7%)
   - *Rationale:* Hundreds of basic utility applications (e.g., identical flashlight apps or wallpapers) share identical permission sets. Deduplicating on feature vectors ensures that identical signatures never appear in both training and test splits.
4. **Stratified Split (80/20):**
   - **Training Set:** 5,805 samples (4,429 benign, 1,376 malware)
   - **Held-Out Test Set:** 1,452 samples (1,108 benign, 344 malware)
   - No data from the held-out test set was used during model fitting or threshold selection.

---

## 4. Feature Space (215 Dimensions)

The model operates across 215 static binary features categorized into three primary Android manifest domains:

### A. Android Permissions (Manifest)
Standard and dangerous permissions requested by applications:
- `SEND_SMS`, `READ_SMS`, `RECEIVE_SMS`, `WRITE_SMS`
- `READ_PHONE_STATE`, `CALL_PHONE`, `READ_CALL_LOG`
- `READ_CONTACTS`, `WRITE_CONTACTS`, `GET_ACCOUNTS`
- `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`
- `CAMERA`, `RECORD_AUDIO`
- `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`
- `INSTALL_PACKAGES`, `SYSTEM_ALERT_WINDOW`, `BIND_DEVICE_ADMIN`

### B. Suspicious API Calls & Binder Invocations
Static byte-code signatures of sensitive Android runtime calls:
- `attachInterface`, `android.os.Binder`, `onServiceConnected`, `transact`, `bindService`
- `TelephonyManager.getDeviceId`, `TelephonyManager.getSubscriberId`, `TelephonyManager.getLine1Number`
- `Ljava.lang.Class.getCanonicalName`, `ClassLoader`, `DexClassLoader`, `PathClassLoader`
- `Runtime.getRuntime`, `Runtime.load`, `System.loadLibrary`
- `Ljavax.crypto.Cipher`, `Ljavax.crypto.spec.SecretKeySpec`

### C. Intent Actions & Receivers
System broadcast triggers monitored by applications:
- `android.intent.action.BOOT_COMPLETED` (persistence across reboots)
- `android.intent.action.PACKAGE_ADDED`, `PACKAGE_REPLACED`
- `android.intent.action.ACTION_POWER_CONNECTED`, `ACTION_POWER_DISCONNECTED`
- `android.intent.action.BATTERY_LOW`

---

## 5. Model Architecture & Hyperparameters

- **Algorithm:** `RandomForestClassifier` (`scikit-learn`)
- **Number of Estimators:** 100 decision trees
- **Max Depth:** 20
- **Min Samples Split:** 4
- **Min Samples Leaf:** 2
- **Class Weight:** `balanced` (mitigates 76:24 class imbalance)
- **Random State:** 42 (determinstic reproducibility)
- **Artifact Path:** `models/mobile_app_model.joblib` (5.2 MB)

---

## 6. Measured Benchmark Evaluation (Held-Out Test Set)

Evaluated on **1,452 unseen test applications** (1,108 Benign, 344 Malware):

| Metric | Measured Score | Evaluation Notes |
| :--- | :---: | :--- |
| **Accuracy** | **95.73%** | 1,390 out of 1,452 unseen samples correctly classified |
| **Precision (Malware)** | **88.95%** | 322 true positives / 362 predicted positives |
| **Recall (Sensitivity)** | **93.60%** | 322 malware detected / 344 actual malware |
| **F1-Score** | **91.22%** | Harmonic mean of precision and recall |
| **ROC-AUC** | **98.80%** | Area under the Receiver Operating Characteristic curve |

### Confusion Matrix
```
                     Predicted Benign (0)    Predicted Malware (1)
Actual Benign (0):          1,068 (TN)                40 (FP)
Actual Malware (1):            22 (FN)               322 (TP)
```

---

## 7. Top Discriminative Features (Feature Importance)

1. `attachInterface` (0.0639) — IPC binder hooking common in spyware/banking trojans.
2. `android.os.Binder` (0.0535) — Inter-process communication interface.
3. `onServiceConnected` (0.0526) — Remote service binding.
4. `transact` (0.0431) — Direct IPC transaction execution.
5. `TelephonyManager.getDeviceId` (0.0429) — IMEI/hardware fingerprint harvesting.
6. `Ljava.lang.Class.getCanonicalName` (0.0387) — Reflection-based class lookup.
7. `READ_PHONE_STATE` (0.0369) — Carrier and phone state inspection.
8. `ServiceConnection` (0.0298) — Service lifecycle tracking.
9. `bindService` (0.0293) — Background service orchestration.
10. `Ljava.lang.Class.cast` (0.0232) — Dynamic type casting.
11. `android.content.pm.Signature` (0.0229) — Signature verification tampering.
12. `TelephonyManager.getSubscriberId` (0.0226) — IMSI SIM card identification.
13. `SEND_SMS` (0.0217) — Premium SMS fraud and OTP interception.

---

## 8. Safety, Fairness & Operational Boundaries

### Zero APK Execution Guarantee
BrandShield AI conducts **100% static analysis** of submitted manifest metadata, package names, permissions, and developer strings. **At no point are APK binaries downloaded, executed, installed, or unpacked**.

### Fairness Safeguard
Legitimate enterprise applications (e.g., mobile banking, ride sharing, conferencing, photo editing) routinely require high-privilege permissions such as `CAMERA`, `ACCESS_FINE_LOCATION`, and `RECORD_AUDIO`. Model 3 evaluates multidimensional co-occurrence patterns across all 215 features rather than penalizing an application merely for requesting a standard Android capability.

### Evidence Separation
Predictions generated by Model 3 represent statistical likelihood of malicious characteristics. Statistical inference is strictly separated from deterministic brand verification (e.g. RapidFuzz comparison against the corporate Brand Registry's `verified_developers`).
