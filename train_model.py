"""
BrandShield AI - Machine Learning Training Pipeline
Trains a RandomForestClassifier on verified public phishing and legitimate URL datasets.
Saves model artifact and measured test evaluation metrics.

Workflow:
1. Load cleaned public dataset (UNB CIC-URL-2016 + PhishTank).
2. Verify class balance and check against data leakage.
3. Split into 80% train and 20% held-out test set (stratified).
4. Extract features using ml_features.py (identical to runtime inference).
5. Train scikit-learn RandomForestClassifier.
6. Evaluate held-out test set: Precision, Recall, F1, Accuracy, ROC-AUC, Confusion Matrix.
7. Save model artifact (models/phishing_rf_model.joblib) and measured metrics (models/model_metrics.json).
"""

import os
import sys
import json
import time
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

import ml_features
import download_dataset

BASE_DIR = os.path.dirname(__file__)
DATA_PATH = os.path.join(BASE_DIR, "data", "cleaned_urls.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_ARTIFACT_PATH = os.path.join(MODELS_DIR, "phishing_rf_model.joblib")
METRICS_JSON_PATH = os.path.join(MODELS_DIR, "model_metrics.json")
TEST_SAMPLES_PATH = os.path.join(BASE_DIR, "data", "test_samples.csv")

def ensure_model_dir():
    os.makedirs(MODELS_DIR, exist_ok=True)

def train_phishing_pipeline():
    ensure_model_dir()

    # Step 1: Ensure dataset is available
    if not os.path.exists(DATA_PATH):
        print("[*] Cleaned dataset not found. Downloading and assembling from public sources...")
        download_dataset.prepare_dataset(max_samples_per_class=5000)

    print(f"[*] Loading dataset from: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = df["label"].astype(int)

    # Global Deduplication check
    initial_count = len(df)
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    if len(df) < initial_count:
        print(f"[*] Removed {initial_count - len(df)} duplicate URL entries.")

    total_samples = len(df)
    benign_count = int(sum(df["label"] == 0))
    phishing_count = int(sum(df["label"] == 1))
    print(f"[*] Total dataset size: {total_samples}")
    print(f"    - Legitimate (Class 0): {benign_count} ({benign_count/total_samples*100:.1f}%)")
    print(f"    - Phishing   (Class 1): {phishing_count} ({phishing_count/total_samples*100:.1f}%)")

    # Step 2: Stratified Train/Test Split (80/20)
    print("\n[*] Splitting dataset into 80% train and 20% held-out test sets...")
    train_df, test_df = train_test_split(
        df, 
        test_size=0.20, 
        random_state=42, 
        stratify=df["label"]
    )
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    # Step 3: Leakage Audit
    train_urls_set = set(train_df["url"])
    test_urls_set = set(test_df["url"])
    leakage = train_urls_set.intersection(test_urls_set)
    if leakage:
        raise ValueError(f"FATAL: Data leakage detected! {len(leakage)} identical URLs found in both train and test.")
    print(f"[OK] Leakage Audit Passed: 0 overlap between training ({len(train_df)}) and testing ({len(test_df)}) sets.")

    # Step 4: Consistent Feature Extraction
    feature_names = ml_features.get_feature_names()
    print(f"\n[*] Extracting {len(feature_names)} lexical features for training URLs...")
    t0 = time.time()
    X_train_raw = [ml_features.extract_features_vector(u) for u in train_df["url"]]
    X_train = np.array(X_train_raw, dtype=np.float32)
    y_train = train_df["label"].to_numpy(dtype=np.int32)
    print(f"[OK] Training features extracted in {time.time() - t0:.2f}s (Shape: {X_train.shape})")

    print(f"[*] Extracting features for held-out testing URLs...")
    t1 = time.time()
    X_test_raw = [ml_features.extract_features_vector(u) for u in test_df["url"]]
    X_test = np.array(X_test_raw, dtype=np.float32)
    y_test = test_df["label"].to_numpy(dtype=np.int32)
    print(f"[OK] Test features extracted in {time.time() - t1:.2f}s (Shape: {X_test.shape})")

    # Step 5: Train RandomForestClassifier
    print("\n[*] Training scikit-learn RandomForestClassifier (100 estimators)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    t_train = time.time()
    clf.fit(X_train, y_train)
    train_duration = time.time() - t_train
    print(f"[OK] Model trained in {train_duration:.2f} seconds.")

    # Step 6: Comprehensive Held-out Evaluation
    print("\n" + "="*60)
    print("HELD-OUT TEST SET EVALUATION (Unseen Data)")
    print("="*60)
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    roc_auc = float(roc_auc_score(y_test, y_prob))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    print(f"Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
    print(f"Precision: {prec:.4f} ({prec*100:.2f}%)")
    print(f"Recall:    {rec:.4f} ({rec*100:.2f}%)")
    print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    print(f"ROC-AUC:   {roc_auc:.4f} ({roc_auc*100:.2f}%)")
    print("\nConfusion Matrix:")
    print(f"  True Negatives (Legitimate Correct):  {tn}")
    print(f"  False Positives (Legitimate Flagged): {fp}")
    print(f"  False Negatives (Phishing Missed):   {fn}")
    print(f"  True Positives  (Phishing Detected): {tp}")

    # Top Feature Importances
    importances = clf.feature_importances_
    feat_imp = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    top_features = [{"feature": f, "importance": round(float(imp), 4)} for f, imp in feat_imp]
    print("\nTop 8 Contributing URL Features:")
    for f, imp in feat_imp[:8]:
        print(f"  - {f:<24}: {imp:.4f}")

    # Step 7: Build Metrics Object
    metrics_summary = {
        "model_type": "RandomForestClassifier",
        "training_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_dataset_size": total_samples,
        "train_samples": len(train_df),
        "test_samples": len(test_df),
        "class_distribution": {
            "legitimate": benign_count,
            "phishing": phishing_count
        },
        "accuracy": round(acc, 4),
        "accuracy_pct": round(acc * 100, 2),
        "precision": round(prec, 4),
        "precision_pct": round(prec * 100, 2),
        "recall": round(rec, 4),
        "recall_pct": round(rec * 100, 2),
        "f1_score": round(f1, 4),
        "f1_score_pct": round(f1 * 100, 2),
        "roc_auc": round(roc_auc, 4),
        "roc_auc_pct": round(roc_auc * 100, 2),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp
        },
        "top_features": top_features,
        "dataset_sources": [
            "UNB Canadian Institute for Cybersecurity (CIC-URL-2016)",
            "PhishTank Open Verified Phishing Archive (online-valid.csv)"
        ],
        "license": "Open Access Academic & Defensive Cybersecurity"
    }

    # Step 8: Save Artifacts
    artifact = {
        "model": clf,
        "feature_names": feature_names,
        "metrics": metrics_summary,
        "created_at": datetime.now().isoformat(),
        "version": "1.0.0"
    }

    print(f"\n[*] Saving model artifact to: {MODEL_ARTIFACT_PATH}")
    joblib.dump(artifact, MODEL_ARTIFACT_PATH, compress=3)

    print(f"[*] Saving measured evaluation metrics to: {METRICS_JSON_PATH}")
    with open(METRICS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_summary, f, indent=2)

    # Save test samples with predictions for validation & tests
    test_eval_df = test_df.copy()
    test_eval_df["predicted"] = y_pred
    test_eval_df["phishing_prob"] = np.round(y_prob, 4)
    test_eval_df.to_csv(TEST_SAMPLES_PATH, index=False, encoding="utf-8")
    print(f"[*] Saved held-out test predictions to: {TEST_SAMPLES_PATH}")

    print("\n" + "="*60)
    print("[SUCCESS] Machine Learning Pipeline Execution Completed Successfully!")
    print("="*60)
    return metrics_summary

if __name__ == "__main__":
    train_phishing_pipeline()
