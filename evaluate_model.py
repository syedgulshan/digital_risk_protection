"""
BrandShield AI - Standalone Model Evaluation Script
Loads the trained RandomForest artifact (models/phishing_rf_model.joblib)
and performs comprehensive evaluation against held-out test data.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

import ml_features

BASE_DIR = os.path.dirname(__file__)
MODEL_ARTIFACT_PATH = os.path.join(BASE_DIR, "models", "phishing_rf_model.joblib")
TEST_SAMPLES_PATH = os.path.join(BASE_DIR, "data", "test_samples.csv")
METRICS_JSON_PATH = os.path.join(BASE_DIR, "models", "model_metrics.json")

def evaluate_model():
    if not os.path.exists(MODEL_ARTIFACT_PATH):
        print(f"[ERROR] Model artifact not found at: {MODEL_ARTIFACT_PATH}")
        print("Please run 'python train_model.py' first.")
        return False

    print(f"[*] Loading model artifact: {MODEL_ARTIFACT_PATH}")
    artifact = joblib.load(MODEL_ARTIFACT_PATH)
    model = artifact["model"]
    feature_names = artifact.get("feature_names", ml_features.get_feature_names())
    metrics = artifact.get("metrics", {})

    print(f"[OK] Model loaded successfully: {model.__class__.__name__} (v{artifact.get('version', '1.0.0')})")
    print(f"     Trained: {artifact.get('created_at', 'Unknown')}")
    print(f"     Feature count: {len(feature_names)}")

    if os.path.exists(TEST_SAMPLES_PATH):
        print(f"\n[*] Evaluating on held-out test samples: {TEST_SAMPLES_PATH}")
        test_df = pd.read_csv(TEST_SAMPLES_PATH)
        X_test = [ml_features.extract_features_vector(u) for u in test_df["url"]]
        y_test = test_df["label"].values

        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

        print("\n" + "="*65)
        print("CLASSIFICATION REPORT ON HELD-OUT TEST DATA")
        print("="*65)
        print(classification_report(y_test, y_pred, target_names=["Benign (0)", "Phishing (1)"], digits=4))

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = [int(v) for v in cm.ravel()]
        print("CONFUSION MATRIX:")
        print(f"  True Negatives (Legitimate Correct):  {tn}")
        print(f"  False Positives (Legitimate Flagged): {fp}")
        print(f"  False Negatives (Phishing Missed):   {fn}")
        print(f"  True Positives  (Phishing Detected): {tp}")

        roc_auc = roc_auc_score(y_test, y_prob)
        print(f"\nROC-AUC Score: {roc_auc:.4f} ({roc_auc*100:.2f}%)")
    else:
        print("[!] test_samples.csv not found; displaying saved metrics:")
        print(json.dumps(metrics, indent=2))

    return True

if __name__ == "__main__":
    evaluate_model()
