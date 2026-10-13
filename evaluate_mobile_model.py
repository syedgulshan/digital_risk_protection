"""
BrandShield AI - Standalone Evaluation Script for Mobile App Model (Model 3)
Loads models/mobile_app_model.joblib and evaluates on the held-out test dataset (data/test_mobile_samples.csv).
Outputs actual measured precision, recall, F1, accuracy, ROC-AUC, and confusion matrix.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

MODEL_PATH = "models/mobile_app_model.joblib"
TEST_DATA_PATH = "data/test_mobile_samples.csv"

def run_evaluation():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file {MODEL_PATH} not found. Run train_mobile_model.py first.")
    if not os.path.exists(TEST_DATA_PATH):
        raise FileNotFoundError(f"Test data file {TEST_DATA_PATH} not found. Run train_mobile_model.py first.")

    print("=" * 80)
    print("BRANDSHIELD AI - MOBILE APP MODEL 3 HELD-OUT TEST EVALUATION REPORT")
    print("=" * 80)

    rf = joblib.load(MODEL_PATH)
    test_df = pd.read_csv(TEST_DATA_PATH, low_memory=False)
    print(f"Test Dataset Path : {TEST_DATA_PATH}")
    print(f"Test Sample Size  : {len(test_df):,} unique application profiles")
    print(f"Class Breakdown   : {test_df['label'].value_counts().to_dict()} (0=Benign, 1=Malware)")

    feature_cols = [c for c in test_df.columns if c != 'label']
    X_test = test_df[feature_cols].values
    y_test = test_df['label'].values

    preds = rf.predict(X_test)
    probs = rf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    auc = roc_auc_score(y_test, probs)
    cm = confusion_matrix(y_test, preds)

    print("\nACTUAL MEASURED BENCHMARK METRICS:")
    print("-" * 80)
    print(f"Accuracy           : {acc * 100:.2f}%  ({sum(preds == y_test)} / {len(y_test)} correct)")
    print(f"Precision (Malware): {prec * 100:.2f}%  ({cm[1][1]} / {cm[0][1] + cm[1][1]})")
    print(f"Recall (Sensitivity: {rec * 100:.2f}%  ({cm[1][1]} / {cm[1][0] + cm[1][1]})")
    print(f"F1-Score           : {f1 * 100:.2f}%")
    print(f"ROC-AUC Score      : {auc * 100:.2f}%  ({auc:.4f})")

    print("\nCONFUSION MATRIX:")
    print("-" * 80)
    print(f"True Negatives  (TN): {cm[0][0]:<5} (Benign apps correctly classified as Benign)")
    print(f"False Positives (FP): {cm[0][1]:<5} (Benign apps falsely flagged as Malicious)")
    print(f"False Negatives (FN): {cm[1][0]:<5} (Malicious apps missed as Benign)")
    print(f"True Positives  (TP): {cm[1][1]:<5} (Malicious apps correctly detected)")
    print("=" * 80)

if __name__ == "__main__":
    run_evaluation()
