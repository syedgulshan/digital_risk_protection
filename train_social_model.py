"""
BrandShield AI - Social Profile Machine Learning Training Pipeline
Trains a scikit-learn RandomForestClassifier on genuine vs. spam profiles from Cresci et al. (2017).

Fairness & Generalization Features:
1. Strict 80/20 train/test stratified split with 0 data leakage.
2. Training data augmentation with 20% metadata masking to ensure the model does NOT
   rely solely on follower counts or assume unverified accounts are fraudulent.
3. Feature extraction imported directly from profile_features.py (29 features).
4. Saves model artifact to models/social_rf_model.joblib.
5. Saves evaluation metrics to models/social_model_metrics.json.
"""

import json
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

import profile_features

CLEANED_DATA_PATH = "data/cleaned_social_profiles.csv"
TEST_DATA_PATH = "data/test_social_samples.csv"
MODEL_SAVE_PATH = "models/social_rf_model.joblib"
METRICS_SAVE_PATH = "models/social_model_metrics.json"

def train_and_evaluate():
    print("=" * 80)
    print("BRANDSHIELD AI - SOCIAL PROFILE RANDOM FOREST TRAINING PIPELINE")
    print("=" * 80)
    
    if not os.path.exists(CLEANED_DATA_PATH):
        raise FileNotFoundError(f"Cleaned dataset not found at {CLEANED_DATA_PATH}. Run download_social_dataset.py first.")
        
    df = pd.read_csv(CLEANED_DATA_PATH, low_memory=False)
    print(f"Loaded {len(df):,} total social profiles from {CLEANED_DATA_PATH}")
    
    # Stratified Train/Test Split (80% Train, 20% Held-Out Test)
    train_df, test_df = train_test_split(
        df, test_size=0.20, random_state=42, stratify=df['label']
    )
    
    # Audit zero data leakage
    train_ids = set(train_df['id'].dropna().astype(str))
    test_ids = set(test_df['id'].dropna().astype(str))
    leakage = train_ids.intersection(test_ids)
    assert len(leakage) == 0, f"DATA LEAKAGE DETECTED: {len(leakage)} overlapping IDs!"
    print(f"[SPLIT AUDIT] Train: {len(train_df):,} | Held-Out Test: {len(test_df):,} | Overlap: 0 (PASSED)")
    
    # Save held-out test dataset
    os.makedirs(os.path.dirname(TEST_DATA_PATH), exist_ok=True)
    test_df.to_csv(TEST_DATA_PATH, index=False)
    print(f"[PERSISTENCE] Held-out test set saved to {TEST_DATA_PATH}")
    
    # Extract training features with 30% random metadata masking for fairness
    print("\n[FEATURES] Extracting training feature vectors (with 30% metadata masking)...")
    np.random.seed(42)
    X_train = []
    y_train = train_df['label'].values
    
    for _, row in train_df.iterrows():
        mask = (np.random.rand() < 0.30)
        vec = profile_features.extract_feature_vector(row.to_dict(), mask_metadata=mask)
        X_train.append(vec)
        
    X_train = np.array(X_train, dtype=np.float32)
    print(f"Training Matrix Shape: {X_train.shape}")
    
    # Train Random Forest Classifier
    print("\n[TRAINING] Fitting RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42)...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    print("[TRAINING COMPLETE]")
    
    # Evaluate on Held-Out Test Set (Full Mode)
    print("\n[EVALUATION] Testing on held-out test dataset (Full metadata mode)...")
    X_test_full = np.array([
        profile_features.extract_feature_vector(row.to_dict(), mask_metadata=False)
        for _, row in test_df.iterrows()
    ], dtype=np.float32)
    y_test = test_df['label'].values
    
    preds_full = rf.predict(X_test_full)
    probs_full = rf.predict_proba(X_test_full)[:, 1]
    
    acc_full = float(accuracy_score(y_test, preds_full))
    prec_full = float(precision_score(y_test, preds_full))
    rec_full = float(recall_score(y_test, preds_full))
    f1_full = float(f1_score(y_test, preds_full))
    auc_full = float(roc_auc_score(y_test, probs_full))
    cm_full = confusion_matrix(y_test, preds_full).tolist()
    
    print("\n" + "=" * 60)
    print("HELD-OUT TEST RESULTS (FULL METADATA):")
    print(f"  Accuracy : {acc_full * 100:.2f}%")
    print(f"  Precision: {prec_full * 100:.2f}%")
    print(f"  Recall   : {rec_full * 100:.2f}%")
    print(f"  F1-Score : {f1_full * 100:.2f}%")
    print(f"  ROC-AUC  : {auc_full * 100:.2f}%")
    print("Confusion Matrix [[TN, FP], [FN, TP]]:")
    print(f"  TN: {cm_full[0][0]:<4} | FP: {cm_full[0][1]:<4}")
    print(f"  FN: {cm_full[1][0]:<4} | TP: {cm_full[1][1]:<4}")
    print("=" * 60)
    
    # Also evaluate on Held-Out Test Set with 100% Masked Metadata (Lexical-Only mode)
    print("\n[EVALUATION] Testing on held-out test dataset (Lexical-Only mode / Missing metadata)...")
    X_test_masked = np.array([
        profile_features.extract_feature_vector(row.to_dict(), mask_metadata=True)
        for _, row in test_df.iterrows()
    ], dtype=np.float32)
    
    preds_masked = rf.predict(X_test_masked)
    probs_masked = rf.predict_proba(X_test_masked)[:, 1]
    
    acc_masked = float(accuracy_score(y_test, preds_masked))
    prec_masked = float(precision_score(y_test, preds_masked))
    rec_masked = float(recall_score(y_test, preds_masked))
    f1_masked = float(f1_score(y_test, preds_masked))
    auc_masked = float(roc_auc_score(y_test, probs_masked))
    cm_masked = confusion_matrix(y_test, preds_masked).tolist()
    
    print(f"  Accuracy (Lexical-Only) : {acc_masked * 100:.2f}%")
    print(f"  Precision (Lexical-Only): {prec_masked * 100:.2f}%")
    print(f"  Recall (Lexical-Only)   : {rec_masked * 100:.2f}%")
    print(f"  F1-Score (Lexical-Only) : {f1_masked * 100:.2f}%")
    print(f"  ROC-AUC (Lexical-Only)  : {auc_masked * 100:.2f}%")
    
    # Feature Importances
    importances = rf.feature_importances_
    feat_names = profile_features.get_feature_names()
    sorted_idx = np.argsort(importances)[::-1]
    
    print("\nTop 10 Most Important Features:")
    top_features = []
    for rank, idx in enumerate(sorted_idx[:10], start=1):
        name = feat_names[idx]
        val = float(importances[idx])
        top_features.append({"name": name, "importance": round(val, 4)})
        print(f"  {rank:>2}. {name:<32}: {val:.4f}")
        
    # Persist model
    os.makedirs(os.path.dirname(MODEL_SAVE_PATH), exist_ok=True)
    joblib.dump(rf, MODEL_SAVE_PATH)
    print(f"\n[ARTIFACT] Saved model to {MODEL_SAVE_PATH} ({os.path.getsize(MODEL_SAVE_PATH):,} bytes)")
    
    # Persist metrics
    metrics_data = {
        "model_type": "RandomForestClassifier",
        "dataset": "Cresci et al. (2017) Twitter Bot/Spam Benchmark",
        "train_samples": len(train_df),
        "test_samples": len(test_df),
        "num_features": len(feat_names),
        "feature_names": feat_names,
        "hyperparameters": {
            "n_estimators": 100,
            "max_depth": 15,
            "min_samples_split": 4,
            "min_samples_leaf": 2,
            "class_weight": "balanced",
            "random_state": 42
        },
        "full_metadata_evaluation": {
            "accuracy": round(acc_full, 4),
            "precision": round(prec_full, 4),
            "recall": round(rec_full, 4),
            "f1_score": round(f1_full, 4),
            "roc_auc": round(auc_full, 4),
            "confusion_matrix": {
                "true_negatives": cm_full[0][0],
                "false_positives": cm_full[0][1],
                "false_negatives": cm_full[1][0],
                "true_positives": cm_full[1][1]
            }
        },
        "lexical_only_evaluation": {
            "accuracy": round(acc_masked, 4),
            "precision": round(prec_masked, 4),
            "recall": round(rec_masked, 4),
            "f1_score": round(f1_masked, 4),
            "roc_auc": round(auc_masked, 4),
            "confusion_matrix": {
                "true_negatives": cm_masked[0][0],
                "false_positives": cm_masked[0][1],
                "false_negatives": cm_masked[1][0],
                "true_positives": cm_masked[1][1]
            }
        },
        "top_features": top_features,
        "limitation_statement": (
            "Model predictions represent statistical propensity based on account characteristics "
            "and do not constitute definitive legal proof of fraud or impersonation without "
            "cross-referencing with registered brand credentials and platform verification badges."
        )
    }
    
    with open(METRICS_SAVE_PATH, "w", encoding="utf-8") as f_out:
        json.dump(metrics_data, f_out, indent=2)
    print(f"[METRICS] Saved benchmark metrics to {METRICS_SAVE_PATH}")
    print("\nTraining and evaluation pipeline completed successfully!")

if __name__ == "__main__":
    train_and_evaluate()
