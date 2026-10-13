"""
BrandShield AI - Mobile App Detection Engine (Model 3)
Integrates the trained Random Forest Android app risk classifier (Drebin NDSS 2014 benchmark)
with RapidFuzz developer entity verification, manifest permission analysis, and evidence separation.

CRITICAL ARCHITECTURAL CONSTRAINTS:
1. Singleton lazy-loader: Loads Model 3 into memory once on startup; does NOT retrain or reload per request.
2. Identical feature extraction: Directly uses mobile_app_features.py (215 features in exact Drebin order).
3. Zero Network & Zero Execution: Analyzes strictly offline lexical, structural, and declared manifest strings.
   Never downloads, unpacks, installs, or executes APK files.
4. Clear Separation: ML predictions represent statistical propensity and are strictly distinguished
   from verified deterministic evidence (e.g. Brand Registry developer verification, store domain checks).
5. Transparent Risk Categories:
   - High-risk indicators
   - Suspicious indicators
   - Lower-risk indicators
   - Insufficient data / model unavailable
"""

import json
import os
import re
import urllib.parse
import joblib
import numpy as np
from rapidfuzz import fuzz

import mobile_app_features

# Path to trained Model 3 artifact and benchmark metrics
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "mobile_app_model.joblib")
METRICS_PATH = os.path.join(os.path.dirname(__file__), "models", "mobile_app_metrics.json")

# Trusted / official app store hosts
OFFICIAL_APP_HOSTS = {
    "play.google.com", "market.android.com", "apps.apple.com", "itunes.apple.com"
}

# Max allowed input lengths for security and reliability
MAX_NAME_LEN = 150
MAX_DEV_LEN = 150
MAX_URL_LEN = 500
MAX_DESC_LEN = 5000

_cached_model = None
_cached_metrics = None

def get_mobile_model():
    """Load Model 3 artifact once into memory (Singleton caching)."""
    global _cached_model
    if _cached_model is None:
        if os.path.exists(MODEL_PATH):
            try:
                _cached_model = joblib.load(MODEL_PATH)
            except Exception as e:
                print(f"[ERROR] Failed to load Mobile App Model artifact: {e}")
                _cached_model = None
    return _cached_model

def get_app_metrics() -> dict:
    """Return evaluated benchmark metrics from training pipeline."""
    global _cached_metrics
    if _cached_metrics is None:
        if os.path.exists(METRICS_PATH):
            try:
                with open(METRICS_PATH, "r", encoding="utf-8") as f:
                    _cached_metrics = json.load(f)
            except Exception:
                _cached_metrics = None
    return _cached_metrics or {}

def is_model_available() -> bool:
    """Check if Model 3 is loaded and available for real-time inference."""
    return get_mobile_model() is not None

def validate_inputs(app_name: str, developer_name: str, store_url: str, description: str) -> tuple[bool, str, dict]:
    """
    Validate input parameters against safety bounds without executing network traffic.
    Returns (is_valid, error_message, sanitized_dict).
    """
    a_clean = str(app_name or "").strip()
    d_clean = str(developer_name or "").strip()
    u_clean = str(store_url or "").strip()
    desc_clean = str(description or "").strip()

    if not a_clean and not d_clean:
        return False, "Application title and developer/publisher name are required.", {}

    if not a_clean:
        return False, "Application title is required.", {}

    if not d_clean:
        return False, "Developer or publisher name is required.", {}

    # Length validations
    if len(a_clean) > MAX_NAME_LEN:
        return False, f"Application title exceeds maximum length of {MAX_NAME_LEN} characters.", {}
    if len(d_clean) > MAX_DEV_LEN:
        return False, f"Developer name exceeds maximum length of {MAX_DEV_LEN} characters.", {}
    if len(u_clean) > MAX_URL_LEN:
        return False, f"Store URL exceeds maximum length of {MAX_URL_LEN} characters.", {}
    if len(desc_clean) > MAX_DESC_LEN:
        return False, f"Description exceeds maximum length of {MAX_DESC_LEN} characters.", {}

    # Syntactic validation for URL
    is_official_store = False
    hostname = ""
    if u_clean:
        candidate = u_clean if u_clean.startswith(('http://', 'https://')) else 'https://' + u_clean
        try:
            parsed = urllib.parse.urlparse(candidate)
            hostname = (parsed.netloc or "").lower()
            if ":" in hostname:
                hostname = hostname.split(":")[0]
            is_official_store = any(hostname == h or hostname.endswith('.' + h) for h in OFFICIAL_APP_HOSTS)
        except Exception:
            hostname = ""

    sanitized = {
        "app_name": a_clean,
        "developer_name": d_clean,
        "store_url": u_clean,
        "description": desc_clean,
        "hostname": hostname,
        "is_official_store": is_official_store
    }
    return True, "", sanitized

def compare_with_brand_developers(developer_name: str, brand_dict: dict) -> dict:
    """
    Deterministic RapidFuzz string comparison against official Brand Registry verified developers.
    Kept strictly separate from the machine learning model prediction.
    """
    if not brand_dict:
        return {
            "has_brand_context": False,
            "target_brand": "",
            "is_verified_developer": False,
            "best_developer_match": "",
            "developer_similarity_pct": 0.0,
            "impersonation_flags": []
        }

    brand_name = brand_dict.get("name", "")
    verified_devs = [v.strip() for v in brand_dict.get("verified_developers", []) if v.strip()]
    clean_dev = developer_name.strip()

    is_verified = False
    best_sim = 0.0
    best_match = ""

    for vd in verified_devs:
        sim = float(fuzz.token_sort_ratio(clean_dev.lower(), vd.lower()))
        if sim > best_sim:
            best_sim = sim
            best_match = vd
        if sim >= 90.0:
            is_verified = True

    flags = []
    if is_verified:
        flags.append("VERIFIED_DEVELOPER_MATCH")
    elif verified_devs and best_sim >= 65.0:
        flags.append(f"DEVELOPER_NAME_TYPOSQUATTING_{int(best_sim)}PCT")
    elif verified_devs:
        flags.append("UNVERIFIED_THIRD_PARTY_DEVELOPER")

    return {
        "has_brand_context": True,
        "target_brand": brand_name,
        "is_verified_developer": is_verified,
        "best_developer_match": best_match,
        "developer_similarity_pct": round(best_sim, 1),
        "impersonation_flags": flags
    }

def analyze_app(app_data: dict, brand_dict: dict = None) -> dict:
    """
    Primary execution function for Model 3 Mobile App Risk Detection.
    
    Coordinates:
    1. Input validation & sanitization (Zero APK execution)
    2. Missing metadata detection
    3. Feature extraction (215 Drebin manifest features)
    4. Model 3 inference (RandomForestClassifier)
    5. RapidFuzz Brand Registry developer matching
    6. Transparent risk categorization & evidence separation
    """
    raw_app = app_data.get("app_name") or app_data.get("title") or ""
    raw_dev = app_data.get("developer_name") or app_data.get("developer") or ""
    raw_url = app_data.get("store_url") or app_data.get("url") or ""
    raw_desc = app_data.get("description") or app_data.get("desc") or ""

    # 1. Input Validation
    is_valid, err_msg, sanitized = validate_inputs(raw_app, raw_dev, raw_url, raw_desc)
    if not is_valid:
        return {
            "status": "invalid_input",
            "available": False,
            "risk_category": "INSUFFICIENT DATA / MODEL UNAVAILABLE",
            "summary_reason": err_msg,
            "ml_prediction": None,
            "verified_evidence": {},
            "indicators": [],
            "missing_data": ["app_name", "developer_name"],
            "limitation_message": "Invalid input. Analysis aborted."
        }

    # 2. Track Missing Metadata
    missing_fields = []
    if not sanitized["store_url"]:
        missing_fields.append("store_url")
    if not sanitized["description"]:
        missing_fields.append("app_description")
    if not app_data.get("permissions") and not app_data.get("requested_permissions"):
        missing_fields.append("explicit_permissions_list")

    # 3. Model 3 Inference (Cached Singleton)
    model = get_mobile_model()
    dev_comp = compare_with_brand_developers(sanitized["developer_name"], brand_dict)

    if model is None:
        return {
            "status": "model_unavailable",
            "available": False,
            "risk_category": "INSUFFICIENT DATA / MODEL UNAVAILABLE",
            "summary_reason": "Model 3 artifact (models/mobile_app_model.joblib) is not available. Run train_mobile_model.py to generate.",
            "ml_prediction": None,
            "verified_evidence": dev_comp,
            "indicators": [{"category": "System", "name": "Model 3 Offline", "severity": "Medium", "detail": "Model artifact not loaded."}],
            "missing_data": missing_fields,
            "limitation_message": "Machine learning prediction unavailable. Proceeding with heuristic developer checks only."
        }

    # 4. Feature Extraction (215 Drebin benchmark features)
    features_payload = {
        "app_name": sanitized["app_name"],
        "developer_name": sanitized["developer_name"],
        "store_url": sanitized["store_url"],
        "description": sanitized["description"],
        "package_name": app_data.get("package_name") or "",
        "permissions": app_data.get("permissions") or app_data.get("requested_permissions") or []
    }
    extracted = mobile_app_features.extract_app_features(features_payload)
    feature_vector = extracted["feature_vector"]
    X = np.array([feature_vector], dtype=np.float32)

    # Scikit-learn Random Forest Inference
    probs = model.predict_proba(X)[0]
    malware_prob = float(probs[1])
    benign_prob = float(probs[0])
    is_malware_suspect = bool(malware_prob >= 0.50)

    pred_label = "MALICIOUS / HIGH-RISK APK" if is_malware_suspect else "BENIGN / LOW-RISK APPLICATION"
    confidence_pct = round(max(malware_prob, benign_prob) * 100, 1)
    if confidence_pct >= 85.0:
        confidence_level = "HIGH"
    elif confidence_pct >= 65.0:
        confidence_level = "MEDIUM"
    else:
        confidence_level = "LOW"

    # 5. Extract Feature Attribution Indicators
    contributing_signals = []
    
    # Check detected dangerous permissions
    dang_perms = extracted.get("dangerous_permissions", [])
    if dang_perms:
        sev = "High" if len(dang_perms) >= 3 or any(p in ("SEND_SMS", "RECORD_AUDIO", "BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW") for p in dang_perms) else "Medium"
        contributing_signals.append({
            "category": "High-risk indicators" if sev == "High" else "Suspicious indicators",
            "name": "Sensitive Android Permissions Declared",
            "detail": f"{len(dang_perms)} dangerous permission(s) detected: {', '.join(dang_perms[:4])}",
            "severity": sev
        })

    # Check for high-risk SMS / telephony capability
    sms_perms = [p for p in dang_perms if "SMS" in p]
    if sms_perms:
        contributing_signals.append({
            "category": "High-risk indicators",
            "name": "SMS Messaging Capabilities",
            "detail": f"Manifest requests SMS interception/transmission: {', '.join(sms_perms)}",
            "severity": "High"
        })

    # Check package analysis keywords
    pkg_susp = extracted.get("package_analysis", {}).get("suspicious_keywords_found", [])
    if pkg_susp:
        contributing_signals.append({
            "category": "Suspicious indicators",
            "name": "Suspicious Package Name Lure",
            "detail": f"Package name contains suspicious token(s): {', '.join(pkg_susp)}",
            "severity": "Medium"
        })

    # Check distribution host
    if sanitized["store_url"] and not sanitized["is_official_store"]:
        contributing_signals.append({
            "category": "Suspicious indicators",
            "name": "Third-Party APK Distribution Mirror",
            "detail": f"Host '{sanitized['hostname']}' is an unofficial distribution mirror outside Google Play / App Store",
            "severity": "High"
        })

    # Check developer mismatch
    if dev_comp.get("has_brand_context") and not dev_comp.get("is_verified_developer"):
        contributing_signals.append({
            "category": "High-risk indicators",
            "name": "Publisher Entity Mismatch",
            "detail": f"Publisher '{sanitized['developer_name']}' does not match registered corporate developers for {dev_comp['target_brand']}",
            "severity": "High"
        })

    if not contributing_signals:
        contributing_signals.append({
            "category": "Lower-risk indicators",
            "name": "Standard Manifest & Permissions Baseline",
            "detail": "Application requests benign capability set without hazardous permissions",
            "severity": "Low"
        })

    # 6. Transparent Risk Category Definition
    if dev_comp.get("is_verified_developer") and sanitized["is_official_store"] and not is_malware_suspect:
        risk_category = "Lower-risk indicators"
        summary_reason = f"Authentic Mobile Listing: Verified publisher match ('{sanitized['developer_name']}') on official app store."
    elif dev_comp.get("has_brand_context") and not dev_comp.get("is_verified_developer") and (is_malware_suspect or not sanitized["is_official_store"]):
        risk_category = "High-risk indicators"
        summary_reason = f"High risk: Publisher mismatch with corporate registry for '{dev_comp['target_brand']}' combined with dangerous manifest profile."
    elif is_malware_suspect and malware_prob >= 0.70:
        risk_category = "High-risk indicators"
        summary_reason = f"High malware propensity ({malware_prob*100:.1f}%) based on Drebin static benchmark permission signature."
    elif is_malware_suspect or len([s for s in contributing_signals if s['severity'] in ('High', 'Medium')]) >= 2:
        risk_category = "Suspicious indicators"
        summary_reason = "Suspicious indicators detected; manifest analysis indicates elevated capability profile."
    elif len(missing_fields) >= 3 and not dev_comp["has_brand_context"]:
        risk_category = "Insufficient data / model unavailable"
        summary_reason = "Limited application metadata available; assessment based on title and developer strings."
    else:
        risk_category = "Lower-risk indicators"
        summary_reason = "Low risk. Application profile conforms to expected benign baseline."

    return {
        "status": "success",
        "available": True,
        "risk_category": risk_category,
        "summary_reason": summary_reason,
        "ml_prediction": {
            "model_name": "RandomForest Mobile App Risk Classifier (Model 3)",
            "benchmark_dataset": "Drebin Android Malware Benchmark (NDSS 2014)",
            "prediction_label": pred_label,
            "is_malware_suspect": is_malware_suspect,
            "malware_probability_pct": round(malware_prob * 100, 1),
            "benign_probability_pct": round(benign_prob * 100, 1),
            "confidence_pct": confidence_pct,
            "confidence_level": confidence_level,
            "features_evaluated_count": 215,
            "dangerous_permissions_detected": dang_perms
        },
        "verified_evidence": dev_comp,
        "indicators": contributing_signals,
        "missing_data": missing_fields,
        "feature_snapshot": {
            "total_permissions_count": extracted.get("total_permissions_count", 0),
            "dangerous_permissions_count": extracted.get("dangerous_permissions_count", 0),
            "dangerous_ratio": extracted.get("dangerous_ratio", 0.0),
            "is_official_store": sanitized["is_official_store"],
            "hostname": sanitized["hostname"],
            "package_name": extracted.get("package_analysis", {}).get("package_name", "")
        },
        "limitation_message": (
            "Model 3 predictions represent statistical classification based on the Drebin (NDSS 2014) static benchmark. "
            "A sensitive permission (such as Camera or Location) is common in legitimate enterprise apps and does not prove fraud alone. "
            "Analysis strictly inspects metadata and manifest strings without executing APK binaries."
        )
    }

def predict_app(app_data: dict, brand_name: str = "", verified_developers: list = None) -> dict:
    """Wrapper conforming to legacy interface for backward compatibility with detector callers."""
    brand_dict = {
        "name": brand_name,
        "verified_developers": verified_developers or []
    } if brand_name or verified_developers else None

    res = analyze_app(app_data, brand_dict)

    if not res.get("available"):
        return {
            "available": False,
            "status": res.get("status", "error"),
            "prediction": None,
            "is_malware_suspect": False,
            "malware_probability_pct": 0,
            "confidence_pct": 0,
            "confidence_level": "N/A",
            "contributing_features": [],
            "message": res.get("summary_reason", "Model unavailable")
        }

    ml = res.get("ml_prediction", {})
    return {
        "available": True,
        "status": "success",
        "prediction": ml.get("prediction_label"),
        "is_malware_suspect": ml.get("is_malware_suspect"),
        "malware_probability_pct": ml.get("malware_probability_pct"),
        "benign_probability_pct": ml.get("benign_probability_pct"),
        "confidence_pct": ml.get("confidence_pct"),
        "confidence_level": ml.get("confidence_level"),
        "contributing_features": [
            {"name": ind["name"], "impact": ind["detail"], "value": ind.get("severity", "Medium")}
            for ind in res.get("indicators", []) if ind.get("category") != "Lower-risk indicators"
        ],
        "feature_snapshot": res.get("feature_snapshot"),
        "dangerous_permissions": ml.get("dangerous_permissions_detected", []),
        "missing_data": res.get("missing_data"),
        "limitation_notice": res.get("limitation_message")
    }

def is_mobile_model_available() -> bool:
    return is_model_available()
