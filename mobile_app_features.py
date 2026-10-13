"""
BrandShield AI - Mobile App Feature Extraction Module (Model 3)
Extracts static permission, API signature, and metadata features based on the Drebin Android benchmark.

CRITICAL SAFETY & FAIRNESS:
1. 100% static analysis: Never downloads, executes, or installs APK binaries.
2. Fairness Safeguard: Does NOT assume that requesting a sensitive permission proves malice.
   Legitimate banking, ride-sharing, and communication apps routinely request camera or location.
3. Feature ordering: Strictly preserves the 215 feature columns of the Drebin benchmark.
"""

import json
import os
import re
import urllib.parse

# Load the exact 215 Drebin feature column names
DREBIN_FEATURES_PATH = os.path.join(os.path.dirname(__file__), "data", "drebin_features.json")

if os.path.exists(DREBIN_FEATURES_PATH):
    with open(DREBIN_FEATURES_PATH, "r", encoding="utf-8") as f:
        DREBIN_FEATURE_NAMES = json.load(f)
else:
    # Fallback to empty list until download script runs
    DREBIN_FEATURE_NAMES = []

# High-risk / sensitive Android permissions (Android Dangerous Permission Groups)
DANGEROUS_PERMISSIONS = {
    "SEND_SMS", "READ_SMS", "RECEIVE_SMS", "WRITE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH",
    "READ_PHONE_STATE", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG", "ADD_VOICEMAIL",
    "USE_SIP", "PROCESS_OUTGOING_CALLS", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO", "CAMERA", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW",
    "WRITE_SETTINGS", "WRITE_SECURE_SETTINGS", "BIND_DEVICE_ADMIN", "PACKAGE_USAGE_STATS",
    "DEVICE_POWER", "REBOOT", "SET_PREFERRED_APPLICATIONS"
}

# Suspicious package name or title lures commonly seen in cracked / rogue APKs
SUSPICIOUS_PACKAGE_KEYWORDS = [
    "mod", "hack", "cheat", "crack", "bypass", "unlimited", "free", "premium_unlocked",
    "keygen", "injector", "bot", "auto_clicker", "patcher", "clone", "fake"
]

def get_feature_names() -> list[str]:
    """Return the exact ordered list of feature column names used by Model 3."""
    return list(DREBIN_FEATURE_NAMES)

def normalize_permission_name(perm: str) -> str:
    """Normalize permission strings (e.g. 'android.permission.SEND_SMS' -> 'SEND_SMS')."""
    p = str(perm or "").strip()
    if "." in p:
        p = p.split(".")[-1]
    return p.upper()

def parse_permissions_from_input(app_data: dict) -> set[str]:
    """
    Extract declared permissions from explicit lists or text descriptions.
    """
    perms = set()

    # 1. Check explicit list in app_data
    explicit_perms = app_data.get("permissions") or app_data.get("requested_permissions") or []
    if isinstance(explicit_perms, (list, tuple, set)):
        for p in explicit_perms:
            normalized = normalize_permission_name(p)
            if normalized:
                perms.add(normalized)
    elif isinstance(explicit_perms, str):
        for token in re.split(r"[\n,;|]+", explicit_perms):
            normalized = normalize_permission_name(token)
            if normalized:
                perms.add(normalized)

    # 2. Check description text for declared permissions or manifest lines
    desc = str(app_data.get("description") or "").upper()
    if desc:
        # Match standard android permission strings
        matches = re.findall(r"(?:ANDROID\.PERMISSION\.)?([A-Z_]{3,35})", desc)
        for m in matches:
            if m in DANGEROUS_PERMISSIONS or m in DREBIN_FEATURE_NAMES:
                perms.add(m)

        # Match natural-language permission disclosures in descriptions
        if "SMS" in desc or "TEXT MESSAGE" in desc:
            perms.add("SEND_SMS")
            perms.add("READ_SMS")
        if "CAMERA" in desc or "TAKE PICTURES" in desc:
            perms.add("CAMERA")
        if "LOCATION" in desc or "GPS" in desc:
            perms.add("ACCESS_FINE_LOCATION")
        if "MICROPHONE" in desc or "RECORD AUDIO" in desc:
            perms.add("RECORD_AUDIO")
        if "CONTACTS" in desc:
            perms.add("READ_CONTACTS")
        if "STORAGE" in desc or "SD CARD" in desc or "PHOTOS" in desc:
            perms.add("WRITE_EXTERNAL_STORAGE")
        if "DEVICE ADMIN" in desc or "ADMINISTRATOR" in desc:
            perms.add("BIND_DEVICE_ADMIN")
        if "OVERLAY" in desc or "DRAW OVER OTHER APPS" in desc:
            perms.add("SYSTEM_ALERT_WINDOW")
        if "ROOT" in desc or "ACCESSIBILITY" in desc:
            perms.add("WRITE_SECURE_SETTINGS")

    return perms

def extract_app_features(app_data: dict) -> dict:
    """
    Extract the 215-dimensional binary feature vector and rich metadata summary.
    
    Returns:
        dict with:
            - feature_vector: list of 215 floats (0 or 1) in exact DREBIN_FEATURE_NAMES order
            - feature_dict: map of feature_name -> 0 or 1
            - requested_permissions: list of normalized detected permissions
            - dangerous_permissions: list of detected dangerous permissions
            - total_permissions_count: int
            - dangerous_permissions_count: int
            - dangerous_ratio: float
            - missing_fields: list of missing metadata items
            - package_analysis: package name lexical checks
    """
    detected_perms = parse_permissions_from_input(app_data)
    
    # Track missing metadata
    missing_fields = []
    if not app_data.get("package_name") and not app_data.get("store_url"):
        missing_fields.append("package_name")
    if not app_data.get("developer_name"):
        missing_fields.append("developer_name")
    if not app_data.get("description"):
        missing_fields.append("app_description")
    if not detected_perms:
        missing_fields.append("declared_permissions")

    # Map to the 215 Drebin features
    feature_dict = {}
    feature_vector = []
    
    for feat_name in DREBIN_FEATURE_NAMES:
        val = 1.0 if feat_name in detected_perms else 0.0
        feature_dict[feat_name] = val
        feature_vector.append(val)

    # Calculate summary metrics
    dangerous_detected = [p for p in detected_perms if p in DANGEROUS_PERMISSIONS]
    total_perms = len(detected_perms)
    dangerous_count = len(dangerous_detected)
    dangerous_ratio = round(dangerous_count / max(total_perms, 1), 3) if total_perms > 0 else 0.0

    # Package name inspection (pure lexical parsing)
    raw_pkg = str(app_data.get("package_name") or "")
    if not raw_pkg and app_data.get("store_url"):
        # Attempt to extract id query param e.g. play.google.com/store/apps/details?id=com.app
        try:
            parsed = urllib.parse.urlparse(str(app_data.get("store_url")))
            qs = urllib.parse.parse_qs(parsed.query)
            if "id" in qs:
                raw_pkg = qs["id"][0]
        except Exception:
            pass

    pkg_suspicious = [kw for kw in SUSPICIOUS_PACKAGE_KEYWORDS if kw in raw_pkg.lower()]

    package_analysis = {
        "package_name": raw_pkg,
        "is_provided": bool(raw_pkg),
        "suspicious_keywords_found": pkg_suspicious,
        "token_count": len(raw_pkg.split(".")) if raw_pkg else 0
    }

    return {
        "feature_vector": feature_vector,
        "feature_dict": feature_dict,
        "requested_permissions": sorted(list(detected_perms)),
        "dangerous_permissions": sorted(dangerous_detected),
        "total_permissions_count": total_perms,
        "dangerous_permissions_count": dangerous_count,
        "dangerous_ratio": dangerous_ratio,
        "missing_fields": missing_fields,
        "package_analysis": package_analysis
    }
