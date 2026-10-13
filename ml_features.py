"""
BrandShield AI - Machine Learning URL Feature Extraction Module
Extracts lexical, structural, and statistical features from raw URLs.

CRITICAL SAFETY:
Strictly static, offline string parsing using urllib.parse and regex.
NEVER visits, connects to, or sends network traffic to submitted URLs.

Used identically during:
1. Training pipeline (train_model.py)
2. Real-time inference in Flask (ml_detector.py)
"""

import math
import re
import urllib.parse
from collections import Counter

# Known URL shortener domains commonly abused to disguise destination hosts
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
}

# Sensitive credential and security keywords frequent in phishing targets
SENSITIVE_PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "account", "update", "banking", "ebanking",
    "password", "credential", "wallet", "unlock", "confirm", "webscr",
    "authenticate", "support", "admin", "service", "claim"
]

# Regex pattern for IPv4 address in hostname
IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

# Regex pattern for hex percent encoding
PERCENT_ENCODING_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")

# Ordered list of extracted feature column names (strictly maintained for model compatibility)
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_subdomains",
    "has_https",
    "has_ip_address",
    "count_digits",
    "count_letters",
    "digit_ratio",
    "letter_ratio",
    "count_special_chars",
    "count_dots",
    "count_hyphens",
    "count_underscores",
    "count_slashes",
    "count_question_marks",
    "count_equals",
    "count_at",
    "count_ampersands",
    "count_percents",
    "suspicious_encoding",
    "is_shortened",
    "entropy",
    "num_path_tokens",
    "sensitive_keyword_count"
]

def get_feature_names() -> list[str]:
    """Return the exact ordered list of feature names used by the ML model."""
    return list(FEATURE_NAMES)

def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy (bits per character) of a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def sanitize_url(raw_url: str) -> str:
    """Safely sanitize URL string without network calls."""
    if not raw_url or not isinstance(raw_url, str):
        return ""
    cleaned = raw_url.strip()
    # Normalize scheme for structural parsing if missing
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "http://" + cleaned
    return cleaned

def extract_url_features(raw_url: str) -> dict:
    """
    Extract exact lexical and structural features from a URL string.
    
    Parameters:
        raw_url: The URL string to inspect.
        
    Returns:
        dict: Mapping of feature names to numerical values.
    """
    url = sanitize_url(raw_url)
    if not url:
        return {feat: 0.0 for feat in FEATURE_NAMES}

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        # Fallback for malformed URLs
        return {feat: 0.0 for feat in FEATURE_NAMES}

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower()

    # 1. Length features
    url_len = len(url)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    # 2. Hostname / subdomain structure
    host_parts = [p for p in hostname.split(".") if p]
    if len(host_parts) > 2:
        num_subdomains = len(host_parts) - 2
    else:
        num_subdomains = 0

    has_https = 1.0 if scheme == "https" else 0.0
    has_ip = 1.0 if IPV4_PATTERN.match(hostname) else 0.0

    # 3. Character counts & ratios
    count_digits = sum(c.isdigit() for c in url)
    count_letters = sum(c.isalpha() for c in url)
    digit_ratio = round(count_digits / max(url_len, 1), 4)
    letter_ratio = round(count_letters / max(url_len, 1), 4)

    # 4. Special character counts
    count_dots = url.count(".")
    count_hyphens = url.count("-")
    count_underscores = url.count("_")
    count_slashes = url.count("/")
    count_question_marks = url.count("?")
    count_equals = url.count("=")
    count_at = url.count("@")
    count_ampersands = url.count("&")
    count_percents = url.count("%")
    count_special_chars = sum(1 for c in url if not c.isalnum() and c not in [":", "/"])

    # 5. Suspicious encoding
    has_pct_encoding = 1.0 if PERCENT_ENCODING_PATTERN.search(url) or count_percents > 0 else 0.0

    # 6. URL shorteners
    is_short = 1.0 if hostname in KNOWN_SHORTENERS else 0.0

    # 7. Shannon entropy
    entropy = calculate_shannon_entropy(url)

    # 8. Path depth & sensitive keywords
    path_tokens = [t for t in path.split("/") if t]
    num_path_tokens = len(path_tokens)

    url_lower = url.lower()
    keyword_hits = sum(1 for kw in SENSITIVE_PHISHING_KEYWORDS if kw in url_lower)

    return {
        "url_length": float(url_len),
        "hostname_length": float(host_len),
        "path_length": float(path_len),
        "query_length": float(query_len),
        "num_subdomains": float(num_subdomains),
        "has_https": float(has_https),
        "has_ip_address": float(has_ip),
        "count_digits": float(count_digits),
        "count_letters": float(count_letters),
        "digit_ratio": float(digit_ratio),
        "letter_ratio": float(letter_ratio),
        "count_special_chars": float(count_special_chars),
        "count_dots": float(count_dots),
        "count_hyphens": float(count_hyphens),
        "count_underscores": float(count_underscores),
        "count_slashes": float(count_slashes),
        "count_question_marks": float(count_question_marks),
        "count_equals": float(count_equals),
        "count_at": float(count_at),
        "count_ampersands": float(count_ampersands),
        "count_percents": float(count_percents),
        "suspicious_encoding": float(has_pct_encoding),
        "is_shortened": float(is_short),
        "entropy": float(entropy),
        "num_path_tokens": float(num_path_tokens),
        "sensitive_keyword_count": float(keyword_hits)
    }

def extract_features_vector(raw_url: str) -> list[float]:
    """Extract ordered feature values as a float list matching FEATURE_NAMES."""
    feat_dict = extract_url_features(raw_url)
    return [feat_dict[name] for name in FEATURE_NAMES]
