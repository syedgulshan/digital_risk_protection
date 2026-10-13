"""
BrandShield AI - Machine Learning Social Profile Feature Extraction Module
Extracts lexical, structural, and behavioral features from social profile inputs.

CRITICAL SAFETY & FAIRNESS:
1. Handles missing metadata safely (e.g. when follower counts or verification status are unknown).
2. Explicitly avoids assuming that unverified accounts, new accounts, or low follower counts prove fraud.
3. Used consistently during:
   - Training pipeline (train_social_model.py)
   - Real-time inference in Flask (profile_detector.py)
"""

import math
import re
from rapidfuzz import fuzz

# Suspicious keywords commonly seen in impersonator/bot usernames
SUSPICIOUS_USER_KEYWORDS = [
    'support', 'help', 'official', 'real', 'claim', 'giveaway', 'bot', 'service',
    'desk', 'care', 'team', 'bonus', 'crypto', 'refund', 'kyc', 'alert', 'verify',
    'assist', 'airdrop', 'rewards', 'dm_for_help', 'direct', 'hotline', 'unlock'
]

# Sensitive urgency and lure patterns in profile bios
BIO_LURE_PATTERNS = [
    r'send\s+(?:a\s+)?dm', r'dm\s+(?:us\s+)?for\s+(?:help|support|refund|unlock)',
    r'whatsapp\s+(?:us|number|helpline|support)', r'telegram\s+(?:bot|group|link|channel)',
    r'urgent\s+(?:account|kyc|verification|action)', r'claim\s+(?:your\s+)?(?:reward|bonus|airdrop|token)',
    r'free\s+(?:subscription|vip|crypto|cash)', r'account\s+(?:suspended|locked|unlocked)',
    r'seed\s+phrase', r'customer\s+care\s+(?:number|hotline|desk)', r'instant\s+refund',
    r'giveaway', r'bonus', r'airdrop'
]

# Exact ordered feature names for model compatibility
FEATURE_NAMES = [
    "username_length",
    "username_digits",
    "username_digit_ratio",
    "username_letters",
    "username_letter_ratio",
    "username_special_chars",
    "username_entropy",
    "username_has_consecutive_digits",
    "username_suspicious_keyword_count",
    "name_length",
    "name_digits",
    "name_digit_ratio",
    "name_special_chars",
    "name_word_count",
    "name_username_similarity",
    "bio_length",
    "bio_word_count",
    "bio_lure_keyword_count",
    "bio_has_url",
    "has_bio",
    "metadata_present",
    "statuses_count_log",
    "followers_count_log",
    "friends_count_log",
    "favourites_count_log",
    "listed_count_log",
    "reputation_ratio",
    "default_profile",
    "default_profile_image"
]

def get_feature_names() -> list[str]:
    """Return the exact ordered list of feature names used by the social ML model."""
    return list(FEATURE_NAMES)

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def extract_profile_features(profile_data: dict, mask_metadata: bool = False) -> dict[str, float]:
    """
    Extract a dictionary of numerical features from profile data.
    
    Args:
        profile_data: Dictionary containing profile fields:
            - screen_name / username: handle
            - name / profile_name: display name
            - description / bio: profile bio text
            - followers_count: optional int/float
            - friends_count: optional int/float
            - statuses_count: optional int/float
            - favourites_count: optional int/float
            - listed_count: optional int/float
            - default_profile: optional bool/int
            - default_profile_image: optional bool/int
        mask_metadata: If True, forces metadata fields to neutral defaults to simulate
                       partial/lexical-only input (used during training augmentation and testing).
                       
    Returns:
        Dictionary mapping each feature in FEATURE_NAMES to a float value.
    """
    # 1. Normalize Username / Handle
    raw_user = (profile_data.get('screen_name') or profile_data.get('username') or '')
    uname = str(raw_user).strip().lower().lstrip('@')
    
    u_len = float(len(uname))
    u_digits = float(sum(c.isdigit() for c in uname))
    u_digit_ratio = u_digits / max(u_len, 1.0)
    u_letters = float(sum(c.isalpha() for c in uname))
    u_letter_ratio = u_letters / max(u_len, 1.0)
    u_special_chars = float(sum(c in '_-.' for c in uname))
    u_entropy = float(shannon_entropy(uname))
    u_consec_digits = 1.0 if re.search(r'\d{3,}', uname) else 0.0
    u_kw_count = float(sum(1 for kw in SUSPICIOUS_USER_KEYWORDS if kw in uname))

    # 2. Display Name Features
    raw_name = (profile_data.get('name') or profile_data.get('profile_name') or '')
    name = str(raw_name).strip()
    n_len = float(len(name))
    n_digits = float(sum(c.isdigit() for c in name))
    n_digit_ratio = n_digits / max(n_len, 1.0)
    n_special = float(sum(not c.isalnum() and not c.isspace() for c in name))
    n_words = float(len(name.split())) if name else 0.0
    name_u_sim = float(fuzz.token_sort_ratio(name.lower(), uname) / 100.0) if (name and uname) else 0.0

    # 3. Description / Bio Features
    raw_bio = (profile_data.get('description') or profile_data.get('bio') or '')
    bio = str(raw_bio).strip()
    b_len = float(len(bio))
    b_words = float(len(bio.split())) if bio else 0.0
    b_lures = float(sum(1 for p in BIO_LURE_PATTERNS if re.search(p, bio, re.IGNORECASE)))
    b_has_url = 1.0 if any(u in bio.lower() for u in ['http', 't.me', 'bit.ly', 'wa.me', '.com', '.org']) else 0.0
    has_bio = 1.0 if b_len > 0 else 0.0

    # 4. Account Metadata Features (with safe handling of missing fields)
    followers_raw = profile_data.get('followers_count')
    friends_raw = profile_data.get('friends_count')
    has_meta = (
        not mask_metadata 
        and followers_raw is not None 
        and friends_raw is not None 
        and str(followers_raw).strip() != '' 
        and str(followers_raw).lower() not in ('none', 'nan', '')
    )

    if not has_meta:
        # FAIRNESS SAFEGUARD (Requirement 5):
        # Missing follower or friend counts NEVER imply fraud.
        # Impute with neutral population medians and set metadata_present = 0.0.
        metadata_present = 0.0
        statuses_log = 8.17      # Median: ~3,517 posts
        followers_log = 5.78     # Median: ~324 followers
        friends_log = 5.77       # Median: ~319 friends
        favourites_log = 6.40    # Median: ~601 likes
        listed_log = 1.10        # Median: ~2 lists
        rep_ratio = 0.50         # Balanced 50/50 reputation ratio
        def_prof = 0.0
        def_img = 0.0
    else:
        metadata_present = 1.0
        try:
            statuses = max(0.0, float(profile_data.get('statuses_count') or 0.0))
        except (ValueError, TypeError):
            statuses = 3517.0
        try:
            followers = max(0.0, float(followers_raw or 0.0))
        except (ValueError, TypeError):
            followers = 324.0
        try:
            friends = max(0.0, float(friends_raw or 0.0))
        except (ValueError, TypeError):
            friends = 319.0
        try:
            favourites = max(0.0, float(profile_data.get('favourites_count') or 0.0))
        except (ValueError, TypeError):
            favourites = 601.0
        try:
            listed = max(0.0, float(profile_data.get('listed_count') or 0.0))
        except (ValueError, TypeError):
            listed = 2.0

        statuses_log = float(math.log1p(statuses))
        followers_log = float(math.log1p(followers))
        friends_log = float(math.log1p(friends))
        favourites_log = float(math.log1p(favourites))
        listed_log = float(math.log1p(listed))
        
        rep_ratio = float(followers / max(followers + friends, 1.0))
        
        raw_dp = str(profile_data.get('default_profile', '0')).lower()
        def_prof = 1.0 if raw_dp in ['1', '1.0', 'true'] else 0.0
        
        raw_dpi = str(profile_data.get('default_profile_image', '0')).lower()
        def_img = 1.0 if raw_dpi in ['1', '1.0', 'true'] else 0.0

    return {
        "username_length": u_len,
        "username_digits": u_digits,
        "username_digit_ratio": u_digit_ratio,
        "username_letters": u_letters,
        "username_letter_ratio": u_letter_ratio,
        "username_special_chars": u_special_chars,
        "username_entropy": u_entropy,
        "username_has_consecutive_digits": u_consec_digits,
        "username_suspicious_keyword_count": u_kw_count,
        "name_length": n_len,
        "name_digits": n_digits,
        "name_digit_ratio": n_digit_ratio,
        "name_special_chars": n_special,
        "name_word_count": n_words,
        "name_username_similarity": name_u_sim,
        "bio_length": b_len,
        "bio_word_count": b_words,
        "bio_lure_keyword_count": b_lures,
        "bio_has_url": b_has_url,
        "has_bio": has_bio,
        "metadata_present": metadata_present,
        "statuses_count_log": statuses_log,
        "followers_count_log": followers_log,
        "friends_count_log": friends_log,
        "favourites_count_log": favourites_log,
        "listed_count_log": listed_log,
        "reputation_ratio": rep_ratio,
        "default_profile": def_prof,
        "default_profile_image": def_img
    }

def extract_feature_vector(profile_data: dict, mask_metadata: bool = False) -> list[float]:
    """
    Extract features in the exact order specified by FEATURE_NAMES.
    Returns a 1D list of floats for direct scikit-learn model inference.
    """
    feat_dict = extract_profile_features(profile_data, mask_metadata=mask_metadata)
    return [feat_dict[k] for k in FEATURE_NAMES]
