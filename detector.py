"""
BrandShield AI - Detection Engine
Heuristic analysis, RapidFuzz string comparison, typosquatting & impersonation logic,
integrated with VirusTotal API v3 threat intelligence and optional Gemini explainer.
"""

import re
import urllib.parse
from rapidfuzz import fuzz
import virustotal
import gemini_explainer
import ml_detector
import social_profile_detector
import mobile_app_detector

# Common leetspeak and character substitution mappings
LEET_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', 
    '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
    '|': 'l', 'vv': 'w', 'rn': 'm'
}

# Suspicious keywords commonly seen in social impersonator handles & slugs
SOCIAL_SUSPICIOUS_KEYWORDS = [
    'support', 'help', 'helpdesk', 'care', 'service', 'assist', 'official',
    'real', 'verified', 'desk', 'center', 'centre', 'team', 'agent', 'security',
    'giveaway', 'airdrop', 'claim', 'refund', 'urgent', 'bonus', 'free', 'crypto',
    'wallet', 'whatsapp', 'telegram', 'dm_for_help', 'direct_message', 'hotline',
    'customer_service', 'priority', 'kyc', 'unlock', 'rewards', 'update', 'alert'
]

# Sensitive credentials/urgency terms in social bios
BIO_LURE_PATTERNS = [
    r'send\s+(?:a\s+)?dm', r'dm\s+(?:us\s+)?for\s+(?:help|support|refund|unlock)',
    r'whatsapp\s+(?:us|number|helpline|support)', r'telegram\s+(?:bot|group|link|channel)',
    r'urgent\s+(?:account|kyc|verification|action)', r'claim\s+(?:your\s+)?(?:reward|bonus|airdrop|token)',
    r'free\s+(?:subscription|vip|crypto|cash)', r'account\s+(?:suspended|locked|unlocked)',
    r'seed\s+phrase', r'customer\s+care\s+(?:number|hotline|desk)', r'instant\s+refund'
]

# High-risk / disposable TLDs frequently abused in brand phishing
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'click', 'rest',
    'icu', 'monster', 'fit', 'cc', 'work', 'loan', 'gdn', 'bar', 'surf', 'cam'
}

# Sensitive path keywords for phishing / credential harvesting
PATH_SENSITIVE_KEYWORDS = [
    'login', 'signin', 'sign-in', 'log-in', 'account', 'verify', 'verification',
    'security', 'banking', 'ebanking', 'portal', 'update', 'confirm', 'otp',
    'password', 'credential', 'wallet', 'unlock', 'session', 'auth', 'authorize',
    'recover', 'webscr', 'identity'
]

# High-risk keywords in mobile app listings
APP_RISK_KEYWORDS = [
    'root', 'accessibility', 'sms', 'read sms', 'otp', 'device admin',
    'bypass', 'unlimited money', 'instant loan without kyc', 'crypto bonus',
    'free tokens', 'telegram bot', 'private key', 'seed phrase', 'screen overlay',
    'miner', 'auto clicker', 'mod apk'
]

OFFICIAL_APP_HOSTS = [
    'play.google.com', 'apps.apple.com', 'apple.com', 'microsoft.com'
]

# Major social network domains and path structures
SOCIAL_PLATFORM_CONFIG = {
    'x.com': {'name': 'Twitter / X', 'path_prefix': '', 'min_parts': 1},
    'twitter.com': {'name': 'Twitter / X', 'path_prefix': '', 'min_parts': 1},
    'instagram.com': {'name': 'Instagram', 'path_prefix': '', 'min_parts': 1},
    'linkedin.com': {'name': 'LinkedIn', 'path_prefix': 'company', 'min_parts': 2},
    't.me': {'name': 'Telegram', 'path_prefix': '', 'min_parts': 1},
    'telegram.me': {'name': 'Telegram', 'path_prefix': '', 'min_parts': 1},
    'facebook.com': {'name': 'Facebook', 'path_prefix': '', 'min_parts': 1},
    'tiktok.com': {'name': 'TikTok', 'path_prefix': '', 'min_parts': 1},
    'youtube.com': {'name': 'YouTube', 'path_prefix': '', 'min_parts': 1},
    'threads.net': {'name': 'Threads', 'path_prefix': '', 'min_parts': 1},
    'github.com': {'name': 'GitHub', 'path_prefix': '', 'min_parts': 1}
}

NON_PROFILE_PATHS = {
    'about', 'login', 'signup', 'home', 'explore', 'messages', 'settings',
    'terms', 'privacy', 'help', 'search', 'notifications', 'i', 'hashtag',
    'legal', 'security', 'download', 'jobs', 'feed', 'share'
}

def normalize_text(text: str) -> str:
    """Normalize username/handle by stripping leading symbols, urls, and whitespace."""
    if not text:
        return ""
    text = text.lower().strip()
    
    # If a full URL was accidentally passed in the username field, extract the path handle
    if '://' in text or text.startswith(('x.com/', 'twitter.com/', 'instagram.com/')):
        info = extract_social_profile_info(text)
        if info and info.get("handle"):
            return info["handle"].lower()

    if text.startswith('@'):
        text = text[1:]
    # Remove query params or slashes if present
    text = text.split('?')[0].split('/')[0].strip()
    return text

def normalize_leetspeak(text: str) -> str:
    """Convert common leet substitutions to standard letters."""
    norm = text.lower()
    for leet, char in LEET_MAP.items():
        norm = norm.replace(leet, char)
    return norm

def extract_social_profile_info(url_or_text: str) -> dict:
    """
    Detects if a URL is hosted on a social media platform and extracts the profile handle.
    Example: 'https://x.com/apexbank_scam_support' -> platform='Twitter / X', handle='apexbank_scam_support'
    """
    if not url_or_text:
        return None
        
    raw = url_or_text.strip()
    if not raw.startswith(('http://', 'https://')):
        raw = 'https://' + raw

    try:
        parsed = urllib.parse.urlparse(raw)
        hostname = (parsed.hostname or "").lower()
        if hostname.startswith('www.'):
            hostname = hostname[4:]
    except Exception:
        return None

    matched_platform = None
    for domain, cfg in SOCIAL_PLATFORM_CONFIG.items():
        if hostname == domain or hostname.endswith('.' + domain):
            matched_platform = cfg
            break

    if not matched_platform:
        return None

    # Parse path to get handle
    path_parts = [p.strip() for p in parsed.path.split('/') if p.strip()]
    if not path_parts:
        return None

    # Skip non-profile utility routes
    if path_parts[0].lower() in NON_PROFILE_PATHS:
        return None

    handle = ""
    # Special case for LinkedIn e.g. /company/apexbank or /in/john
    if 'linkedin' in hostname:
        if len(path_parts) >= 2 and path_parts[0].lower() in ('company', 'in', 'school'):
            handle = path_parts[1]
        elif len(path_parts) >= 1:
            handle = path_parts[0]
    # YouTube e.g. /@apexbank or /c/apexbank
    elif 'youtube' in hostname:
        if path_parts[0].startswith('@'):
            handle = path_parts[0][1:]
        elif len(path_parts) >= 2 and path_parts[0].lower() in ('c', 'channel', 'user'):
            handle = path_parts[1]
        else:
            handle = path_parts[0]
    else:
        handle = path_parts[0]

    # Clean handle
    if handle.startswith('@'):
        handle = handle[1:]
    handle = handle.split('?')[0].split('&')[0].strip()

    if not handle or handle.lower() in NON_PROFILE_PATHS:
        return None

    return {
        "platform_name": matched_platform['name'],
        "domain": hostname,
        "handle": handle.lower(),
        "is_social": True
    }

def categorize_risk_score(score: int, is_insufficient: bool = False) -> str:
    """Standardize the four user-mandated categories."""
    if is_insufficient:
        return "UNKNOWN / INSUFFICIENT DATA"
    if score >= 70:
        return "HIGH RISK"
    elif score >= 40:
        return "SUSPICIOUS"
    else:
        return "LOW RISK"

# =========================================================================
# 1. SOCIAL PROFILE CHECKER
# =========================================================================
def analyze_social_profile(platform: str, profile_name: str, username: str, 
                           profile_url: str, description: str, brand_dict: dict,
                           profile_meta: dict = None) -> dict:
    """
    Analyzes a social media profile for impersonation, typosquatting, 
    and phishing heuristics against registered brand records.
    Consistently cross-references profile_url with username to eliminate false safe ratings.
    """
    clean_user = normalize_text(username)
    clean_name = profile_name.strip()
    clean_desc = (description or "").strip()
    brand_name = brand_dict.get("name", "") if brand_dict else ""
    norm_brand = normalize_text(brand_name)
    official_handles = [normalize_text(h) for h in brand_dict.get("official_handles", [])] if brand_dict else []
    official_domains = [d.lower().strip() for d in brand_dict.get("official_domains", [])] if brand_dict else []

    heuristic_findings = []
    total_score = 0
    reasons = []

    # If no brand is specified, we cannot perform reliable brand protection matching
    if not norm_brand and not official_handles:
        return {
            "risk_score": 50,
            "risk_category": "UNKNOWN / INSUFFICIENT DATA",
            "summary_reason": "No registered brand credentials available to perform comparative impersonation analysis.",
            "heuristic_findings": [{"name": "Insufficient Brand Context", "desc": "Provide or register a target brand to compare handles.", "severity": "Medium", "points": 50}],
            "api_findings": {"status": "unconfigured", "summary": "Awaiting brand registry target."},
            "indicators": [{"name": "Insufficient Brand Context", "desc": "Provide or register a target brand.", "severity": "Medium", "points": 50}],
            "recommendations": ["Select an official registered brand from the Brand Registry."]
        }

    # 1. Inspect Profile URL & Validate against submitted handle
    url_info = extract_social_profile_info(profile_url) if profile_url else None
    url_handle = url_info.get("handle") if url_info else ""
    url_domain = url_info.get("domain") if url_info else ""
    ml_findings = ml_detector.predict_url(profile_url) if profile_url else {"available": False, "status": "unsupported_input", "prediction": None, "message": "No profile URL provided."}

    # Evaluate Social Profile with dedicated Random Forest ML model (separate from URL ML)
    profile_payload = {
        "username": clean_user,
        "profile_name": clean_name,
        "description": clean_desc,
        "platform": platform
    }
    if profile_meta:
        profile_payload.update(profile_meta)
    profile_ml_findings = social_profile_detector.predict_profile(profile_payload, brand_name=brand_name)

    # Check for handle/URL discrepancy (Masquerading bypass attempt)
    if url_handle and clean_user and url_handle != clean_user:
        points = 45
        total_score += points
        heuristic_findings.append({
            "name": "Profile URL & Username Discrepancy",
            "desc": f"Submitted handle claims to be '@{clean_user}', but profile URL points to handle '/@{url_handle}' (Deceptive masquerading).",
            "severity": "High",
            "points": points
        })
        reasons.append(f"Profile URL handle '/@{url_handle}' conflicts with claimed handle '@{clean_user}'")

    # Evaluate the active handle (if URL provided, evaluate both clean_user and url_handle)
    target_handles_to_test = [clean_user]
    if url_handle and url_handle not in target_handles_to_test:
        target_handles_to_test.append(url_handle)

    # 2. Check if this is an authentic registered handle
    is_exact_official_match = (clean_user in official_handles)
    if url_handle:
        # If URL handle is not official, this CANNOT be a clean official match
        if url_handle not in official_handles:
            is_exact_official_match = False
        else:
            is_exact_official_match = True

    if is_exact_official_match:
        # Check if bio doesn't contain glaring anomalies
        has_bio_lure = any(re.search(pat, clean_desc.lower()) for pat in BIO_LURE_PATTERNS)
        if not has_bio_lure:
            recs = [
                "Profile handle corresponds to authenticated official brand registry.",
                "Maintain platform verification badge (checkmark) and active 2-Factor Authentication (2FA)."
            ]
            api_res = virustotal.check_url_virustotal(profile_url) if profile_url else {
                "status": "not_applicable",
                "summary": "Verified official handle.",
                "is_social_platform": True
            }
            return {
                "risk_score": 4,
                "risk_category": "LOW RISK",
                "summary_reason": f"Authentic Profile: Handle '@{clean_user}' is an exact match for {brand_name}'s official registered brand credentials.",
                "heuristic_findings": [
                    {
                        "name": "Verified Official Handle Match",
                        "desc": f"Username and profile URL match authorized records in {brand_name}'s corporate registry.",
                        "severity": "Low",
                        "points": 0
                    },
                    {
                        "name": "Clean Security Signals",
                        "desc": "No unauthorized support claims, credential solicitations, or deceptive external links detected.",
                        "severity": "Low",
                        "points": 4
                    }
                ],
                "api_findings": api_res,
                "ml_findings": ml_findings,
                "profile_ml_findings": profile_ml_findings,
                "indicators": [
                    {
                        "name": "Verified Official Handle Match",
                        "desc": f"Corresponds to authenticated registry for {brand_name}.",
                        "severity": "Low",
                        "points": 0
                    }
                ],
                "recommendations": recs
            }

    # 3. Impersonation & Typosquatting Analysis (RapidFuzz)
    # Test primary handle and url handle
    for test_handle in target_handles_to_test:
        if not test_handle:
            continue

        max_handle_sim = 0
        for h in official_handles:
            sim = fuzz.ratio(test_handle, h)
            if sim > max_handle_sim:
                max_handle_sim = sim

        brand_sim = fuzz.ratio(test_handle, norm_brand) if norm_brand else 0
        partial_brand_sim = fuzz.partial_ratio(norm_brand, test_handle) if norm_brand else 0

        # Leetspeak detection
        deleet_user = normalize_leetspeak(test_handle)
        is_leetspeak_spoof = False
        if deleet_user != test_handle and norm_brand:
            if (norm_brand in deleet_user or 
                fuzz.partial_ratio(norm_brand, deleet_user) >= 85 or 
                any(fuzz.partial_ratio(h, deleet_user) >= 85 for h in official_handles)):
                is_leetspeak_spoof = True

        if is_leetspeak_spoof:
            points = 35
            total_score += points
            heuristic_findings.append({
                "name": "Deliberate Leetspeak Homoglyph",
                "desc": f"Handle '@{test_handle}' uses character substitutions mimicking '{brand_name}' (normalized: '{deleet_user}').",
                "severity": "High",
                "points": points
            })
            reasons.append(f"Character substitution (leetspeak) targeting {brand_name}")
            break

        elif max_handle_sim >= 75 and test_handle not in official_handles:
            points = 32
            total_score += points
            heuristic_findings.append({
                "name": "High Handle Typosquatting Similarity",
                "desc": f"Handle '@{test_handle}' has {max_handle_sim:.0f}% similarity to an official handle without matching the registry.",
                "severity": "High",
                "points": points
            })
            reasons.append(f"Handle typosquatting ({max_handle_sim:.0f}% similarity)")
            break

        elif norm_brand and (norm_brand in test_handle or partial_brand_sim >= 85):
            points = 26
            total_score += points
            heuristic_findings.append({
                "name": "Brand Stem Embedding",
                "desc": f"Handle incorporates official brand stem '{brand_name}' without being a registered asset.",
                "severity": "Medium",
                "points": points
            })
            reasons.append("Unauthorized use of brand name in handle")
            break

    # 4. Check profile display name similarity
    if brand_name and clean_name:
        name_sim = fuzz.token_sort_ratio(brand_name, clean_name)
        if name_sim >= 85 and clean_user not in official_handles:
            points = 18
            total_score += points
            heuristic_findings.append({
                "name": "Display Name Impersonation",
                "desc": f"Display name '{clean_name}' closely resembles official brand '{brand_name}' ({name_sim:.0f}% match).",
                "severity": "Medium",
                "points": points
            })
            reasons.append("Profile display name closely mirrors brand name")

    # 5. Suspicious Keywords in Handle / URL Slug
    found_handle_keywords = set()
    for test_handle in target_handles_to_test:
        for kw in SOCIAL_SUSPICIOUS_KEYWORDS:
            if kw in test_handle:
                found_handle_keywords.add(kw)

    if found_handle_keywords:
        points = min(30, len(found_handle_keywords) * 15)
        total_score += points
        heuristic_findings.append({
            "name": "High-Risk Support / Lure Keywords in Handle",
            "desc": f"Handle includes social engineering words: {', '.join(sorted(found_handle_keywords))}.",
            "severity": "High" if ('support' in found_handle_keywords or 'help' in found_handle_keywords or 'claim' in found_handle_keywords) else "Medium",
            "points": points
        })
        reasons.append(f"Lure keywords in handle ({', '.join(sorted(found_handle_keywords))})")

    # 6. Profile Bio Social Engineering Lures
    bio_matches = []
    for pat in BIO_LURE_PATTERNS:
        match = re.search(pat, clean_desc.lower())
        if match:
            bio_matches.append(match.group(0))

    if bio_matches:
        points = min(28, len(bio_matches) * 14)
        total_score += points
        heuristic_findings.append({
            "name": "Deceptive Bio Lure Language",
            "desc": f"Bio contains coercive support/financial solicitations: '{bio_matches[0]}'.",
            "severity": "High",
            "points": points
        })
        reasons.append("Bio contains credential or financial solicitations")

    # 7. External Domain Mismatch in Bio or Links
    urls_in_bio = re.findall(r'https?://[^\s/$.?#].[^\s]*', clean_desc)
    detected_external_domains = []
    for u in urls_in_bio:
        try:
            p = urllib.parse.urlparse(u)
            if p.netloc:
                detected_external_domains.append(p.netloc.lower())
        except Exception:
            pass

    domain_mismatch_found = False
    mismatched_domain_name = ""
    for d in detected_external_domains:
        if virustotal.is_social_platform_domain(d):
            continue
        is_official = any(d == od or d.endswith('.' + od) for od in official_domains)
        if not is_official and official_domains:
            domain_mismatch_found = True
            mismatched_domain_name = d
            break

    if domain_mismatch_found:
        points = 24
        total_score += points
        heuristic_findings.append({
            "name": "External Unofficial Domain in Bio",
            "desc": f"Profile routes traffic to '{mismatched_domain_name}', distinct from registered official domains ({', '.join(official_domains)}).",
            "severity": "High",
            "points": points
        })
        reasons.append(f"Bio routes to unofficial domain '{mismatched_domain_name}'")

    # 8. VirusTotal External Intelligence Check
    api_findings = {}
    if profile_url:
        api_findings = virustotal.check_url_virustotal(profile_url)
    elif urls_in_bio:
        api_findings = virustotal.check_url_virustotal(urls_in_bio[0])
    else:
        api_findings = {
            "status": "unconfigured" if not virustotal.is_virustotal_configured() else "no_url",
            "summary": "VirusTotal API key is not configured in .env" if not virustotal.is_virustotal_configured() else "No external URL present to scan.",
            "is_flagged": False,
            "is_social_platform": bool(url_info)
        }

    # If VirusTotal flagged an external domain as malicious
    if api_findings.get("is_flagged"):
        points = 35
        total_score += points
        heuristic_findings.append({
            "name": "VirusTotal Malicious Reputation Detection",
            "desc": f"External intelligence flagged destination: {api_findings.get('summary')}.",
            "severity": "High",
            "points": points
        })
        reasons.append("External domain flagged in threat intelligence databases")

    # 9. Optional Gemini API Explainer for suspicious bio
    gemini_data = None
    if bio_matches and clean_desc:
        gemini_data = gemini_explainer.explain_suspicious_profile_bio(
            brand_name=brand_name,
            handle=clean_user,
            bio_text=clean_desc,
            detected_keywords=bio_matches
        )

    # 10. Incorporate Model 2 Social Profile ML Propensity
    if profile_ml_findings and profile_ml_findings.get("available"):
        ml_spam_prob = profile_ml_findings.get("spam_probability_pct", 0.0)
        is_bot = profile_ml_findings.get("is_spam_suspect", False)
        signals = profile_ml_findings.get("contributing_features", [])

        if is_bot or ml_spam_prob >= 50.0:
            pts = int(min(38, 22 + (ml_spam_prob - 50.0) * 0.35))
            total_score += pts
            heuristic_findings.append({
                "name": "Machine Learning Bot / Spam Propensity (Model 2)",
                "desc": f"RandomForest classifier flagged synthetic bot profile ({ml_spam_prob:.1f}% spam propensity).",
                "severity": "High" if ml_spam_prob >= 75.0 else "Medium",
                "points": pts
            })
            reasons.append(f"Model 2 bot propensity ({ml_spam_prob:.1f}%)")
        elif len(signals) >= 2 and any(s.get("value") in ("Medium", "High") for s in signals):
            pts = 16
            total_score += pts
            sig_names = [s.get("name") for s in signals[:2]]
            heuristic_findings.append({
                "name": "Automated Profile Signatures",
                "desc": f"Profile exhibits synthetic characteristics: {', '.join(sig_names)}.",
                "severity": "Medium",
                "points": pts
            })
            reasons.append(f"Synthetic characteristics ({', '.join(sig_names)})")

    # 11. Automated Bot Generator Pattern (Trailing Digits)
    match_digits = re.search(r'\d{3,}$', clean_user)
    if match_digits and not is_exact_official_match:
        digits_len = len(match_digits.group(0))
        pts = min(25, 14 + digits_len * 2)
        total_score += pts
        heuristic_findings.append({
            "name": "Automated Bot Naming Pattern (Trailing Digits)",
            "desc": f"Handle ends with a {digits_len}-digit numeric sequence ('{match_digits.group(0)}') characteristic of mass-generated bot accounts.",
            "severity": "Medium",
            "points": pts
        })
        reasons.append(f"Automated trailing digits ({match_digits.group(0)})")

    # 12. High Numeric Character Density
    if len(clean_user) > 0 and not is_exact_official_match:
        d_ratio = sum(c.isdigit() for c in clean_user) / len(clean_user)
        if d_ratio >= 0.35:
            pts = 16
            total_score += pts
            heuristic_findings.append({
                "name": "High Numeric Character Density",
                "desc": f"{d_ratio*100:.0f}% of handle characters are numeric digits, anomalous for organic brand accounts.",
                "severity": "Medium",
                "points": pts
            })
            reasons.append("High numeric character density")

    # 13. Cross-Brand Impersonation Detection
    try:
        import database as db_mod
        all_brands = db_mod.get_all_brands()
        for other_b in all_brands:
            if brand_dict and other_b.get("id") == brand_dict.get("id"):
                continue
            other_norm = normalize_text(other_b.get("name", ""))
            if other_norm and len(other_norm) >= 4 and other_norm in clean_user:
                pts = 35
                total_score += pts
                heuristic_findings.append({
                    "name": f"Cross-Brand Impersonation ({other_b['name']})",
                    "desc": f"Handle incorporates name of registered brand '{other_b['name']}', conflicting with selected target brand '{brand_name}'.",
                    "severity": "High",
                    "points": pts
                })
                reasons.append(f"Cross-brand impersonation of '{other_b['name']}'")
                break
    except Exception:
        pass

    # Calculate final score and category
    if not heuristic_findings:
        total_score = 12
        heuristic_findings.append({
            "name": "Independent Profile Asset",
            "desc": "Handle does not exhibit known brand typosquatting patterns, deceptive keywords, or credential lures.",
            "severity": "Low",
            "points": 12
        })
        summary_reason = "Low impersonation risk. No deceptive markers or typosquatting patterns identified."
    else:
        total_score = max(5, min(99, total_score))
        summary_reason = "; ".join(reasons) if reasons else "Multiple heuristic indicators identified."

    risk_category = categorize_risk_score(total_score)
    recommendations = generate_social_recommendations(risk_category, brand_name, clean_user, platform, heuristic_findings)

    return {
        "risk_score": total_score,
        "risk_category": risk_category,
        "summary_reason": summary_reason,
        "heuristic_findings": heuristic_findings,
        "api_findings": api_findings,
        "ml_findings": ml_findings,
        "profile_ml_findings": profile_ml_findings,
        "indicators": heuristic_findings,  # Backward compatibility
        "gemini_explanation": gemini_data.get("explanation") if gemini_data else None,
        "recommendations": recommendations,
        "profile_url_info": url_info
    }

def generate_social_recommendations(risk_cat: str, brand: str, user: str, platform: str, indicators: list) -> list:
    recs = []
    if risk_cat == "HIGH RISK":
        recs.append(f"File an immediate impersonation and trademark takedown report with {platform}'s Trust & Safety center.")
        recs.append(f"Publish a community warning on official {brand} channels cautioning followers against fake handle '@{user}'.")
        recs.append("Add the handle to the brand threat intelligence watchlist for domain phishing correlations.")
    elif risk_cat == "SUSPICIOUS":
        recs.append(f"Monitor handle '@{user}' for potential phishing links, profile image modifications, or DM spam.")
        recs.append(f"Submit a brand trademark inquiry to verify if this account is an affiliated partner or unapproved agent.")
        recs.append("Check platform follower growth and engagement activity periodically.")
    else:
        recs.append("No immediate takedown necessary. Continue passive digital footprint monitoring.")
        recs.append("Ensure your organization's official brand registry details remain up to date.")
    return recs

# =========================================================================
# 2. SUSPICIOUS LINK CHECKER
# =========================================================================
def analyze_suspicious_link(submitted_url: str, brand_dict: dict = None) -> dict:
    """
    Syntactic, heuristic, and VirusTotal v3 security inspection of submitted URLs.
    CRITICAL: Never visits or connects to the submitted URL.
    
    KEY FIX: Accurately differentiates fake profile URLs from genuine profile URLs
    on social platforms (e.g. x.com/apexbank vs x.com/apexbank_scam_support).
    """
    url = (submitted_url or "").strip()
    if not url:
        return {
            "risk_score": 0,
            "risk_category": "UNKNOWN / INSUFFICIENT DATA",
            "summary_reason": "No target URL was provided for analysis.",
            "heuristic_findings": [],
            "api_findings": {"status": "unconfigured", "summary": "Empty URL provided."},
            "ml_findings": {"available": False, "status": "unsupported_input", "prediction": None, "message": "Empty URL provided."},
            "indicators": [],
            "recommendations": ["Submit a valid HTTP or HTTPS URL to inspect."]
        }

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return {
            "risk_score": 50,
            "risk_category": "UNKNOWN / INSUFFICIENT DATA",
            "summary_reason": "URL is structurally malformed and could not be parsed safely.",
            "heuristic_findings": [{"name": "Malformed URL Structure", "desc": "URL failed RFC standard parsing.", "severity": "Medium", "points": 50}],
            "api_findings": {"status": "unconfigured", "summary": "Malformed URL."},
            "ml_findings": {"available": False, "status": "unsupported_input", "prediction": None, "message": "Malformed URL."},
            "indicators": [{"name": "Malformed URL Structure", "desc": "URL failed RFC standard parsing.", "severity": "Medium", "points": 50}],
            "recommendations": ["Do not attempt to load this link. Re-verify the source text."]
        }

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return {
            "risk_score": 50,
            "risk_category": "UNKNOWN / INSUFFICIENT DATA",
            "summary_reason": "URL lacks a valid hostname or destination host.",
            "heuristic_findings": [{"name": "Missing Hostname", "desc": "Could not identify destination domain.", "severity": "Medium", "points": 50}],
            "api_findings": {"status": "unconfigured", "summary": "Missing hostname."},
            "ml_findings": {"available": False, "status": "unsupported_input", "prediction": None, "message": "Missing hostname."},
            "indicators": [{"name": "Missing Hostname", "desc": "Could not identify destination domain.", "severity": "Medium", "points": 50}],
            "recommendations": ["Check URL syntax."]
        }

    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    port = parsed.port
    scheme = parsed.scheme.lower()

    brand_name = brand_dict.get("name", "") if brand_dict else ""
    norm_brand = normalize_text(brand_name)
    official_domains = [d.lower().strip() for d in brand_dict.get("official_domains", [])] if brand_dict else []
    official_handles = [normalize_text(h) for h in brand_dict.get("official_handles", [])] if brand_dict else []

    heuristic_findings = []
    total_score = 0
    reasons = []

    # Query VirusTotal API v3 for external threat intelligence (safe static query)
    api_findings = virustotal.check_url_virustotal(url)

    # Query Machine Learning RandomForest Phishing Detector (trained on real UNB + PhishTank data)
    ml_findings = ml_detector.predict_url(url)

    # =========================================================================
    # SPECIAL CASE: SOCIAL MEDIA PROFILE URL (x.com/handle, etc.)
    # Resolves the core bug: fake profile URLs and genuine profile URLs producing the same result!
    # =========================================================================
    social_info = extract_social_profile_info(url)
    if social_info and social_info.get("handle"):
        profile_handle = social_info["handle"]
        platform_name = social_info["platform_name"]
        
        # 1. Exact match with registered official handle on social platform
        if profile_handle in official_handles:
            recs = [
                f"URL corresponds to official corporate handle '@{profile_handle}' on {platform_name}.",
                "Ensure platform verification checkmark is visible and active."
            ]
            return {
                "risk_score": 4,
                "risk_category": "LOW RISK",
                "summary_reason": f"Authentic Profile URL: Handle '@{profile_handle}' on {platform_name} matches official registered corporate handles for {brand_name}.",
                "heuristic_findings": [
                    {
                        "name": "Verified Official Brand Handle on Authorized Platform",
                        "desc": f"Profile slug '/{profile_handle}' matches authenticated corporate handle in {brand_name}'s registry.",
                        "severity": "Low",
                        "points": 0
                    },
                    {
                        "name": "Platform Reputation & Structure Consistency",
                        "desc": f"Hosted on authorized social ecosystem ({social_info['domain']}).",
                        "severity": "Low",
                        "points": 4
                    }
                ],
                "api_findings": api_findings,
                "ml_findings": ml_findings,
                "indicators": [
                    {
                        "name": "Verified Official Brand Handle",
                        "desc": f"Matches {brand_name} registry.",
                        "severity": "Low",
                        "points": 0
                    }
                ],
                "social_profile_detected": True,
                "recommendations": recs,
                "parsed_data": {
                    "hostname": hostname,
                    "scheme": scheme,
                    "path": path,
                    "is_social_profile": True,
                    "profile_handle": profile_handle
                }
            }

        # 2. Handle in URL does NOT match official handles -> Impersonation & Typosquat Analysis!
        social_points = 0
        social_reasons = []

        # Check leetspeak
        deleet_handle = normalize_leetspeak(profile_handle)
        is_leet = False
        if deleet_handle != profile_handle and norm_brand:
            if norm_brand in deleet_handle or fuzz.partial_ratio(norm_brand, deleet_handle) >= 85:
                is_leet = True

        if is_leet:
            pts = 35
            social_points += pts
            heuristic_findings.append({
                "name": "Deliberate Leetspeak in Profile URL Slug",
                "desc": f"Profile handle in URL '/{profile_handle}' uses character homoglyphs mimicking '{brand_name}'.",
                "severity": "High",
                "points": pts
            })
            social_reasons.append(f"Character substitution mimicking {brand_name}")

        elif norm_brand and norm_brand in profile_handle:
            pts = 32
            social_points += pts
            heuristic_findings.append({
                "name": "Unauthorized Brand Stem in Profile URL",
                "desc": f"Profile handle '/{profile_handle}' embeds brand name '{brand_name}' on {platform_name} without being an official registered handle.",
                "severity": "High",
                "points": pts
            })
            social_reasons.append(f"Unauthorized brand '{brand_name}' claimed in profile handle")

        elif norm_brand and fuzz.partial_ratio(norm_brand, profile_handle) >= 80:
            pts = 26
            social_points += pts
            heuristic_findings.append({
                "name": "Fuzzy Brand Similarity in Profile Slug",
                "desc": f"Profile handle '/{profile_handle}' is highly similar to brand '{brand_name}' (impersonation risk).",
                "severity": "Medium",
                "points": pts
            })
            social_reasons.append(f"High similarity to brand '{brand_name}'")

        # Check suspicious keywords in profile handle slug
        found_slug_kws = [kw for kw in SOCIAL_SUSPICIOUS_KEYWORDS if kw in profile_handle]
        if found_slug_kws:
            pts = min(32, len(found_slug_kws) * 16)
            social_points += pts
            heuristic_findings.append({
                "name": "Social Engineering Keywords in Profile URL Slug",
                "desc": f"Profile URL path appends lure keywords: {', '.join(found_slug_kws)} (indicative of fake support desk / airdrop scam).",
                "severity": "High" if ('support' in found_slug_kws or 'help' in found_slug_kws or 'claim' in found_slug_kws) else "Medium",
                "points": pts
            })
            social_reasons.append(f"Lure keywords in profile slug ({', '.join(found_slug_kws)})")

        # Core Rule 8 Indicator:
        pts = 20
        social_points += pts
        heuristic_findings.append({
            "name": "Legitimate Platform Domain Hosting Unverified Handle",
            "desc": (
                f"URL is hosted on '{hostname}' (a legitimate social platform). "
                "However, domain reputation does NOT indicate profile authenticity. "
                f"The handle '/{profile_handle}' is not recognized in {brand_name}'s official registry."
            ),
            "severity": "Medium",
            "points": pts
        })

        if social_points >= 40:
            final_score = min(96, max(75, social_points))
            cat = "HIGH RISK"
            summary_reason = f"High Risk: Fake/Impersonation profile URL targeting {brand_name} on {platform_name}. " + "; ".join(social_reasons)
        elif social_points >= 25:
            final_score = 55
            cat = "SUSPICIOUS"
            summary_reason = f"Suspicious profile URL on {platform_name}: " + "; ".join(social_reasons)
        else:
            final_score = 15
            cat = "LOW RISK"
            summary_reason = f"Profile URL on {platform_name} with low correlation to brand."

        recs = [
            f"Do not interact with or provide credentials to handle '/{profile_handle}'.",
            f"File an impersonation report with {platform_name}'s Trust & Safety team citing trademark infringement.",
            f"Advise customers to verify handles exclusively via {brand_name}'s official portal."
        ]

        return {
            "risk_score": final_score,
            "risk_category": cat,
            "summary_reason": summary_reason,
            "heuristic_findings": heuristic_findings,
            "api_findings": api_findings,
            "ml_findings": ml_findings,
            "indicators": heuristic_findings,
            "social_profile_detected": True,
            "recommendations": recs,
            "parsed_data": {
                "hostname": hostname,
                "scheme": scheme,
                "path": path,
                "is_social_profile": True,
                "profile_handle": profile_handle
            }
        }

    # =========================================================================
    # STANDARD WEB DOMAIN ANALYSIS
    # =========================================================================

    # 1. Exact match with official domain
    is_exact_official = any(hostname == od or hostname.endswith('.' + od) for od in official_domains)
    if is_exact_official and scheme == 'https':
        return {
            "risk_score": 3,
            "risk_category": "LOW RISK",
            "summary_reason": f"Authorized Corporate Asset: Hostname '{hostname}' matches approved official domain registry for {brand_name}.",
            "heuristic_findings": [
                {
                    "name": "Verified Corporate Domain Topology",
                    "desc": f"Hostname '{hostname}' matches approved official domain registry with valid HTTPS scheme.",
                    "severity": "Low",
                    "points": 0
                },
                {
                    "name": "Safe Protocol Standard",
                    "desc": "Enforces HTTPS encryption.",
                    "severity": "Low",
                    "points": 3
                }
            ],
            "api_findings": api_findings,
            "ml_findings": ml_findings,
            "indicators": [
                {
                    "name": "Verified Corporate Domain",
                    "desc": f"Matches approved official registry for {brand_name}.",
                    "severity": "Low",
                    "points": 0
                }
            ],
            "recommendations": [
                "URL conforms to official corporate domain registry.",
                "Ensure continuous TLS certificate monitoring and CAA DNS records."
            ],
            "parsed_data": {
                "hostname": hostname,
                "scheme": scheme,
                "path": path or "/",
                "port": port or 443,
                "tld": hostname.split('.')[-1]
            }
        }

    # 2. Raw IP address as host
    ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, hostname):
        pts = 32
        total_score += pts
        heuristic_findings.append({
            "name": "Raw IP Hostname",
            "desc": f"URL uses a bare IP address ('{hostname}') instead of a registered domain name.",
            "severity": "High",
            "points": pts
        })
        reasons.append("Bare IP address host")

    # 3. Protocol evaluation
    if scheme == 'http':
        pts = 15
        total_score += pts
        heuristic_findings.append({
            "name": "Insecure HTTP Protocol",
            "desc": "Transmits unencrypted plaintext, vulnerable to man-in-the-middle credential interception.",
            "severity": "Medium",
            "points": pts
        })
        reasons.append("Unencrypted HTTP")

    # 4. Port Anomalies
    if port and port not in (80, 443):
        pts = 18
        total_score += pts
        heuristic_findings.append({
            "name": "Non-Standard Port Usage",
            "desc": f"Uses non-standard network port ':{port}', common in illicit test harnesses and C2 relays.",
            "severity": "Medium",
            "points": pts
        })
        reasons.append(f"Non-standard port (:{port})")

    # 5. Suspicious TLD
    host_parts = hostname.split('.')
    tld = host_parts[-1] if len(host_parts) > 1 else ""
    if tld in SUSPICIOUS_TLDS:
        pts = 22
        total_score += pts
        heuristic_findings.append({
            "name": "High-Risk Disposable TLD",
            "desc": f"Top-level domain '.{tld}' is recognized in abuse feeds as low-cost/disposable phishing infrastructure.",
            "severity": "Medium",
            "points": pts
        })
        reasons.append(f"High-risk TLD (.{tld})")

    # 6. Excessive Subdomain Stacking
    if len(host_parts) >= 4:
        pts = 16
        total_score += pts
        heuristic_findings.append({
            "name": "Excessive Subdomain Stacking",
            "desc": f"Deep subdomain hierarchy ({len(host_parts)} levels) used to obscure true destination domain.",
            "severity": "Medium",
            "points": pts
        })
        reasons.append("Excessive subdomain depth")

    # 7. Brand Impersonation / Typosquatting in Hostname
    if norm_brand:
        if norm_brand in hostname and not is_exact_official:
            pts = 35
            total_score += pts
            heuristic_findings.append({
                "name": "Brand Squatting in Hostname",
                "desc": f"Host '{hostname}' embeds the brand name '{brand_name}' but is not an authorized corporate asset.",
                "severity": "High",
                "points": pts
            })
            reasons.append(f"Unauthorized brand '{brand_name}' embedded in domain")
        else:
            root_domain = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else hostname
            sim = fuzz.partial_ratio(norm_brand, root_domain)
            if sim >= 80 and not is_exact_official:
                pts = 26
                total_score += pts
                heuristic_findings.append({
                    "name": "Fuzzy Domain Similarity",
                    "desc": f"Domain stem '{root_domain}' is {sim:.0f}% similar to '{brand_name}' (typosquatting risk).",
                    "severity": "Medium",
                    "points": pts
                })
                reasons.append(f"Domain typosquatting similarity ({sim:.0f}%)")

    # 8. Sensitive Path & Query Keywords (Credential Harvesting Lures)
    full_path_query = path + "?" + query
    found_path_kws = [kw for kw in PATH_SENSITIVE_KEYWORDS if kw in full_path_query]
    if found_path_kws:
        pts = min(28, len(found_path_kws) * 14)
        total_score += pts
        heuristic_findings.append({
            "name": "Credential Harvesting Path Tokens",
            "desc": f"Path contains sensitive authentication/account lure keywords: {', '.join(found_path_kws[:3])}.",
            "severity": "High" if ('login' in found_path_kws or 'verify' in found_path_kws or 'otp' in found_path_kws) else "Medium",
            "points": pts
        })
        reasons.append(f"Sensitive path triggers ({', '.join(found_path_kws[:3])})")

    # 9. URL Obfuscation Indicators
    if '@' in url:
        pts = 25
        total_score += pts
        heuristic_findings.append({
            "name": "URL Authority Obfuscation",
            "desc": "URL uses '@' symbol to mislead user about target host.",
            "severity": "High",
            "points": pts
        })
        reasons.append("Credential obfuscation via '@'")

    if hostname.count('-') >= 3:
        pts = 14
        total_score += pts
        heuristic_findings.append({
            "name": "Multiple Hyphen Delimiters",
            "desc": "Extensive hyphenation in domain frequently correlates with automated phishing domain generation.",
            "severity": "Low",
            "points": pts
        })
        reasons.append("Heavy domain hyphenation")

    # 10. Incorporate VirusTotal Threat Intelligence Finding (if available)
    if api_findings.get("is_flagged"):
        pts = 35
        total_score += pts
        heuristic_findings.append({
            "name": "VirusTotal Threat Intelligence Detection",
            "desc": f"Flagged by {api_findings.get('malicious_count', 0)} security vendors on VirusTotal (Reputation: {api_findings.get('reputation', 0)}).",
            "severity": "High",
            "points": pts
        })
        reasons.append(f"Flagged by {api_findings.get('malicious_count', 0)} security vendors on VirusTotal")

    # 9. Machine Learning RandomForest Phishing Model
    if ml_findings.get("available") and ml_findings.get("is_phishing"):
        ml_prob = ml_findings.get("phishing_probability", 0.0)
        conf = ml_findings.get("confidence_pct", 0.0)
        if ml_prob >= 0.75:
            pts = 35
            sev = "High"
        elif ml_prob >= 0.50:
            pts = 20
            sev = "Medium"
        else:
            pts = 0
            sev = "Low"

        if pts > 0:
            total_score += pts
            heuristic_findings.append({
                "name": "Machine Learning Phishing Model Flag",
                "desc": f"Trained RandomForest model flagged phishing URL lexical characteristics with {conf}% confidence.",
                "severity": sev,
                "points": pts
            })
            reasons.append(f"ML Phishing Prediction ({conf}% confidence)")

    # Multi-factor rule: Do not label malicious based on one single minor indicator alone
    if len(heuristic_findings) <= 1 and total_score < 40 and not api_findings.get("is_flagged") and not (ml_findings.get("available") and ml_findings.get("is_phishing")):
        total_score = min(total_score, 30)
        risk_category = "LOW RISK"
        summary_reason = "Single minor indicator observed. Multi-factor threshold not met for suspicious categorization."
    elif total_score >= 70 and (len(heuristic_findings) >= 2 or api_findings.get("is_flagged") or (ml_findings.get("available") and ml_findings.get("is_phishing"))):
        risk_category = "HIGH RISK"
        summary_reason = "High Risk Multi-factor threat identified: " + "; ".join(reasons)
    elif total_score >= 40:
        risk_category = "SUSPICIOUS"
        summary_reason = "Suspicious attributes detected: " + "; ".join(reasons)
    else:
        risk_category = "LOW RISK"
        summary_reason = "Standard web link. No critical impersonation or phishing patterns identified."

    total_score = max(4, min(99, total_score))
    recommendations = generate_link_recommendations(risk_category, hostname, reasons)

    return {
        "risk_score": total_score,
        "risk_category": risk_category,
        "summary_reason": summary_reason,
        "heuristic_findings": heuristic_findings,
        "api_findings": api_findings,
        "ml_findings": ml_findings,
        "indicators": heuristic_findings,
        "recommendations": recommendations,
        "parsed_data": {
            "hostname": hostname,
            "scheme": scheme,
            "path": path or "/",
            "port": port or (443 if scheme == 'https' else 80),
            "tld": tld,
            "is_social_profile": False
        }
    }

def generate_link_recommendations(risk_cat: str, hostname: str, reasons: list) -> list:
    recs = []
    if risk_cat == "HIGH RISK":
        recs.append("NEVER navigate to or submit credentials on this URL.")
        recs.append(f"Submit this link to Google Safe Browsing and Microsoft Defender SmartScreen for automated browser-level blocking.")
        recs.append(f"Notify the domain registrar abuse contact for '{hostname}' to request DNS domain suspension.")
        recs.append("Add the host to enterprise perimeter firewall / DNS sinkhole blocklists.")
    elif risk_cat == "SUSPICIOUS":
        recs.append("Exercise extreme caution. Inspect domain ownership via WHOIS before any interaction.")
        recs.append("Verify the URL against your organization's official published site navigation.")
        recs.append("Do not enter banking credentials, passwords, or personal recovery codes.")
    else:
        recs.append("Link displays low threat indicators. Always verify SSL lock certificate before entering sensitive information.")
    return recs

# =========================================================================
# 3. MOBILE APP LISTING CHECKER
# =========================================================================
def analyze_mobile_app(app_name: str, developer_name: str, store_url: str, 
                       description: str, brand_dict: dict = None, apk_hash: str = None) -> dict:
    """
    Evaluates mobile app store listings for developer mismatches,
    unauthorized brand cloning, risky permission claims, and APK threat intelligence.
    """
    clean_app = (app_name or "").strip()
    clean_dev = (developer_name or "").strip()
    clean_url = (store_url or "").strip().lower()
    clean_desc = (description or "").strip().lower()
    clean_hash = (apk_hash or "").strip().lower()

    if not clean_app or not clean_dev:
        return {
            "risk_score": 0,
            "risk_category": "UNKNOWN / INSUFFICIENT DATA",
            "summary_reason": "Missing required App Name or Developer Name.",
            "heuristic_findings": [],
            "api_findings": {"status": "not_applicable", "summary": "Missing inputs"},
            "app_ml_findings": {"available": False, "status": "missing_inputs", "prediction": None, "message": "Missing required app or developer name."},
            "indicators": [],
            "recommendations": ["Provide app title and developer name."]
        }

    brand_name = brand_dict.get("name", "") if brand_dict else ""
    norm_brand = normalize_text(brand_name)
    verified_devs = brand_dict.get("verified_developers", []) if brand_dict else []

    heuristic_findings = []
    total_score = 0
    reasons = []

    # Threat Intelligence Integration (VirusTotal API v3)
    if clean_hash:
        api_findings = virustotal.check_file_hash_virustotal(clean_hash)
    elif clean_url:
        raw_vt = virustotal.check_url_virustotal(clean_url)
        api_findings = dict(raw_vt)
        api_findings["binary_verification_note"] = "Store URL scan evaluates download mirror reputation only, not the cryptographic APK binary signature."
    else:
        api_findings = {
            "status": "not_applicable",
            "summary": "No store URL or APK cryptographic hash provided for external threat intelligence lookup.",
            "malicious_count": 0,
            "total_vendors": 0,
            "is_flagged": False
        }

    if api_findings.get("is_flagged"):
        mal_cnt = api_findings.get("malicious_count", 0)
        pts = min(40, max(20, mal_cnt * 10))
        total_score += pts
        reasons.append(f"VirusTotal detected {mal_cnt} malicious engine flags")
        heuristic_findings.append({
            "name": "VirusTotal Threat Intelligence Flag",
            "desc": api_findings.get("summary", "External security vendors flagged submitted application asset."),
            "severity": "High",
            "points": pts
        })

    # Evaluate with Model 3 Random Forest Android Classifier (Drebin NDSS 2014 Benchmark)
    app_payload = {
        "app_name": clean_app,
        "developer_name": clean_dev,
        "store_url": clean_url,
        "description": clean_desc
    }
    app_ml_findings = mobile_app_detector.predict_app(app_payload, brand_name=brand_name, verified_developers=verified_devs)

    # 1. Developer entity verification
    dev_match = False
    best_dev_sim = 0
    for vd in verified_devs:
        sim = fuzz.token_sort_ratio(clean_dev.lower(), vd.lower())
        if sim > best_dev_sim:
            best_dev_sim = sim
        if sim >= 90:
            dev_match = True
            break

    # 2. Host distribution check
    is_official_store = any(oh in clean_url for oh in OFFICIAL_APP_HOSTS)

    # If developer is verified AND hosted on official store AND clean description AND not flagged by ML AND not flagged by VT:
    if dev_match and is_official_store and not any(kw in clean_desc for kw in APP_RISK_KEYWORDS) and not app_ml_findings.get("is_malware_suspect", False) and not api_findings.get("is_flagged", False):
        return {
            "risk_score": 5,
            "risk_category": "LOW RISK",
            "summary_reason": f"Authentic Mobile Listing: Verified developer match ('{clean_dev}') and official store distribution.",
            "heuristic_findings": [
                {
                    "name": "Verified Developer Match",
                    "desc": f"Developer '{clean_dev}' matches corporate records for {brand_name} ({best_dev_sim:.0f}% confidence).",
                    "severity": "Low",
                    "points": 0
                },
                {
                    "name": "Official App Store Ecosystem",
                    "desc": "Distributed through authorized Google Play or Apple App Store repository.",
                    "severity": "Low",
                    "points": 5
                }
            ],
            "api_findings": api_findings,
            "app_ml_findings": app_ml_findings,
            "indicators": [
                {
                    "name": "Verified Developer Match",
                    "desc": f"Developer matches corporate records for {brand_name}.",
                    "severity": "Low",
                    "points": 0
                }
            ],
            "recommendations": [
                "Listing corresponds to official corporate application catalog.",
                "Ensure standard code signing key rotation and regular security reviews."
            ]
        }

    # Brand stem in app name
    app_uses_brand = False
    if norm_brand and (norm_brand in normalize_text(clean_app) or fuzz.partial_ratio(norm_brand, normalize_text(clean_app)) >= 85):
        app_uses_brand = True

    # Check developer mismatch when brand name is claimed
    if app_uses_brand and not dev_match:
        pts = 48
        total_score += pts
        heuristic_findings.append({
            "name": "Developer Entity Mismatch",
            "desc": f"Listing claims brand name '{brand_name}', but publisher '{clean_dev}' does NOT match registered corporate entities ({', '.join(verified_devs) if verified_devs else 'None'}).",
            "severity": "High",
            "points": pts
        })
        reasons.append("Publisher entity mismatch with brand registry")

    # Check unverified / third-party APK distribution
    if not is_official_store:
        pts = 28
        total_score += pts
        heuristic_findings.append({
            "name": "Untrusted Third-Party Distribution Host",
            "desc": "App is distributed via unofficial third-party APK mirror/repository without cryptographic play protect or app review safeguards.",
            "severity": "High",
            "points": pts
        })
        reasons.append("Third-party / unverified APK download source")

    # High-Risk Permissions / Fraudulent keywords in Description
    found_app_kws = [kw for kw in APP_RISK_KEYWORDS if kw in clean_desc]
    if found_app_kws:
        pts = min(30, len(found_app_kws) * 15)
        total_score += pts
        heuristic_findings.append({
            "name": "High-Risk Android Permission Lures",
            "desc": f"Listing claims to require hazardous permissions or capabilities: {', '.join(found_app_kws[:3])}.",
            "severity": "High",
            "points": pts
        })
        reasons.append(f"Dangerous permission claims ({', '.join(found_app_kws[:3])})")

    # Look-alike Name with deceptive prefixes/suffixes
    lookalike_tokens = ['free', 'pro', 'instant', 'quick', 'bonus', 'wallet', 'reward', 'mod', 'unlimited', 'loan', 'fast', 'cash']
    found_tokens = [tok for tok in lookalike_tokens if tok in clean_app.lower()]
    if found_tokens and app_uses_brand:
        pts = 24
        total_score += pts
        heuristic_findings.append({
            "name": "Deceptive App Title Modifier",
            "desc": f"App title blends brand name with promotional lure words: {', '.join(found_tokens)}.",
            "severity": "Medium",
            "points": pts
        })
        reasons.append(f"Deceptive title modifier ({', '.join(found_tokens)})")

    # ML Model 3 Attribution Signal
    if app_ml_findings and app_ml_findings.get("available") and app_ml_findings.get("is_malware_suspect"):
        prob = app_ml_findings.get("malware_probability_pct", 50)
        pts = int(min(35, prob * 0.4))
        total_score += pts
        heuristic_findings.append({
            "name": "Machine Learning Android Malware Flag (Model 3)",
            "desc": f"RandomForest Drebin classifier detected malicious static manifest pattern ({prob:.1f}% confidence).",
            "severity": "High" if prob >= 70 else "Medium",
            "points": pts
        })
        reasons.append(f"ML risk flag ({prob:.1f}% malware propensity)")

    if not heuristic_findings:
        total_score = 10
        heuristic_findings.append({
            "name": "Uncorrelated Application Listing",
            "desc": "Listing does not present look-alike brand infringement or dangerous permission patterns.",
            "severity": "Low",
            "points": 10
        })
        summary_reason = "Low risk. Listing does not impersonate verified corporate entities."
    else:
        total_score = max(5, min(99, total_score))
        summary_reason = "; ".join(reasons) if reasons else "Prototype heuristic flags detected."

    risk_category = categorize_risk_score(total_score)
    recommendations = generate_app_recommendations(risk_category, clean_app, clean_dev, is_official_store)

    return {
        "risk_score": total_score,
        "risk_category": risk_category,
        "summary_reason": summary_reason,
        "heuristic_findings": heuristic_findings,
        "api_findings": api_findings,
        "app_ml_findings": app_ml_findings,
        "indicators": heuristic_findings,
        "recommendations": recommendations
    }

def generate_app_recommendations(risk_cat: str, app_name: str, dev_name: str, is_official: bool) -> list:
    recs = []
    if risk_cat == "HIGH RISK":
        if not is_official:
            recs.append("Advise employees and customers immediately NOT to download or install this third-party APK.")
            recs.append("File a DMCA copyright and trademark takedown notice with the hosting APK distribution platform.")
        else:
            recs.append(f"Submit a formal impersonation report to Google Play / Apple Developer Program alleging brand infringement against developer '{dev_name}'.")
        recs.append("Issue an official public advisory listing authorized corporate app bundle IDs and verified download URLs.")
    elif risk_cat == "SUSPICIOUS":
        recs.append("Review whether developer entity is a sub-contractor, regional licensee, or authorized partner.")
        recs.append("Verify SHA-256 certificate fingerprints against internal mobile release signatures.")
    else:
        recs.append("Maintain routine monitoring of app store search results for newly published look-alikes.")
    return recs
