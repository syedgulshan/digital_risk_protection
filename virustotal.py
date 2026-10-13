"""
BrandShield AI - VirusTotal API v3 Integration Module
Provides URL and domain reputation intelligence with safe static querying,
robust error handling (401, 404, 429, timeouts), caching, and explainability.
Documentation: https://docs.virustotal.com/reference/overview
"""

import os
import base64
import urllib.parse
from datetime import datetime, timedelta
import requests
from dotenv import load_dotenv

# Ensure environment variables are loaded from .env
load_dotenv()

VT_API_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT_SECONDS = 5.0

# In-memory session cache for local fast lookup (key -> (timestamp, data))
_MEMORY_CACHE = {}
CACHE_TTL_HOURS = 4

# Known social media platforms whose domain reputation does not equal profile authenticity
SOCIAL_DOMAINS = {
    'x.com', 'twitter.com', 'instagram.com', 'facebook.com', 'fb.com',
    'linkedin.com', 'telegram.org', 't.me', 'telegram.me', 'tiktok.com',
    'youtube.com', 'threads.net', 'github.com', 'reddit.com', 'pinterest.com'
}

def get_virustotal_api_key() -> str:
    """Retrieve VirusTotal API key from environment, returning empty string if unset."""
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not key or key.lower() in ("your_virustotal_api_key_here", "placeholder", "none"):
        return ""
    return key

def is_virustotal_configured() -> bool:
    """Check if a valid VirusTotal API key is present in environment."""
    return bool(get_virustotal_api_key())

def encode_url_id(url: str) -> str:
    """
    Encode URL into VirusTotal v3 URL identifier:
    Base64 urlsafe string without trailing '=' padding characters.
    """
    clean_url = url.strip()
    return base64.urlsafe_b64encode(clean_url.encode("utf-8")).decode("utf-8").strip("=")

def extract_domain(url: str) -> str:
    """Safely extract lowercase hostname/domain from URL."""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""

def is_social_platform_domain(domain: str) -> bool:
    """Check if domain belongs to a known public social network."""
    domain = domain.lower()
    return any(domain == sd or domain.endswith('.' + sd) for sd in SOCIAL_DOMAINS)

def check_url_virustotal(url: str, session: requests.Session = None) -> dict:
    """
    Query VirusTotal API v3 for URL reputation.
    CRITICAL: Never visits or connects to the target URL itself. Only queries the VT API.
    
    Handles:
    - Missing / Unconfigured API key
    - Cache hits (avoids consuming public quota)
    - 200 OK (Clean / Malicious / Suspicious)
    - 404 Not Found (URL not present in VT threat intelligence dataset)
    - 401 / 403 (Invalid credentials)
    - 429 (Rate limit reached)
    - Timeouts & Service failures
    """
    url = (url or "").strip()
    if not url:
        return {
            "status": "error",
            "configured": is_virustotal_configured(),
            "summary": "No URL provided for analysis.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_vendors": 0,
            "reputation": 0,
            "is_flagged": False,
            "is_social_platform": False,
            "cached": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    domain = extract_domain(url)
    is_social = is_social_platform_domain(domain)

    # Check in-memory cache
    cache_key = f"url:{url}"
    if cache_key in _MEMORY_CACHE:
        cached_time, cached_data = _MEMORY_CACHE[cache_key]
        if datetime.now() - cached_time < timedelta(hours=CACHE_TTL_HOURS):
            cached_copy = dict(cached_data)
            cached_copy["cached"] = True
            return cached_copy

    api_key = get_virustotal_api_key()
    if not api_key:
        result = {
            "status": "unconfigured",
            "configured": False,
            "summary": "VirusTotal API key is not configured in .env",
            "details": "Threat intelligence lookups skipped. Evaluation completed using deterministic local heuristics.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_vendors": 0,
            "reputation": 0,
            "categories": {},
            "is_flagged": False,
            "is_social_platform": is_social,
            "social_notice": (
                f"Target is on social network ({domain}). Domain reputation does not guarantee profile legitimacy."
                if is_social else ""
            ),
            "cached": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        return result

    url_id = encode_url_id(url)
    endpoint = f"{VT_API_BASE}/urls/{url_id}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "BrandShield-AI-SecurityPlatform/1.0"
    }

    req_func = session.get if session else requests.get

    try:
        response = req_func(endpoint, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        
        # 1. Successful report found
        if response.status_code == 200:
            data = response.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            reputation = attrs.get("reputation", 0)
            categories = attrs.get("categories", {})
            
            is_flagged = (malicious > 0 or suspicious > 1 or reputation < -10)
            
            if is_flagged:
                summary = f"Flagged by {malicious} security vendor(s) and {suspicious} suspicious detection(s)."
            elif harmless > 0:
                summary = f"Analyzed by {total} security vendors: 0 flagged as malicious ({harmless} verified harmless)."
            else:
                summary = f"Observed in threat database with 0 vendor detections."

            social_notice = ""
            if is_social:
                social_notice = (
                    f"Note: URL is hosted on '{domain}' (a legitimate platform). "
                    "Clean domain reputation does NOT guarantee that the individual profile or channel is authentic. "
                    "Profile legitimacy requires username verification and brand registry cross-checking."
                )

            result = {
                "status": "success",
                "configured": True,
                "summary": summary,
                "details": f"VirusTotal v3 scan data. Reputation score: {reputation}.",
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "total_vendors": total,
                "reputation": reputation,
                "categories": categories,
                "is_flagged": is_flagged,
                "is_social_platform": is_social,
                "social_notice": social_notice,
                "cached": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            _MEMORY_CACHE[cache_key] = (datetime.now(), result)
            return result

        # 2. URL not yet indexed in VirusTotal dataset (HTTP 404)
        elif response.status_code == 404:
            # Query the parent domain to provide baseline domain reputation
            domain_result = check_domain_virustotal(domain, api_key=api_key, session=session)
            
            social_notice = ""
            if is_social:
                social_notice = (
                    f"The profile URL is hosted on legitimate platform '{domain}'. "
                    "Clean domain reputation does NOT guarantee that the individual profile or channel is authentic. "
                    "Individual account status must be assessed through handle similarity and brand registry verification."
                )

            result = {
                "status": "not_found",
                "configured": True,
                "summary": "URL is not found in threat-intelligence records (newly observed or unsubmitted entity).",
                "details": (
                    f"VirusTotal has not yet indexed this exact URL. "
                    + (f"Domain '{domain}' reputation: {domain_result.get('summary', 'Clean')}" if domain_result.get('status') == 'success' else "")
                ),
                "malicious_count": domain_result.get("malicious_count", 0),
                "suspicious_count": domain_result.get("suspicious_count", 0),
                "harmless_count": domain_result.get("harmless_count", 0),
                "total_vendors": domain_result.get("total_vendors", 0),
                "reputation": domain_result.get("reputation", 0),
                "categories": domain_result.get("categories", {}),
                "is_flagged": domain_result.get("is_flagged", False),
                "is_social_platform": is_social,
                "social_notice": social_notice,
                "cached": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            _MEMORY_CACHE[cache_key] = (datetime.now(), result)
            return result

        # 3. Authentication failure (HTTP 401 / 403)
        elif response.status_code in (401, 403):
            return {
                "status": "auth_error",
                "configured": True,
                "summary": "VirusTotal API authentication failed (Invalid or unauthorized API key).",
                "details": "HTTP 401/403. Please verify VIRUSTOTAL_API_KEY in .env.",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "total_vendors": 0,
                "reputation": 0,
                "is_flagged": False,
                "is_social_platform": is_social,
                "cached": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        # 4. Rate limit reached (HTTP 429)
        elif response.status_code == 429:
            return {
                "status": "rate_limited",
                "configured": True,
                "summary": "VirusTotal API rate limit reached (HTTP 429).",
                "details": "Standard free public limit is 4 requests/minute. Analysis proceeded using local heuristic engine.",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "total_vendors": 0,
                "reputation": 0,
                "is_flagged": False,
                "is_social_platform": is_social,
                "cached": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        # 5. Other HTTP error
        else:
            return {
                "status": "api_error",
                "configured": True,
                "summary": f"VirusTotal API responded with status code HTTP {response.status_code}.",
                "details": "External intelligence unavailable for this request. Local heuristics applied.",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "total_vendors": 0,
                "reputation": 0,
                "is_flagged": False,
                "is_social_platform": is_social,
                "cached": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    except requests.exceptions.Timeout:
        return {
            "status": "timeout",
            "configured": True,
            "summary": "VirusTotal API request timed out (connection exceeded threshold).",
            "details": "Remote service did not respond within timeout window. Local heuristics applied.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_vendors": 0,
            "reputation": 0,
            "is_flagged": False,
            "is_social_platform": is_social,
            "cached": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    except requests.exceptions.RequestException as e:
        return {
            "status": "service_unavailable",
            "configured": True,
            "summary": "VirusTotal API is currently unreachable or offline.",
            "details": f"Network error: {type(e).__name__}. Local heuristics applied.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_vendors": 0,
            "reputation": 0,
            "is_flagged": False,
            "is_social_platform": is_social,
            "cached": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def check_domain_virustotal(domain: str, api_key: str = None, session: requests.Session = None) -> dict:
    """
    Query VirusTotal API v3 for domain reputation.
    Safe query; never connects to or executes destination.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return {"status": "error", "summary": "Empty domain"}

    cache_key = f"domain:{domain}"
    if cache_key in _MEMORY_CACHE:
        cached_time, cached_data = _MEMORY_CACHE[cache_key]
        if datetime.now() - cached_time < timedelta(hours=CACHE_TTL_HOURS):
            return dict(cached_data)

    if not api_key:
        api_key = get_virustotal_api_key()

    if not api_key:
        return {
            "status": "unconfigured",
            "configured": False,
            "summary": "VirusTotal API key not configured.",
            "malicious_count": 0,
            "total_vendors": 0
        }

    endpoint = f"{VT_API_BASE}/domains/{domain}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "BrandShield-AI-SecurityPlatform/1.0"
    }
    req_func = session.get if session else requests.get

    try:
        response = req_func(endpoint, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        if response.status_code == 200:
            data = response.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            reputation = attrs.get("reputation", 0)
            categories = attrs.get("categories", {})

            res = {
                "status": "success",
                "summary": f"Domain '{domain}': {malicious} malicious / {suspicious} suspicious vendor flags.",
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "total_vendors": total,
                "reputation": reputation,
                "categories": categories,
                "is_flagged": (malicious > 0 or suspicious > 1)
            }
            _MEMORY_CACHE[cache_key] = (datetime.now(), res)
            return res
        else:
            return {
                "status": "not_found" if response.status_code == 404 else "api_error",
                "summary": f"Domain lookup status: {response.status_code}",
                "malicious_count": 0,
                "total_vendors": 0,
                "is_flagged": False
            }
    except Exception as e:
        return {
            "status": "error",
            "summary": f"Domain lookup error: {str(e)}",
            "malicious_count": 0,
            "total_vendors": 0,
            "is_flagged": False
        }

def check_file_hash_virustotal(file_hash: str, api_key: str = None, session: requests.Session = None) -> dict:
    """
    Query VirusTotal API v3 for an APK or file cryptographic hash (MD5, SHA-1, SHA-256).
    CRITICAL: Never uploads binaries or executes files. Queries existing threat intelligence only.
    """
    clean_hash = (file_hash or "").strip().lower()
    if not clean_hash:
        return {
            "status": "error",
            "configured": is_virustotal_configured(),
            "summary": "No cryptographic hash provided for analysis.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_vendors": 0,
            "is_flagged": False,
            "cached": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    # Validate hash format (MD5=32, SHA1=40, SHA256=64 hex chars)
    import re
    if not re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", clean_hash):
        return {
            "status": "invalid_hash",
            "configured": is_virustotal_configured(),
            "summary": "Invalid cryptographic hash format. Must be a 32-char MD5, 40-char SHA-1, or 64-char SHA-256 hexadecimal string.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_vendors": 0,
            "is_flagged": False,
            "cached": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    # Check in-memory cache
    cache_key = f"file:{clean_hash}"
    if cache_key in _MEMORY_CACHE:
        cached_time, cached_data = _MEMORY_CACHE[cache_key]
        if datetime.now() - cached_time < timedelta(hours=CACHE_TTL_HOURS):
            cached_copy = dict(cached_data)
            cached_copy["cached"] = True
            return cached_copy

    if not api_key:
        api_key = get_virustotal_api_key()

    if not api_key:
        return {
            "status": "unconfigured",
            "configured": False,
            "summary": "VirusTotal API key is not configured in .env",
            "details": "Threat intelligence lookup skipped. Analysis conducted using static manifest features.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "total_vendors": 0,
            "is_flagged": False,
            "cached": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    endpoint = f"{VT_API_BASE}/files/{clean_hash}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "BrandShield-AI-SecurityPlatform/1.0"
    }
    req_func = session.get if session else requests.get

    try:
        response = req_func(endpoint, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)

        if response.status_code == 200:
            data = response.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            res = {
                "status": "success",
                "configured": True,
                "summary": f"APK Hash '{clean_hash[:12]}...': {malicious} malicious / {suspicious} suspicious vendor flags ({total} engines).",
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "total_vendors": total,
                "meaning_file_name": attrs.get("meaningful_name") or attrs.get("type_description", "Android APK"),
                "is_flagged": (malicious > 0 or suspicious > 1),
                "cached": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            _MEMORY_CACHE[cache_key] = (datetime.now(), res)
            return res

        elif response.status_code == 404:
            res = {
                "status": "not_found",
                "configured": True,
                "summary": f"Hash '{clean_hash[:12]}...' is not present in the VirusTotal database.",
                "details": "Binary has not been submitted or observed by public antivirus engines. Absence from database does NOT prove the app is safe.",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "total_vendors": 0,
                "is_flagged": False,
                "cached": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            _MEMORY_CACHE[cache_key] = (datetime.now(), res)
            return res

        elif response.status_code in (401, 403):
            return {
                "status": "invalid_key",
                "configured": True,
                "summary": "VirusTotal API key is unauthorized or rejected (HTTP 401/403).",
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_vendors": 0,
                "is_flagged": False,
                "cached": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        elif response.status_code == 429:
            return {
                "status": "rate_limited",
                "configured": True,
                "summary": "VirusTotal API rate limit reached (HTTP 429).",
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_vendors": 0,
                "is_flagged": False,
                "cached": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        else:
            return {
                "status": "api_error",
                "configured": True,
                "summary": f"VirusTotal API responded with HTTP {response.status_code}.",
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_vendors": 0,
                "is_flagged": False,
                "cached": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    except requests.exceptions.Timeout:
        return {
            "status": "timeout",
            "configured": True,
            "summary": "VirusTotal API request timed out.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_vendors": 0,
            "is_flagged": False,
            "cached": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": "service_unavailable",
            "configured": True,
            "summary": f"VirusTotal service unreachable: {type(e).__name__}",
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_vendors": 0,
            "is_flagged": False,
            "cached": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

