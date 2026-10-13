"""
BrandShield AI - Optional Gemini API Explainer Module
Provides secondary natural-language cybersecurity explanations of suspicious profile descriptions.
CRITICAL: Never used as the sole fraud detector. Deterministic heuristics govern risk scoring.
"""

import os
from dotenv import load_dotenv

load_dotenv()

def get_gemini_api_key() -> str:
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key or key.lower() in ("your_gemini_api_key_here", "placeholder", "none"):
        return ""
    return key

def is_gemini_configured() -> bool:
    return bool(get_gemini_api_key())

def explain_suspicious_profile_bio(brand_name: str, handle: str, bio_text: str, detected_keywords: list = None) -> dict:
    """
    Generate an AI-assisted explanation of suspicious bio text using Gemini API if configured.
    Falls back gracefully if key is missing or service is unreachable.
    """
    if not is_gemini_configured() or not (bio_text or "").strip():
        return {
            "configured": False,
            "explanation": None,
            "status": "unconfigured"
        }

    api_key = get_gemini_api_key()

    prompt = (
        f"You are a cyber risk intelligence analyst. In 1 to 2 concise sentences, "
        f"explain why the following profile bio text claiming to be '{brand_name}' (handle '{handle}') "
        f"exhibits social engineering, credential harvesting, or impersonation risk. "
        f"Identified cues: {', '.join(detected_keywords or ['unauthorized claims'])}.\n"
        f"Bio Text: \"{bio_text.strip()}\""
    )

    try:
        import requests
        # Modern Gemini models with fallback in case of transient demand spikes
        models_to_try = [
            "gemini-3.5-flash-lite",
            "gemini-3.5-flash",
            "gemini-flash-lite-latest",
            "gemini-3.8-flash"
        ]
        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "maxOutputTokens": 100,
                "temperature": 0.2
            }
        }
        for model_name in models_to_try:
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            try:
                res = requests.post(endpoint, json=payload, timeout=3.5)
                if res.status_code == 200:
                    data = res.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        if text:
                            return {
                                "configured": True,
                                "explanation": text.strip(),
                                "status": "success",
                                "model": model_name
                            }
            except Exception:
                continue

        return {
            "configured": True,
            "explanation": None,
            "status": f"api_error_{res.status_code}"
        }
    except Exception as e:
        return {
            "configured": True,
            "explanation": None,
            "status": f"error: {type(e).__name__}"
        }
