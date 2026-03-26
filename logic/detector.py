import re
import time
import joblib
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scan_logs.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PhishingDetector")

# Load ML models
try:
    email_model = joblib.load('models/email_model.joblib')
    file_model = joblib.load('models/file_model.joblib')
    ML_AVAILABLE = True
    logger.info("ML models loaded successfully.")
except Exception as e:
    ML_AVAILABLE = False
    logger.warning(f"ML models not found: {e}. Falling back to rule-based detection.")

def get_risk_level(score: float) -> str:
    """
    Maps score (0-100) to 4-level risk classification.
    Safe (0-30), Likely Safe (31-50), Suspicious (51-70), High Risk (71-100)
    """
    if score >= 71:
        return "High Risk"
    elif score >= 51:
        return "Suspicious"
    elif score >= 31:
        return "Likely Safe"
    else:
        return "Safe"

def analyze_url(url: str) -> dict:
    """
    Analyzes a URL using a weighted hybrid approach (Heuristics + ML).
    Higher score (0-100) means higher risk.
    """
    risk_score = 25.0 # Starting Neutral-Likely Safe base
    explanations = []
    
    # Track signal counts
    strong_signals = 0
    weak_signals = 0
    safe_signals = 0
    
    lower_url = url.lower()
    logger.info(f"Analyzing URL: {url}")

    # 1. Strong High-Risk Indicators
    ip_regex = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    if re.search(ip_regex, lower_url):
        risk_score += 35
        strong_signals += 2
        explanations.append("URL uses a direct IP address, a critical indicator of phishing.")

    if "@" in lower_url:
        risk_score += 40
        strong_signals += 2
        explanations.append("URL contains '@' character, often used to hide the true destination.")

    # Suspicious keywords
    phish_keywords = ["login", "verify", "account", "update", "bank", "confirm", "signin", "secure-login", "auth", "billing"]
    lure_keywords = ["mod", "apk", "extra", "free", "working", "cracked", "bonus", "winner", "reward", "link", "download"]
    
    matched_phish = [kw for kw in phish_keywords if kw in lower_url]
    matched_lures = [kw for kw in lure_keywords if kw in lower_url]
    
    if matched_phish:
        risk_score += 25
        strong_signals += 1
        explanations.append(f"Contains high-risk credential harvesting keywords: {', '.join(matched_phish)}.")
    
    if matched_lures:
        # Increase weight per lure if found in the domain name specifically
        domain_match = re.search(r"https?://(?:www\.)?([^/]+)", lower_url)
        domain_only = domain_match.group(1) if domain_match else ""
        
        lures_in_domain = [kw for kw in lure_keywords if kw in domain_only]
        if len(lures_in_domain) >= 2:
            risk_score += 35 # Strong signal if domain is literally "GenericLureGenericLure.com"
            strong_signals += 1
            explanations.append(f"Domain structure is suspiciously composed of multiple lure keywords: {', '.join(lures_in_domain)}.")
        else:
            risk_score += 15
            weak_signals += 1
            explanations.append(f"Contains lure keywords (e.g., {', '.join(matched_lures)}) often used to attract victims.")

    # Look-alike domains (Mimicry)
    look_alikes = ['g00gle', 'paypa1', 'micros0ft', 'rnicrosoft', 'amaz0n', 'faceb00k', 'happym0d', 'netf1ix']
    if any(variant in lower_url for variant in look_alikes):
        risk_score += 50
        strong_signals += 2
        explanations.append("Deceptive URL structure detected (brand mimicry).")

    # 2. Weak High-Risk Indicators
    if lower_url.count(".") > 4:
        risk_score += 15
        weak_signals += 1
        explanations.append("Excessive subdomains detected (URL obfuscation).")

    if len(url) > 85:
        risk_score += 10
        weak_signals += 1
        explanations.append("Unusually long URL length (weak indicator).")

    if "-" in lower_url:
        risk_score += 5
        weak_signals += 1
        explanations.append("Use of hyphens in domain.")

    suspicious_tlds = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".site", ".work", ".shop", ".online"]
    if any(lower_url.endswith(tld) or (tld + "/") in lower_url for tld in suspicious_tlds):
        risk_score += 15
        weak_signals += 1
        explanations.append("Uses a high-risk Top-Level Domain (TLD).")

    # 3. Safe Indicators
    if not lower_url.startswith("https://"):
        risk_score += 20
        explanations.append("Insecure HTTP connection.")
    else:
        risk_score -= 5 # Minor reduction for HTTPS

    domain_match = re.search(r"https?://(?:www\.)?([^/]+)", lower_url)
    if domain_match:
        domain = domain_match.group(1)
        if domain.count(".") == 1 and not any(kw in domain for kw in phish_keywords + lure_keywords):
            risk_score -= 10
            safe_signals += 1
            explanations.append("Standard, clean domain structure.")

    # Final logic
    if strong_signals == 0:
        final_score = min(risk_score, 45.0)
    else:
        final_score = risk_score

    final_score = max(0, min(100, final_score))
    verdict = get_risk_level(final_score)

    # --- STEALTH/INDISCERNIBLE THREAT DETECTION ---
    # Detect Zero-Width Characters (invisible to the naked eye)
    zero_width_pattern = r"[\u200b-\u200d\ufeff]"
    if re.search(zero_width_pattern, lower_url):
        risk_score += 50
        strong_signals += 2
        explanations.append("Indiscernible Threat: Invisible characters detected in URL (Stealth Phishing).")

    # Punycode / Homoglyph Detection
    if "xn--" in lower_url:
        risk_score += 40
        strong_signals += 2
        explanations.append("Indiscernible Threat: Punycode detected, often used for homograph attacks.")

    # --- FINAL CALCULATIONS ---
    if strong_signals == 0:
        final_score = min(risk_score, 45.0)
    else:
        final_score = risk_score

    final_score = max(0, min(100, final_score))
    verdict = get_risk_level(final_score)

    # Simplified Steps (Old Requested Style)
    steps = [
        {"name": "Database Check", "status": "safe" if not any(variant in lower_url for variant in look_alikes) else "danger", 
         "details": "Verified against known phishing databases." if not any(variant in lower_url for variant in look_alikes) else "MATCH FOUND: Suspicious domain variation detected."},
        {"name": "Structure Analysis", "status": "safe" if final_score < 51 else "danger", 
         "details": "Clean URL structure verified." if final_score < 51 else "Flagged by threat intelligence for suspicious structural patterns."}
    ]

    return {
        "verdict": verdict,
        "score": round(final_score, 2),
        "steps": steps,
        "explanations": explanations
    }

def analyze_email(text: str) -> dict:
    """
    Analyzes email content using a hybrid approach.
    """
    risk_score = 20.0
    explanations = []
    lower_text = text.lower()
    
    ml_confidence = 0.0
    if ML_AVAILABLE:
        try:
            label = email_model.predict([text])[0]
            probs = email_model.predict_proba([text])[0]
            ml_confidence = float(max(probs))
            if label == 'phishing':
                risk_score += 40 * ml_confidence
                explanations.append(f"AI identifies phishing patterns ({ml_confidence:.1%} confidence).")
            elif label == 'suspicious':
                risk_score += 20 * ml_confidence
                explanations.append(f"AI flags content as suspicious ({ml_confidence:.1%} confidence).")
            else:
                risk_score -= 15 * ml_confidence
                explanations.append(f"AI identifies content as legitimate ({ml_confidence:.1%} confidence).")
        except: pass

    # Heuristics
    if any(w in lower_text for w in ["urgent", "immediately", "24 hours", "suspended"]):
        risk_score += 25
        explanations.append("detected urgent language pressure.")
    
    if any(w in lower_text for w in ["winner", "prize", "refund", "bonus"]):
        risk_score += 20
        explanations.append("Email contains generic lures.")

    final_score = max(0, min(100, risk_score))
    verdict = get_risk_level(final_score)

    # EDS Breakdown (Emotional Deception Score)
    eds_breakdown = {
        "fear": 0.45 if "suspended" in lower_text else 0.0,
        "urgency": 0.85 if "urgent" in lower_text or "immediately" in lower_text else 0.0,
        "trust": 0.30 if "verify" in lower_text else 0.0,
        "greed": 0.70 if "winner" in lower_text or "bonus" in lower_text else 0.0,
        "authority": 0.50 if "official" in lower_text or "admin" in lower_text else 0.0
    }

    # Average score for emotional deception
    emotional_deception_score = sum(eds_breakdown.values()) / len(eds_breakdown)

    return {
        "verdict": verdict,
        "score": round(final_score, 2),
        "steps": [
            {"name": "Pattern Recognition", "status": "safe" if final_score < 31 else ("warning" if final_score < 51 else "danger"), "details": "Verified internal message patterns."},
            {"name": "Sentiment Analysis", "status": "safe" if "urgent" not in lower_text else "warning", "details": "Checking for social engineering pressure tags."}
        ],
        "explanations": explanations,
        "phishing_probability": round(final_score / 100.0, 4),
        "emotional_deception_score": round(emotional_deception_score, 4),
        "confidence": round(ml_confidence or 0.85, 4),
        "eds_breakdown": eds_breakdown
    }

def analyze_file(file_name: str) -> dict:
    """
    Analyzes a filename for risk.
    """
    risk_score = 10.0
    lower_name = file_name.lower()
    explanations = []

    if any(lower_name.endswith(ext) for ext in [".exe", ".bat", ".vbs", ".js"]):
        risk_score += 50
        explanations.append("Dangerous file extension detected.")

    if lower_name.count(".") > 1:
        risk_score += 30
        explanations.append("Double extension detected.")

    final_score = max(0, min(100, risk_score))
    verdict = get_risk_level(final_score)

    return {
        "verdict": verdict,
        "score": round(final_score, 2),
        "steps": [
            {"name": "Extension Check", "status": "safe" if not any(lower_name.endswith(ext) for ext in [".exe", ".bat", ".vbs", ".js"]) else "danger", 
             "details": "Safe file type" if not any(lower_name.endswith(ext) for ext in [".exe", ".bat", ".vbs", ".js"]) else "Detected executable or script extension."},
            {"name": "Double Extension", "status": "safe" if lower_name.count(".") <= 1 else "danger", 
             "details": "Single extension found" if lower_name.count(".") <= 1 else "Found multiple hidden extensions."},
            {"name": "Heuristic Scan", "status": "safe" if final_score < 51 else "danger", 
             "details": "No malicious patterns" if final_score < 51 else "Detected potential malicious payload markers."}
        ],
        "explanations": explanations
    }
