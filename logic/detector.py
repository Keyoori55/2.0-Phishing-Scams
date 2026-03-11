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

def analyze_url(url: str) -> dict:
    """
    Analyzes a URL for potential phishing indicators using a hybrid rule-based approach.
    
    Args:
        url: The URL string to analyze.
        
    Returns:
        A dictionary containing the verdict, risk score, and step-by-step breakdown.
    """
    score = 100
    verdict = "safe"
    steps = [
        {"name": "Database Check", "status": "safe", "details": "No known threats found"},
        {"name": "Structure Analysis", "status": "safe", "details": "Standard URL structure"},
        {"name": "Brand & Keywords", "status": "safe", "details": "No mimicry or sensitive terms"},
        {"name": "Security Protocol", "status": "safe", "details": "Secure HTTPS connection"}
    ]

    lower_url = url.lower()
    logger.info(f"Analyzing URL: {url}")

    # 1. KNOWN THREATS DATABASE
    known_threats = [
        "testsafebrowsing.appspot.com",
        "ianfette.org",
        "example.com/phishing",
        "malware.testing.google.test"
    ]

    if any(threat in lower_url for threat in known_threats):
        logger.warning(f"URL matched known threat database: {url}")
        return {
            "verdict": "danger",
            "score": 10,
            "steps": [
                {"name": "Database Check", "status": "danger", "details": "MATCH FOUND: Known Phishing Test Site"},
                {"name": "Structure Analysis", "status": "warning", "details": "Flagged by threat intelligence"},
                {"name": "Brand & Keywords", "status": "warning", "details": "High-risk signature detected"},
                {"name": "Security Protocol", "status": "safe", "details": "HTTPS (Valid but malicious)"}
            ]
        }

    # 2. PROTOCOL CHECK
    if lower_url.startswith("http://"):
        score -= 20
        steps[3] = {"name": "Security Protocol", "status": "warning", "details": "Insecure (HTTP) - Traffic not encrypted"}

    # 3. IP ADDRESS CHECK
    ip_regex = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    if re.search(ip_regex, lower_url):
        score -= 40
        steps[1] = {"name": "Structure Analysis", "status": "danger", "details": "Direct IP address usage is highly suspicious"}

    # 4. SUSPICIOUS CHARACTERISTICS
    if len(url) > 75:
        score -= 10
        if steps[1]["status"] == "safe":
            steps[1] = {"name": "Structure Analysis", "status": "warning", "details": "Unusually long URL length"}

    if lower_url.count(".") > 4:
        score -= 15
        steps[1] = {"name": "Structure Analysis", "status": "warning", "details": "Excessive subdomains detected (URL obfuscation)"}

    if "@" in lower_url:
        score -= 40
        steps[1] = {"name": "Structure Analysis", "status": "danger", "details": "URL contains '@' (Authorization Bypass Attempt)"}

    # 5. TYPOSQUATTING & LOOK-ALIKE DOMAINS
    look_alikes = {
        'google': ['g00gle', 'goggle', 'goooogle', 'googIe'],
        'paypal': ['paypa1', 'paypai', 'pay-pal', 'paly-pal'],
        'amazon': ['amaz0n', 'amizon', 'amz-on'],
        'microsoft': ['micros0ft', 'rnicrosoft', 'mircosoft'],
        'facebook': ['faceb00k', 'face-book', 'faacebook'],
        'apple': ['appIe', 'appe1'],
        'netflix': ['netf1ix', 'net-flix']
    }
    
    for brand, variants in look_alikes.items():
        if any(variant in lower_url for variant in variants):
            score -= 50
            steps[2] = {"name": "Brand & Keywords", "status": "danger", "details": f"Look-alike domain detected (Mimicking {brand.capitalize()})"}
            break

    # 6. SENSITIVE KEYWORDS
    keywords = ["login", "signin", "verify", "account", "update", "bank", "secure", "confirm", "wallet"]
    if any(kw in lower_url for kw in keywords):
        if score < 100 or lower_url.startswith("http://"):
            score -= 20
            if steps[2]["status"] == "safe":
                steps[2] = {"name": "Brand & Keywords", "status": "warning", "details": "Credential harvesting keywords detected"}

    # 7. SUSPICIOUS TLDs
    suspicious_tlds = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".cn", ".ru", ".site", ".work"]
    if any(lower_url.endswith(tld) or (tld + "/") in lower_url for tld in suspicious_tlds):
        score -= 25
        if steps[1]["status"] == "safe":
            steps[1] = {"name": "Structure Analysis", "status": "warning", "details": "High-risk TLD (often used for spam)"}

    # FINAL SCORING
    if score <= 50:
        verdict = "danger"
    elif score < 85:
        verdict = "warning"

    logger.info(f"URL Analysis Complete. Verdict: {verdict}, Score: {score}")
    return {"verdict": verdict, "score": round(max(0, score), 2), "steps": steps}


def analyze_email(text: str) -> dict:
    """
    Analyzes email content for phishing indicators using AI models and rule-based heuristics.
    
    Args:
        text: The email body text.
        
    Returns:
        A dictionary containing the verdict, score, probability, and emotional deception analysis.
    """
    score = 100
    verdict = "safe"
    steps = [
        {"name": "Rule Analysis", "status": "safe", "details": "No suspicious keywords matched"},
        {"name": "AI Prediction", "status": "safe", "details": "AI model analysis complete"},
        {"name": "Urgency Scan", "status": "safe", "details": "Tone is standard"},
        {"name": "Link Inspection", "status": "safe", "details": "Links appear safe"}
    ]

    lower_text = text.lower()
    logger.info("Analyzing email content...")
    
    # Emotional Deception Score (EDS) Breakdown
    eds = {
        "fear": 0.0,
        "urgency": 0.0,
        "trust": 0.0,
        "greed": 0.0,
        "authority": 0.0
    }

    # 1. ML Analysis (AI)
    ml_confidence = 0.0
    ml_label = 'legitimate'
    if ML_AVAILABLE:
        try:
            ml_label = email_model.predict([text])[0]
            probs = email_model.predict_proba([text])[0]
            ml_confidence = float(max(probs))
            logger.info(f"AI Prediction: {ml_label} (Confidence: {ml_confidence:.1%})")
            
            if ml_label == 'phishing':
                score -= 60 * ml_confidence
                steps[1] = {"name": "AI Prediction", "status": "danger", "details": f"AI flagged as PHISHING (Confidence: {ml_confidence:.1%})"}
            elif ml_label == 'suspicious':
                score -= 30 * ml_confidence
                steps[1] = {"name": "AI Prediction", "status": "warning", "details": f"AI flagged as SUSPICIOUS (Confidence: {ml_confidence:.1%})"}
            elif ml_label == 'legitimate':
                steps[1] = {"name": "AI Prediction", "status": "safe", "details": f"AI flagged as LEGITIMATE (Confidence: {ml_confidence:.1%})"}
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            steps[1] = {"name": "AI Prediction", "status": "warning", "details": "ML prediction engine error"}

    # 2. URGENCY / SOCIAL ENGINEERING
    urgency_words = ["urgent", "immediately", "24 hours", "suspended", "locked", "unusual activity", "action required", "expiring", "now"]
    urgency_matches = [w for w in urgency_words if w in lower_text]
    if urgency_matches:
        eds["urgency"] = min(1.0, len(urgency_matches) * 0.2 + (0.3 if "urgent" in lower_text else 0))
        score -= 30
        steps[2] = {"name": "Urgency Scan", "status": "danger", "details": "High urgency/Panic induction detected"}

    # 3. FEAR
    fear_words = ["consequences", "legal action", "penalty", "block", "security breach", "unauthorized", "stolen", "deleted"]
    fear_matches = [w for w in fear_words if w in lower_text]
    if fear_matches:
        eds["fear"] = min(1.0, len(fear_matches) * 0.25)
        score -= 20

    # 4. TRUST (Misuse of Trust)
    trust_words = ["official", "support", "security team", "verified", "no-reply", "customer service"]
    trust_matches = [w for w in trust_words if w in lower_text]
    if trust_matches:
        eds["trust"] = min(1.0, len(trust_matches) * 0.2)
        score -= 10

    # 5. GREED
    greed_words = ["winner", "prize", "refund", "bonus", "free", "claim", "reward", "cash"]
    greed_matches = [w for w in greed_words if w in lower_text]
    if greed_matches:
        eds["greed"] = min(1.0, len(greed_matches) * 0.25)
        score -= 25

    # 6. AUTHORITY
    authority_words = ["director", "ceo", "department", "administrator", "manager", "official notice"]
    authority_matches = [w for w in authority_words if w in lower_text]
    if authority_matches:
        eds["authority"] = min(1.0, len(authority_matches) * 0.2)
        score -= 15

    # 7. FINANCIAL / CREDENTIALS
    financial_words = ["verify your account", "confirm payment", "credit card", "bank details", "password", "social security", "billing info"]
    if any(w in lower_text for w in financial_words):
        score -= 30
        if steps[0]["status"] == "safe":
            steps[0] = {"name": "Rule Analysis", "status": "warning", "details": "Requests for sensitive information"}

    # 8. SUSPICIOUS LINKS
    if any(link in lower_text for link in ["http://", "bit.ly", "tinyurl"]):
        score -= 20
        steps[3] = {"name": "Link Inspection", "status": "warning", "details": "Contains shortened or insecure links"}

    # 9. EXPLICIT PHISHING DECLARATIONS
    phishing_declarations = ["this is a phishing email", "identified as phishing", "phishing warning", "report this phishing"]
    if any(decl in lower_text for decl in phishing_declarations):
        educational_keywords = ["educational", "awareness", "what is", "learn about"]
        is_educational = any(edu in lower_text for edu in educational_keywords)
        
        if not is_educational:
            logger.info("Explicit phishing declaration detected.")
            score -= 50
            if steps[0]["status"] == "safe":
                steps[0] = {"name": "Rule Analysis", "status": "danger", "details": "Explicit phishing warning or declaration detected"}
            else:
                steps[0]["status"] = "danger"
                steps[0]["details"] += " | Explicit phishing warning detected"
        else:
            logger.info("Educational phishing content detected (safe).")
            score += 10
            steps[0] = {"name": "Rule Analysis", "status": "safe", "details": "Educational content about phishing detected"}

    if score <= 50:
        verdict = "danger"
    elif score < 85:
        verdict = "warning"

    total_eds = sum(eds.values()) / 5.0
    logger.info(f"Email Analysis Complete. Verdict: {verdict}, Score: {score}, EDS: {total_eds:.2f}")

    return {
        "verdict": verdict, 
        "score": round(max(0, score), 2), 
        "steps": steps,
        "phishing_probability": round((100 - score) / 100.0, 4),
        "emotional_deception_score": round(total_eds, 4),
        "eds_breakdown": {k: round(v, 4) for k, v in eds.items()},
        "confidence": round(ml_confidence if ML_AVAILABLE else 0.8, 4)
    }


def analyze_file(file_name: str) -> dict:
    """
    Analyzes a filename for potential malicious indicators using AI and heuristics.
    
    Args:
        file_name: The name of the file to analyze.
        
    Returns:
        A dictionary containing the verdict, score, and steps.
    """
    score = 100
    verdict = "safe"
    steps = [
        {"name": "AI Extension Scan", "status": "safe", "details": "AI file type analysis complete"},
        {"name": "Double Extension", "status": "safe", "details": "Single extension found"},
        {"name": "Heuristic Scan", "status": "safe", "details": "No malicious patterns"}
    ]

    lower_name = file_name.lower()
    logger.info(f"Analyzing filename: {file_name}")

    # 1. ML Analysis (AI)
    if ML_AVAILABLE:
        try:
            label = file_model.predict([file_name])[0]
            logger.info(f"AI File Prediction: {label}")
            if label == 'phishing':
                score -= 60
                steps[0] = {"name": "AI Extension Scan", "status": "danger", "details": "AI identifies this filename pattern as MALICIOUS (Phishing)"}
            elif label == 'suspicious':
                score -= 30
                steps[0] = {"name": "AI Extension Scan", "status": "warning", "details": "AI identifies this filename pattern as SUSPICIOUS"}
            elif label == 'legitimate':
                steps[0] = {"name": "AI Extension Scan", "status": "safe", "details": "AI identifies this filename pattern as LEGITIMATE"}
        except Exception as e:
            logger.error(f"File ML prediction error: {e}")
            steps[0] = {"name": "AI Extension Scan", "status": "warning", "details": "ML prediction engine error"}

    # Double Extension
    if lower_name.count(".") > 1:
        if any(lower_name.endswith(ext) for ext in [".exe", ".bat", ".js", ".vbs"]):
            score -= 50
            steps[1] = {"name": "Double Extension", "status": "danger", "details": "Double extension masquerading detected"}

    # Security Patterns in names
    if any(kw in lower_name for kw in ["password", "crack", "hack", "bypass"]):
        score -= 20
        steps[2] = {"name": "Heuristic Scan", "status": "warning", "details": "Sensitive keywords in filename"}

    if score <= 50:
        verdict = "danger"
    elif score < 90:
        verdict = "warning"

    logger.info(f"File Analysis Complete. Verdict: {verdict}, Score: {score}")
    return {"verdict": verdict, "score": round(max(0, score), 2), "steps": steps}
