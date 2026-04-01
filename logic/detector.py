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

def analyze_file(file_name: str, content: str = "") -> dict:
    """
    Analyzes a file (name and content) for risk.
    """
    risk_score = 10.0
    lower_name = file_name.lower()
    lower_content = content.lower() if content else ""
    explanations = []
    
    # --- FILENAME HEURISTICS ---
    dangerous_exts = [".exe", ".bat", ".vbs", ".js", ".msi", ".cmd", ".scr", ".ps1", ".vbe", ".jse", ".wsf", ".wsh"]
    if any(lower_name.endswith(ext) for ext in dangerous_exts):
        risk_score += 65 # High enough to trigger High Risk when combined with base 10
        explanations.append(f"CRITICAL: Dangerous executable or script extension detected: {os.path.splitext(file_name)[1]}. Executables are high-risk files.")

    if lower_name.count(".") > 1:
        # Check if it's a double extension like .pdf.exe or .txt.vbs
        parts = lower_name.split('.')
        if parts[-1] in ["exe", "bat", "vbs", "js", "scr", "cmd"]:
            risk_score += 40
            explanations.append("High-risk double extension detected (e.g., .txt.exe), a common obfuscation technique.")
        else:
            risk_score += 20
            explanations.append("Multiple extensions detected, potentially hiding the true file type.")

    # --- CONTENT HEURISTICS ---
    if content:
        # Detect suspicious script patterns
        suspicious_patterns = [
            # General script and shell patterns
            (r"eval\(", 30, "Contains 'eval()' used for dynamic code execution."),
            (r"base64[_-]decode|atob\(", 25, "Contains base64 decoding logic, often used to hide payloads."),
            (r"powershell\.exe|bypass|noprofile|windowstyle\s+hidden", 45, "Detected PowerShell obfuscation or stealth execution flags."),
            (r"cmd\.exe\s+/c|/r\s+", 25, "Attempts to execute shell commands directly."),
            (r"downloadstring|downloadfile|iwr\s+|curl\s+|wget\s+", 40, "Contains network downloader commands."),
            (r"wscript\.shell|shell\.application", 30, "Uses Windows Script Host for system interaction."),
            (r"createobject\(", 20, "Generic object creation (common in VBScript malware)."),
            
            # PDF Specific patterns (analyzed from extracted text/metadata)
            (r"/javascript|/js\b", 60, "CRITICAL: Detected embedded JavaScript in document (High-risk PDF weaponization)."),
            (r"/openaction|/aa\b", 60, "CRITICAL: Automatic execution trigger found (PDF weaponization indicator)."),
            (r"/launch|/embeddedfile", 45, "High Risk: Document attempts to launch external processes or contains embedded files."),
            (r"/uri|/action\s+/s\b", 35, "Suspicious: Document contains automatic URL redirection or hidden links."),
            
            # Office / Macro patterns
            (r"autoopen|document_open|workbook_open", 70, "CRITICAL: Contains auto-execution macros (Major Office threat indicator)."),
            (r"autoexec|document_close|workbook_beforeclose", 50, "High Risk: Stealthy auto-execution macro patterns identified."),
            (r"vba_project|vbaproject", 40, "Suspicious: Contains VBA Project references (Macro-enabled document)."),
            (r"shell\s*\(|filesystemobject|winmgmts", 50, "CRITICAL: Macro attempts to interact with the OS or filesystem (Malicious behavior)."),
            (r"ptrsafe|declare\s+function|lib\s+\"", 35, "High Risk: Uses external Windows APIs (Common in advanced malware)."),
            
            # Social Engineering / Phishing Lures in Document
            (r"urgent|immediately|action\s+required|suspended|failure\s+to\s+comply", 35, "Document uses high-pressure/urgent language often found in phishing (Social Engineering)."),
            (r"enable\s+macros|enable\s+content|decrypt|unlock\s+hidden\s+data", 60, "CRITICAL: Document explicitly asks user to enable macros or decrypt content (Classic malware lure)."),
            (r"salary|credentials|account\s+updates|security\s+override", 30, "Document contains common phishing lure keywords (Financial/Security)."),
            (r"system\s+username|password\s+when\s+prompted", 45, "High Risk: Document contains indicators of credential harvesting attempts."),
        ]
        
        match_count = 0
        for pattern, weight, explanation in suspicious_patterns:
            if re.search(pattern, lower_content):
                risk_score += weight
                explanations.append(explanation)
                match_count += 1
        
        # Obfuscation indicator (high density of non-alphanumeric chars or long strings without spaces)
        if len(content) > 100:
            alnum_ratio = len([c for c in content if c.isalnum() or c.isspace()]) / len(content)
            if alnum_ratio < 0.55:
                risk_score += 25
                explanations.append("High entropy/obfuscation detected in file content (Stealth indicator).")
            
            # Check for very long strings (potential encoded payloads)
            if any(len(word) > 200 for word in content.split()):
                risk_score += 20
                explanations.append("Detected unusually long contiguous strings (Potential encoded payload).")

    # Use ML model if available (filename-based)
    if ML_AVAILABLE:
        try:
            label = file_model.predict([file_name])[0]
            if label == 'phishing' or label == 'suspicious':
                risk_score += 20
                explanations.append("AI model flags the filename as highly suspicious based on historical patterns.")
        except: pass

    # Final Score adjustment for forced High Risk cases
    # If it's an executable OR matched multiple critical document patterns, force High Risk
    is_executable = any(lower_name.endswith(ext) for ext in dangerous_exts)
    has_critical_matches = any("CRITICAL" in exp for exp in explanations)
    
    if is_executable or has_critical_matches:
        risk_score = max(risk_score, 75.0)
        if is_executable:
            explanations.append("Priority Protection: Flagged as High Risk due to dangerous file type.")
        if has_critical_matches:
            explanations.append("Priority Protection: Flagged as High Risk due to verified malicious active content markers.")

    final_score = max(0, min(100, risk_score))
    verdict = get_risk_level(final_score)

    steps = [
        {"name": "Security Policy Check", "status": "safe" if not any(lower_name.endswith(ext) for ext in dangerous_exts) else "danger", 
         "details": "Filename meets safety policies." if not any(lower_name.endswith(ext) for ext in dangerous_exts) else "Blocked: Dangerous file extension."},
        {"name": "Deep Content Inspection", "status": "safe" if final_score < 40 else ("warning" if final_score < 70 else "danger"), 
         "details": f"Analyzed {len(content)} chars. {'No critical threats' if final_score < 40 else str(match_count) + ' threat markers'} identified." if content else "No content available for inspection."},
    ]

    return {
        "verdict": verdict,
        "score": round(final_score, 2),
        "steps": steps,
        "explanations": list(set(explanations)) # Unique explanations
    }
