import re
import time

def analyze_url(url):
    score = 100
    verdict = "safe"
    steps = [
        {"name": "Database Check", "status": "safe", "details": "No known threats found"},
        {"name": "Structure Analysis", "status": "safe", "details": "Standard URL structure"},
        {"name": "Brand & Keywords", "status": "safe", "details": "No mimicry or sensitive terms"},
        {"name": "Security Protocol", "status": "safe", "details": "Secure HTTPS connection"}
    ]

    lower_url = url.lower()

    # 1. KNOWN THREATS DATABASE
    known_threats = [
        "testsafebrowsing.appspot.com",
        "ianfette.org",
        "example.com/phishing",
        "malware.testing.google.test"
    ]

    if any(threat in lower_url for threat in known_threats):
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

    # 5. TYPOSQUATTING & BRAND MIMICRY
    suspicious_brands = ["g00gle", "goggle", "paypa1", "paypaI", "amaz0n", "micros0ft", "n0rton", "faceb00k", "netf1ix"]
    if any(brand in lower_url for brand in suspicious_brands):
        score -= 50
        steps[2] = {"name": "Brand & Keywords", "status": "danger", "details": "Typosquatting Detected (Brand Mimicry)"}

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

    return {"verdict": verdict, "score": max(0, score), "steps": steps}


def analyze_email(text):
    score = 100
    verdict = "safe"
    steps = [
        {"name": "Phishing Patterns", "status": "safe", "details": "No common templates matched"},
        {"name": "Urgency Analysis", "status": "safe", "details": "Tone is standard"},
        {"name": "Financial Risk", "status": "safe", "details": "No financial requests found"},
        {"name": "Link Inspection", "status": "safe", "details": "Links appear safe"}
    ]

    lower_text = text.lower()

    # 1. URGENCY / SOCIAL ENGINEERING
    urgency_words = ["urgent", "immediately", "24 hours", "suspended", "locked", "unusual activity", "action required"]
    if any(w in lower_text for w in urgency_words):
        score -= 30
        steps[1] = {"name": "Urgency Analysis", "status": "danger", "details": "High urgency/Panic induction detected"}

    # 2. FINANCIAL / CREDENTIALS
    financial_words = ["verify your account", "confirm payment", "credit card", "bank details", "password", "social security", "billing info"]
    if any(w in lower_text for w in financial_words):
        score -= 30
        steps[2] = {"name": "Financial Risk", "status": "warning", "details": "Requests for sensitive information"}

    # 3. GENERIC GREETINGS
    if len(lower_text) < 50 and ("dear customer" in lower_text or "dear user" in lower_text):
        score -= 10
        steps[0] = {"name": "Phishing Patterns", "status": "warning", "details": "Generic greeting detected"}

    # 4. SUSPICIOUS LINKS
    if any(link in lower_text for link in ["http://", "bit.ly", "tinyurl"]):
        score -= 20
        steps[3] = {"name": "Link Inspection", "status": "warning", "details": "Contains shortened or insecure links"}

    if score <= 50:
        verdict = "danger"
    elif score < 85:
        verdict = "warning"

    return {"verdict": verdict, "score": max(0, score), "steps": steps}


def analyze_file(file_name):
    score = 100
    verdict = "safe"
    steps = [
        {"name": "Extension Check", "status": "safe", "details": "Safe file type"},
        {"name": "Double Extension", "status": "safe", "details": "Single extension found"},
        {"name": "Heuristic Scan", "status": "safe", "details": "No malicious patterns"}
    ]

    lower_name = file_name.lower()

    # Double Extension
    if lower_name.count(".") > 1:
        if any(lower_name.endswith(ext) for ext in [".exe", ".bat", ".js", ".vbs"]):
            score -= 50
            steps[1] = {"name": "Double Extension", "status": "danger", "details": "Double extension masquerading detected"}

    # Executables
    if any(lower_name.endswith(ext) for ext in [".exe", ".bat", ".cmd", ".msi", ".scr"]):
        score -= 40
        if steps[0]["status"] == "safe":
            steps[0] = {"name": "Extension Check", "status": "danger", "details": "High-risk executable type"}
    # Scripts
    elif any(lower_name.endswith(ext) for ext in [".js", ".vbs", ".ps1", ".py"]):
        score -= 30
        if steps[0]["status"] == "safe":
            steps[0] = {"name": "Extension Check", "status": "warning", "details": "Script file - potential execution risk"}
    # Archives
    elif any(lower_name.endswith(ext) for ext in [".zip", ".rar", ".7z"]):
        score -= 10
        if steps[0]["status"] == "safe":
            steps[0] = {"name": "Extension Check", "status": "warning", "details": "Archive file (contents hidden)"}

    if score <= 50:
        verdict = "danger"
    elif score < 90:
        verdict = "warning"

    return {"verdict": verdict, "score": max(0, score), "steps": steps}
