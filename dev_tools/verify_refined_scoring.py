import sys
import os

# Add current directory to sys.path
sys.path.append(os.getcwd())

from logic.detector import analyze_url

def test_url(url, expected_verdict):
    print(f"\nTesting URL: {url}")
    result = analyze_url(url)
    print(f"Verdict: {result['verdict']}")
    print(f"Safety Score: {result['score']}")
    
    # Check if verdict matches expected
    if result['verdict'] == expected_verdict:
        print(f"SUCCESS: Match with expected verdict '{expected_verdict}'.")
    else:
        print(f"FAILURE: Expected '{expected_verdict}', got '{result['verdict']}'.")

urls = [
    ("https://google.com", "Safe"),
    ("http://google.com", "Safe"),
    ("https://google.com/login", "Safe"),
    ("http://127.0.0.1/login", "Safe"),
    ("http://8.8.8.8/verify", "High Risk"),
    ("https://g00gle.com/login", "High Risk"),
    ("http://scam-site.xyz/update", "High Risk")
]

for url, expected in urls:
    test_url(url, expected)
