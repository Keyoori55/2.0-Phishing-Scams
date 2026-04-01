import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_file_scan(name, content):
    print(f"\nTesting File Scan: {name}")
    files = {'file': (name, content)}
    try:
        response = requests.post(f"{BASE_URL}/api/scan/file", files=files)
        if response.status_code == 200:
            result = response.json()
            print(f"Verdict: {result['verdict']}")
            print(f"Score: {result['score']}%")
            print(f"Explanations: {result['explanations']}")
        else:
            print(f"Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    # Test 1: Clean file
    test_file_scan("clean_doc.txt", "This is a normal document with no suspicious code.")
    
    # Test 2: Suspicious filename only
    test_file_scan("update.exe", "Normal installer content")
    
    # Test 3: Suspicious content (PowerShell)
    test_file_scan("script.txt", "powershell.exe -ExecutionPolicy Bypass -Command 'Invoke-WebRequest ...'")
    
    # Test 4: Obfuscated/High entropy content
    test_file_scan("data.bin", "@@@@####$$$$%%%%^^^^&&&&****(((())))" * 10)
