import requests
import os

BASE_URL = "http://127.0.0.1:5000"

def test_file_scan(name, content):
    print(f"\n--- Testing File Scan: {name} ---")
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
    # Simulate a malicious PDF (text-based representation for now)
    # A real PDF would be binary, but we want to see if these patterns are caught
    malicious_pdf_content = """
    %PDF-1.7
    1 0 obj
    <</Type /Catalog /Pages 2 0 R /OpenAction 3 0 R>>
    endobj
    2 0 obj
    <</Type /Pages /Kids [4 0 R] /Count 1>>
    endobj
    3 0 obj
    <</Type /Action /S /JavaScript /JS (app.alert('Malicious!');)>>
    endobj
    4 0 obj
    <</Type /Page /Parent 2 0 R /Contents 5 0 R>>
    endobj
    5 0 obj
    <</Length 44>>
    stream
    BT /F1 12 Tf 70 700 Td (Hello World) Tj ET
    endstream
    endobj
    xref
    0 6
    0000000000 65535 f 
    0000000009 00000 n 
    0000000062 00000 n 
    0000000114 00000 n 
    0000000182 00000 n 
    0000000236 00000 n 
    trailer
    <</Size 6 /Root 1 0 R>>
    startxref
    312
    %%EOF
    """
    
    test_file_scan("invoice.pdf", malicious_pdf_content)

    # Test with a suspicious filename not in the hardcoded list but maybe in ML?
    # Actually, let's try a filename that's "phishing" in files.csv but not in the hardcoded extension list
    test_file_scan("password_reset.html", "<html><body>Login here</body></html>")
