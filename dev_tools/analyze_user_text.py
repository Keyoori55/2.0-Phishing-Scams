import sys
import os

# Set up paths to import from logic
sys.path.append(os.path.join(os.getcwd(), 'logic'))

from detector import analyze_email

text = """
CONFIDENTIAL DOCUMENT – ACTION REQUIRED Dear Employee, This document contains
critical updates to your salary and account credentials. ■■ WARNING: Unauthorized access has
been detected. Your credentials must be revalidated immediately. INSTRUCTIONS: 1. Open this
document in Microsoft Word. 2. ENABLE MACROS to decrypt secure content. 3. Enter your system
username and password when prompted. Failure to comply will result in: - Immediate account
suspension - Loss of salary access - Permanent restriction ---------------------------------------- SECURE
DATA ACCESS PANEL [ ENABLE CONTENT ] [ ENABLE EDITING ] This document is protected.
Macros are required to unlock hidden data. ---------------------------------------- SYSTEM ALERT
Multiple login failures detected. Security override required. ---------------------------------------- NOTE:
This is an automated system-generated file. Do not ignore. IT Security Department
"""

result = analyze_email(text)
print(f"Verdict: {result['verdict']}")
print(f"Risk Score: {result['score']}%")
print(f"Explanations: {result['explanations']}")
print(f"Emotional Deception Score: {result['emotional_deception_score']}")
print(f"EDS Breakdown: {result['eds_breakdown']}")
