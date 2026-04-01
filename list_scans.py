import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'logic'))
from database import get_db_connection

conn = get_db_connection()
cursor = conn.cursor(dictionary=True)
cursor.execute('SELECT id, identifier, risk_score, verdict, created_at FROM scan_logs WHERE scan_type = "file" ORDER BY created_at DESC LIMIT 10')
rows = cursor.fetchall()

print("Recent File Scans:")
for row in rows:
    print(f"ID: {row['id']} | File: {row['identifier']} | Score: {row['risk_score']} | Verdict: {row['verdict']} | Date: {row['created_at']}")
conn.close()
