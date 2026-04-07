import sys
import os
from datetime import datetime

# Add logic folder to path
sys.path.append(os.getcwd())
from logic.database import get_dashboard_stats, init_db

def test_dashboard_data():
    print("=== Dashboard Data Verification ===")
    init_db()
    
    # Simulate a user ID (e.g., 999)
    user_id = 999
    stats = get_dashboard_stats(user_id)
    
    if not stats:
        print("FAILURE: get_dashboard_stats returned None")
        return

    # Check 7-Day Trends
    labels = stats['scans_over_time']['labels']
    data = stats['scans_over_time']['data']
    
    print(f"Activity Trend Labels: {labels}")
    print(f"Activity Trend Data: {data}")
    
    if len(labels) == 7 and len(data) == 7:
        print("SUCCESS: 7-day trends correctly initialized with 7 points.")
    else:
        print(f"FAILURE: Expected 7 points, got {len(labels)} labels and {len(data)} data points.")

    # Check KPIs
    kpis = stats['kpis']
    print(f"KPIs: {kpis}")
    if all(k in kpis for k in ['total_scans', 'threats_blocked', 'avg_risk', 'system_accuracy']):
        print("SUCCESS: All required KPIs are present.")
    else:
        print("FAILURE: Missing KPI fields.")

if __name__ == "__main__":
    test_dashboard_data()
