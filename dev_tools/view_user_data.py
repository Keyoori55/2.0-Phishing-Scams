import sys
import os

# Add the project root to sys.path to allow imports from logic/
sys.path.append(os.getcwd())

from logic.database import get_db_connection

def view_all_user_data():
    """Fetches and displays all user data and scan history from the database with improved formatting."""
    print("="*60)
    print("      PHISHING DETECTOR - DATABASE COMMAND CENTER      ")
    print("="*60 + "\n")
    
    conn = get_db_connection()
    if not conn:
        print("CRITICAL ERROR: Failed to connect to the database.")
        return
        
    cursor = conn.cursor(dictionary=True)
    
    try:
        # 1. Summary
        cursor.execute("SELECT COUNT(*) as count FROM users")
        u_count = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM emails")
        e_count = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM scan_logs")
        s_count = cursor.fetchone()['count']
        
        print(f"SYSTEM SUMMARY:")
        print(f" - Total Registered Users: {u_count}")
        print(f" - Total Email Scans:     {e_count}")
        print(f" - Total URL/File Scans:  {s_count}\n")

        # 2. Users Table
        print("-" * 30)
        print(" REGISTERED USERS")
        print("-" * 30)
        cursor.execute("SELECT id, username, email FROM users ORDER BY id DESC")
        users = cursor.fetchall()
        for u in users:
            print(f"[{u['id']:2}] {u['username']:15} | {u['email']}")

        # 3. Recent Activity
        print("\n" + "-" * 30)
        print(" RECENT ACTIVITY (Top 10)")
        print("-" * 30)
        
        # Combine scans for activity feed
        query = (
            "SELECT 'Email' as type, subject as target, verdict, created_at FROM emails "
            "UNION ALL "
            "SELECT scan_type as type, identifier as target, verdict, created_at FROM scan_logs "
            "ORDER BY created_at DESC LIMIT 10"
        )
        cursor.execute(query)
        activities = cursor.fetchall()
        
        for act in activities:
            target_disp = (act['target'][:30] + '..') if len(act['target']) > 32 else act['target']
            print(f"{act['created_at'].strftime('%H:%M:%S')} | {act['type']:6} | {act['verdict']:10} | {target_disp}")

    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        cursor.close()
        conn.close()
    
    print("\n" + "="*60)

if __name__ == "__main__":
    view_all_user_data()
