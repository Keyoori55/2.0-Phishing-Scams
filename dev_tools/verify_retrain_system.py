import sys
import os

# Add logic folder to path
sys.path.append(os.getcwd())

from logic.database import init_db, get_db_connection
from train_model import train_email_model

def test_retrain_system():
    print("=== AI Retraining Verification ===")
    
    # 1. Initialize DB (ensure columns exist)
    print("Initializing Database...")
    init_db()
    
    # 2. Trigger Retrain
    print("Triggering Email Model Retrain...")
    acc, f1 = train_email_model()
    
    if acc == 0:
        print("FAILURE: Training failed (possibly due to dataset guardrails).")
        return

    # 3. Verify Database Record
    print("\nVerifying Database Record...")
    conn = get_db_connection()
    if not conn:
        print("FAILURE: Could not connect to database.")
        return
        
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM model_history ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    
    if row:
        print(f"Record Found: ID {row['id']}")
        print(f"Model: {row['model_type']}")
        print(f"Accuracy: {row['accuracy']:.4f}")
        print(f"Training Samples: {row['dataset_size']}")
        print(f"Training Duration: {row['training_duration']:.4f}s")
        
        if row['dataset_size'] > 0 and row['training_duration'] > 0:
            print("\nSUCCESS: Detailed metrics captured and stored correctly.")
        else:
            print("\nFAILURE: Metrics (size/duration) are missing or zero.")
    else:
        print("FAILURE: No record found in model_history.")
        
    cursor.close()
    conn.close()

if __name__ == "__main__":
    test_retrain_system()
