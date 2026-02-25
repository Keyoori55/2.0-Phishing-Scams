import mysql.connector
from mysql.connector import errorcode
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

load_dotenv()

def get_db_connection():
    """Establishes and returns a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'ped_eds_db')
        )
        return conn
    except mysql.connector.Error as err:
        print(f"DEBUG: get_db_connection failed: {err}")
        if err.errno == errorcode.ER_BAD_DB_ERROR:
            # Create database if it doesn't exist
            print("DEBUG: Database not found, creating...")
            return create_database()
        else:
            print(f"DEBUG: Critical Connection Error: {err}")
            return None

def create_database():
    """Creates the database and returns a connection."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', '')
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {os.getenv('DB_NAME', 'ped_eds_db')}")
        conn.database = os.getenv('DB_NAME', 'ped_eds_db')
        return conn
    except mysql.connector.Error as err:
        print(f"Failed creating database: {err}")
        return None

def init_db():
    """Initializes the database schema."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    
    tables = {}
    
    # Updated emails table with user_id
    tables['emails'] = (
        "CREATE TABLE IF NOT EXISTS emails ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  user_id INT NULL,"
        "  subject TEXT,"
        "  sender VARCHAR(255),"
        "  body LONGTEXT,"
        "  phishing_probability FLOAT,"
        "  emotional_deception_score FLOAT,"
        "  verdict VARCHAR(50),"
        "  confidence FLOAT,"
        "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "  INDEX idx_sender (sender),"
        "  INDEX idx_verdict (verdict),"
        "  INDEX idx_user_id (user_id)"
        ") ENGINE=InnoDB"
    )
    
    tables['emotion_scores'] = (
        "CREATE TABLE IF NOT EXISTS emotion_scores ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  email_id INT,"
        "  fear FLOAT,"
        "  urgency FLOAT,"
        "  trust FLOAT,"
        "  greed FLOAT,"
        "  authority FLOAT,"
        "  FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE"
        ") ENGINE=InnoDB"
    )
    
    tables['training_data'] = (
        "CREATE TABLE IF NOT EXISTS training_data ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  text LONGTEXT,"
        "  label VARCHAR(50),"
        "  dataset_version VARCHAR(50),"
        "  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB"
    )
    
    # Updated scan_logs with user_id and identifier
    tables['scan_logs'] = (
        "CREATE TABLE IF NOT EXISTS scan_logs ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  user_id INT NULL,"
        "  scan_type VARCHAR(50),"
        "  identifier TEXT NULL,"
        "  risk_score FLOAT,"
        "  verdict VARCHAR(50),"
        "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "  INDEX idx_scan_type (scan_type),"
        "  INDEX idx_created_at (created_at),"
        "  INDEX idx_user_id (user_id)"
        ") ENGINE=InnoDB"
    )
    
    tables['feedback'] = (
        "CREATE TABLE IF NOT EXISTS feedback ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  name VARCHAR(255),"
        "  message TEXT,"
        "  rating INT,"
        "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB"
    )

    # Basic users table without MFA
    tables['users'] = (
        "CREATE TABLE IF NOT EXISTS users ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  username VARCHAR(255) NOT NULL UNIQUE,"
        "  email VARCHAR(255) NOT NULL UNIQUE,"
        "  password_hash VARCHAR(255) NOT NULL,"
        "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB"
    )

    tables['model_history'] = (
        "CREATE TABLE IF NOT EXISTS model_history ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  model_type VARCHAR(50),"
        "  version VARCHAR(50),"
        "  accuracy FLOAT,"
        "  f1_score FLOAT,"
        "  training_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "  active_status BOOLEAN DEFAULT TRUE"
        ") ENGINE=InnoDB"
    )
    
    for table_name in tables:
        table_description = tables[table_name]
        try:
            print(f"Creating table {table_name}: ", end='')
            cursor.execute(table_description)
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                # Check if we need to update existing tables (Simple approach)
                if table_name == 'emails':
                    try:
                        cursor.execute("ALTER TABLE emails ADD COLUMN IF NOT EXISTS user_id INT NULL")
                        cursor.execute("ALTER TABLE emails ADD INDEX IF NOT EXISTS idx_user_id (user_id)")
                    except: pass
                if table_name == 'scan_logs':
                    try:
                        cursor.execute("ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS user_id INT NULL")
                        cursor.execute("ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS identifier TEXT NULL")
                        cursor.execute("ALTER TABLE scan_logs ADD INDEX IF NOT EXISTS idx_user_id (user_id)")
                    except: pass
                print("already exists/updated.")
            else:
                print(err.msg)
        else:
            print("OK")

    cursor.close()
    conn.close()
    return True

def store_email_scan(data, emotion_breakdown, user_id=None):
    """Stores email scan results and emotion scores with user association."""
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    
    # Store email
    add_email = (
        "INSERT INTO emails "
        "(user_id, subject, sender, body, phishing_probability, emotional_deception_score, verdict, confidence) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
    )
    email_data = (
        user_id,
        data.get('subject', 'Unknown Subject'),
        data.get('sender', 'Unknown Sender'),
        data.get('body', ''),
        data.get('phishing_probability', 0.0),
        data.get('emotional_deception_score', 0.0),
        data.get('verdict', 'safe'),
        data.get('confidence', 0.0)
    )
    
    try:
        cursor.execute(add_email, email_data)
        email_id = cursor.lastrowid
        
        # Store emotion scores
        add_emotions = (
            "INSERT INTO emotion_scores "
            "(email_id, fear, urgency, trust, greed, authority) "
            "VALUES (%s, %s, %s, %s, %s, %s)"
        )
        emotion_data = (
            email_id,
            emotion_breakdown.get('fear', 0.0),
            emotion_breakdown.get('urgency', 0.0),
            emotion_breakdown.get('trust', 0.0),
            emotion_breakdown.get('greed', 0.0),
            emotion_breakdown.get('authority', 0.0)
        )
        cursor.execute(add_emotions, emotion_data)
        
        conn.commit()
        return email_id
    except mysql.connector.Error as err:
        print(f"Error storing email scan: {err}")
        conn.rollback()
        return None
    finally:
        cursor.close()
        conn.close()

def store_scan_log(scan_type, risk_score, verdict, identifier=None, user_id=None):
    """Stores a log of a URL or File scan with user association."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    add_log = (
        "INSERT INTO scan_logs "
        "(user_id, scan_type, identifier, risk_score, verdict) "
        "VALUES (%s, %s, %s, %s, %s)"
    )
    log_data = (user_id, scan_type, identifier, risk_score, verdict)
    
    try:
        cursor.execute(add_log, log_data)
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error storing scan log: {err}")
        return False
    finally:
        cursor.close()
        conn.close()

def store_feedback(name, message, rating):
    """Stores user feedback."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    add_feedback = (
        "INSERT INTO feedback "
        "(name, message, rating) "
        "VALUES (%s, %s, %s)"
    )
    feedback_data = (name, message, rating)
    
    try:
        cursor.execute(add_feedback, feedback_data)
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error storing feedback: {err}")
        return False
    finally:
        cursor.close()
        conn.close()


def create_user(username, email, password):
    """Creates a new user account with a hashed password. Returns status code."""
    conn = get_db_connection()
    if not conn:
        return "CONNECTION_ERROR"
    
    # Hash the password
    password_hash = generate_password_hash(password)
    
    cursor = conn.cursor()
    add_user = (
        "INSERT INTO users "
        "(username, email, password_hash) "
        "VALUES (%s, %s, %s)"
    )
    data = (username, email, password_hash)
    
    try:
        cursor.execute(add_user, data)
        conn.commit()
        return "SUCCESS"
    except mysql.connector.Error as err:
        print(f"Error creating user: {err}")
        if err.errno == errorcode.ER_DUP_ENTRY:
            return "ALREADY_EXISTS"
        return "ERROR"
    finally:
        cursor.close()
        conn.close()

def get_user(email):
    """Retrieves a user by email."""
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor(dictionary=True)
    query = "SELECT * FROM users WHERE email = %s"
    
    try:
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        return user
    except mysql.connector.Error as err:
        print(f"Error fetching user: {err}")
        return None
    finally:
        cursor.close()
        conn.close()

def verify_user_login(email, password):
    """Verifies user credentials. Returns (status, user_object)."""
    user = get_user(email)
    if user is None:
        # Check if specifically a connection error or just user not found
        conn = get_db_connection()
        if not conn:
            return "CONNECTION_ERROR", None
        return "INVALID_CREDENTIALS", None
        
    if check_password_hash(user['password_hash'], password):
        return "SUCCESS", user
    return "INVALID_CREDENTIALS", None


def get_all_model_history():
    """Retrieves all AI model performance records."""
    conn = get_db_connection()
    if not conn:
        return []
    
    cursor = conn.cursor(dictionary=True)
    query = "SELECT * FROM model_history ORDER BY training_date DESC"
    
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except mysql.connector.Error as err:
        print(f"Error fetching model history: {err}")
        return []
    finally:
        cursor.close()
        conn.close()

def get_user_scan_history(user_id):
    """Retrieves personalized scan history for a user."""
    conn = get_db_connection()
    if not conn:
        return []
    
    cursor = conn.cursor(dictionary=True)
    # Combine emails and scan_logs (simplified approach)
    query = (
        "SELECT 'email' as type, id, subject as identifier, verdict, created_at, phishing_probability as score "
        "FROM emails WHERE user_id = %s "
        "UNION ALL "
        "SELECT scan_type as type, id, identifier as identifier, verdict, created_at, risk_score as score "
        "FROM scan_logs WHERE user_id = %s "
        "ORDER BY created_at DESC"
    )
    
    try:
        cursor.execute(query, (user_id, user_id))
        return cursor.fetchall()
    except mysql.connector.Error as err:
        print(f"Error fetching scan history: {err}")
        return []
    finally:
        cursor.close()
        conn.close()

def log_model_performance(model_type, version, accuracy, f1_score):
    """Logs a new AI model performance record."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    add_history = (
        "INSERT INTO model_history "
        "(model_type, version, accuracy, f1_score, training_date) "
        "VALUES (%s, %s, %s, %s, %s)"
    )
    
    # Deactivate previous versions for this model type
    try:
        cursor.execute("UPDATE model_history SET active_status = FALSE WHERE model_type = %s", (model_type,))
        
        data = (model_type, version, accuracy, f1_score, datetime.now())
        cursor.execute(add_history, data)
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error logging model history: {err}")
        return False
    finally:
        cursor.close()
        conn.close()
