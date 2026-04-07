import mysql.connector
from mysql.connector import errorcode
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

load_dotenv()

def get_db_connection():
    """Establishes and returns a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
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
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD')
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
    
    # Updated scan_logs with user_id, identifier and emotion scores
    tables['scan_logs'] = (
        "CREATE TABLE IF NOT EXISTS scan_logs ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  user_id INT NULL,"
        "  scan_type VARCHAR(50),"
        "  identifier TEXT NULL,"
        "  risk_score FLOAT,"
        "  verdict VARCHAR(50),"
        "  fear FLOAT DEFAULT 0.0,"
        "  urgency FLOAT DEFAULT 0.0,"
        "  trust FLOAT DEFAULT 0.0,"
        "  greed FLOAT DEFAULT 0.0,"
        "  authority FLOAT DEFAULT 0.0,"
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
        "  precision_score FLOAT,"
        "  recall_score FLOAT,"
        "  f1_score FLOAT,"
        "  training_duration FLOAT,"
        "  dataset_size INT,"
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
                print("already exists.")
            else:
                print(err.msg)
        else:
            print("OK")

        # --- Update existing tables with new columns if needed ---
        if table_name == 'emails':
            try:
                cursor.execute("ALTER TABLE emails ADD COLUMN user_id INT NULL")
            except mysql.connector.Error as err:
                if err.errno != 1060: pass
            try:
                cursor.execute("ALTER TABLE emails ADD INDEX idx_user_id (user_id)")
            except: pass

        if table_name == 'scan_logs':
            columns_to_add = [
                ("user_id", "INT NULL"),
                ("identifier", "TEXT NULL"),
                ("fear", "FLOAT DEFAULT 0.0"),
                ("urgency", "FLOAT DEFAULT 0.0"),
                ("trust", "FLOAT DEFAULT 0.0"),
                ("greed", "FLOAT DEFAULT 0.0"),
                ("authority", "FLOAT DEFAULT 0.0")
            ]
            for col_name, col_type in columns_to_add:
                try:
                    cursor.execute(f"ALTER TABLE scan_logs ADD COLUMN {col_name} {col_type}")
                except mysql.connector.Error as err:
                    if err.errno != 1060:
                        print(f"Error adding column {col_name} to scan_logs: {err.msg}")
            try:
                cursor.execute("ALTER TABLE scan_logs ADD INDEX idx_user_id (user_id)")
            except: pass

        if table_name == 'model_history':
            columns_to_add = [
                ("precision_score", "FLOAT"),
                ("recall_score", "FLOAT"),
                ("f1_score", "FLOAT"),
                ("training_duration", "FLOAT"),
                ("dataset_size", "INT")
            ]
            for col_name, col_type in columns_to_add:
                try:
                    cursor.execute(f"ALTER TABLE model_history ADD COLUMN {col_name} {col_type}")
                except mysql.connector.Error as err:
                    if err.errno != 1060:
                        print(f"Error adding column {col_name} to model_history: {err.msg}")

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

def store_scan_log(scan_type, risk_score, verdict, identifier=None, user_id=None, emotions=None):
    """Stores a log of a URL or File scan with emotion scores."""
    conn = get_db_connection()
    if not conn:
        return False
    
    if emotions is None:
        emotions = {}

    cursor = conn.cursor()
    add_log = (
        "INSERT INTO scan_logs "
        "(user_id, scan_type, identifier, risk_score, verdict, fear, urgency, trust, greed, authority) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )
    log_data = (
        user_id, scan_type, identifier, risk_score, verdict,
        emotions.get('fear', 0.0),
        emotions.get('urgency', 0.0),
        emotions.get('trust', 0.0),
        emotions.get('greed', 0.0),
        emotions.get('authority', 0.0)
    )
    
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

def log_model_performance(model_type, version, accuracy, precision, recall, f1, duration=0, size=0):
    """Logs a new AI model performance record with detailed metrics."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    add_history = (
        "INSERT INTO model_history "
        "(model_type, version, accuracy, precision_score, recall_score, f1_score, training_duration, dataset_size, training_date) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )
    
    # Deactivate previous versions for this model type
    try:
        cursor.execute("UPDATE model_history SET active_status = FALSE WHERE model_type = %s", (model_type,))
        
        data = (model_type, version, float(accuracy), float(precision), float(recall), float(f1), float(duration), int(size), datetime.now())
        cursor.execute(add_history, data)
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error logging model history: {err}")
        return False
    finally:
        cursor.close()
        conn.close()
def get_dashboard_stats(user_id):
    """Aggregates statistics for dashboard charts."""
    conn = get_db_connection()
    if not conn:
        return None
    
    stats = {
        'kpis': {
            'total_scans': 0,
            'threats_blocked': 0,
            'avg_risk': 0,
            'system_accuracy': 0.94 
        },
        'phishing_vs_legitimate': {'phishing': 0, 'legitimate': 0},
        'scan_distribution': {'url': 0, 'email': 0, 'file': 0},
        'scans_over_time': {'labels': [], 'data': []},
        'risk_distribution': {'low': 0, 'medium': 0, 'high': 0},
        'top_indicators': {'labels': ['Fear', 'Urgency', 'Trust', 'Greed', 'Authority'], 'data': [0, 0, 0, 0, 0]}
    }
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Fetch current system accuracy from model history
        cursor.execute("SELECT accuracy FROM model_history WHERE active_status = TRUE LIMIT 1")
        model_row = cursor.fetchone()
        if model_row:
            stats['kpis']['system_accuracy'] = round(float(model_row['accuracy']), 4)

        # 1. Combined Scans Data
        query_combined = (
            "SELECT type, verdict, score, created_at FROM ("
            "  SELECT 'email' as type, verdict, phishing_probability as score, created_at FROM emails WHERE user_id = %s "
            "  UNION ALL "
            "  SELECT scan_type as type, verdict, risk_score as score, created_at FROM scan_logs WHERE user_id = %s"
            ") as combined"
        )
        cursor.execute(query_combined, (user_id, user_id))
        rows = cursor.fetchall()
        
        total_risk_sum = 0
        for row in rows:
            stats['kpis']['total_scans'] += 1
            score = float(row['score'])
            if score > 1.0: # Normalize legacy 0-100 scores
                score = score / 100.0
                
            total_risk_sum += (score * 100)
            
            # Phishing vs Legitimate
            if row['verdict'] in ['danger', 'phishing', 'High Risk', 'high']:
                stats['phishing_vs_legitimate']['phishing'] += 1
                stats['kpis']['threats_blocked'] += 1
            elif row['verdict'] in ['safe', 'Safe']:
                stats['phishing_vs_legitimate']['legitimate'] += 1
                
            # Scan Distribution
            s_type = row['type']
            if s_type in stats['scan_distribution']:
                stats['scan_distribution'][s_type] += 1
                
            # Risk Distribution (0-0.3 Safe, 0.31-0.6 Suspicious, 0.61-1.0 High)
            if score <= 0.3:
                stats['risk_distribution']['low'] += 1
            elif score <= 0.6:
                stats['risk_distribution']['medium'] += 1
            else:
                stats['risk_distribution']['high'] += 1
        
        if stats['kpis']['total_scans'] > 0:
            stats['kpis']['avg_risk'] = round(total_risk_sum / stats['kpis']['total_scans'], 1)

        # 2. Scans Over Time (Last 7 days - with 0 mapping)
        days = []
        for i in range(6, -1, -1):
            day = datetime.now() - timedelta(days=i)
            days.append(day.strftime('%Y-%m-%d'))
        
        # Initialize day map
        day_map = {day: 0 for day in days}
        
        query_t = (
            "SELECT DATE(created_at) as date, COUNT(*) as count FROM ("
            "  SELECT created_at FROM emails WHERE user_id = %s "
            "  UNION ALL "
            "  SELECT created_at FROM scan_logs WHERE user_id = %s"
            ") as combined "
            "WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) "
            "GROUP BY DATE(created_at) ORDER BY DATE(created_at)"
        )
        cursor.execute(query_t, (user_id, user_id))
        t_rows = cursor.fetchall()
        for row in t_rows:
            date_str = row['date'].strftime('%Y-%m-%d')
            if date_str in day_map:
                day_map[date_str] = row['count']
        
        # Fill stats
        for date_str in days:
            d_obj = datetime.strptime(date_str, '%Y-%m-%d')
            stats['scans_over_time']['labels'].append(d_obj.strftime('%a'))
            stats['scans_over_time']['data'].append(day_map[date_str])

        # 4. Top Indicators (Merged Averages from Emails and Scan Logs)
        query_i = (
            "SELECT AVG(fear) as fear, AVG(urgency) as urgency, AVG(trust) as trust, "
            "AVG(greed) as greed, AVG(authority) as authority FROM ("
            "  SELECT fear, urgency, trust, greed, authority FROM emotion_scores es "
            "  JOIN emails e ON es.email_id = e.id WHERE e.user_id = %s "
            "  UNION ALL "
            "  SELECT fear, urgency, trust, greed, authority FROM scan_logs WHERE user_id = %s"
            ") as merged_emotions"
        )
        cursor.execute(query_i, (user_id, user_id))
        i_row = cursor.fetchone()
        if i_row and i_row['fear'] is not None:
            print(f"DEBUG: Found emotion data: {i_row}")
            stats['top_indicators']['data'] = [
                round(float(i_row['fear']), 2),
                round(float(i_row['urgency']), 2),
                round(float(i_row['trust']), 2),
                round(float(i_row['greed']), 2),
                round(float(i_row['authority']), 2)
            ]
        else:
            print("DEBUG: No emotion data found or averages were None")
            # Provide zeroed data if no scans yet, ensuring chart isn't empty
            stats['top_indicators']['data'] = [0, 0, 0, 0, 0]

        return stats
    except mysql.connector.Error as err:
        print(f"DEBUG: Error fetching dashboard stats: {err}")
        return None
    finally:
        cursor.close()
        conn.close()
