import sqlite3
import os
import hashlib
from datetime import datetime

DATABASE_DIR = "database"
DATABASE_PATH = os.path.join(DATABASE_DIR, "logsentrix.db")

def get_connection():
    os.makedirs(DATABASE_DIR, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    # Standard SHA-256 password hashing
    salt = "logsentrix_salt_2026"
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Create Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # 2. Create Analyses History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyses_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_logs INTEGER NOT NULL,
        anomalies_count INTEGER NOT NULL,
        accuracy REAL NOT NULL,
        risk_score REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'Completed'
    )
    """)
    
    # 3. Create Detected Threats Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS detected_threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id INTEGER,
        timestamp TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        status_code INTEGER,
        message TEXT,
        threat_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL NOT NULL,
        remediation TEXT,
        status TEXT NOT NULL DEFAULT 'Open',
        FOREIGN KEY(analysis_id) REFERENCES analyses_history(id) ON DELETE SET NULL
    )
    """)
    
    # Migration: Add xai_explanations column if missing
    try:
        cursor.execute("ALTER TABLE detected_threats ADD COLUMN xai_explanations TEXT")
    except sqlite3.OperationalError:
        pass # column already exists
    
    # 4. Create Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT
    )
    """)
    
    # 5. Create Settings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        value TEXT NOT NULL
    )
    """)
    
    conn.commit()
    
    # Seed default roles if not present
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_users = [
            ("admin", hash_password("admin123"), "Admin"),
            ("analyst", hash_password("analyst123"), "Security Analyst"),
            ("viewer", hash_password("viewer123"), "Viewer")
        ]
        cursor.executemany("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", default_users)
        conn.commit()
        
        # Log database creation
        cursor.execute("INSERT INTO audit_logs (username, action, details) VALUES (?, ?, ?)", 
                       ("system", "DB_INIT", "Database initialized and default user roles seeded."))
        conn.commit()
        
    # Seed default settings if not present
    default_settings = [
        ("detection_threshold", "0.08"),
        ("auto_refresh_interval", "5"),
        ("email_alerts_enabled", "False"),
        ("email_alerts_recipient", "security@company.com"),
        ("sound_alerts_enabled", "True"),
        ("active_model", "Isolation Forest")
    ]
    for key, val in default_settings:
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))
    
    conn.commit()
    conn.close()

# User Management Functions
def verify_user(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    pwd_hash = hash_password(password)
    cursor.execute("SELECT username, role FROM users WHERE username = ? AND password_hash = ?", (username, pwd_hash))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"username": user["username"], "role": user["role"]}
    return None

def create_user(username, password, role, creator="admin"):
    conn = get_connection()
    cursor = conn.cursor()
    pwd_hash = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, pwd_hash, role))
        conn.commit()
        log_action(creator, "CREATE_USER", f"User '{username}' with role '{role}' successfully created.")
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

# Audit Logging
def log_action(username, action, details=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO audit_logs (username, action, details) VALUES (?, ?, ?)", (username, action, details))
    conn.commit()
    conn.close()

def get_audit_logs(limit=200):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, username, action, details FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

# Analysis Run Tracking
def add_analysis_run(filename, total_logs, anomalies_count, accuracy, risk_score):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO analyses_history (filename, total_logs, anomalies_count, accuracy, risk_score)
        VALUES (?, ?, ?, ?, ?)
    """, (filename, total_logs, anomalies_count, accuracy, risk_score))
    run_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return run_id

def get_analyses_history(limit=50):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses_history ORDER BY upload_time DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

# Threat Management
def add_threat(analysis_id, timestamp, ip_address, status_code, message, threat_type, severity, confidence, remediation, xai_explanations=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO detected_threats (analysis_id, timestamp, ip_address, status_code, message, threat_type, severity, confidence, remediation, xai_explanations, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open')
    """, (analysis_id, timestamp, ip_address, status_code, message, threat_type, severity, confidence, remediation, xai_explanations))
    threat_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return threat_id

def get_threats(analysis_id=None, limit=200):
    conn = get_connection()
    cursor = conn.cursor()
    if analysis_id is not None:
        cursor.execute("SELECT * FROM detected_threats WHERE analysis_id = ? ORDER BY timestamp DESC LIMIT ?", (analysis_id, limit))
    else:
        cursor.execute("SELECT * FROM detected_threats ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_kpis():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total historical logs analyzed
    cursor.execute("SELECT SUM(total_logs) FROM analyses_history")
    total_logs = cursor.fetchone()[0] or 0
    
    # Total anomalies detected
    cursor.execute("SELECT COUNT(*) FROM detected_threats")
    total_anomalies = cursor.fetchone()[0] or 0
    
    # Average threat risk score
    cursor.execute("SELECT AVG(risk_score) FROM analyses_history")
    avg_risk = cursor.fetchone()[0] or 0.0
    
    # Average model confidence on anomalies
    cursor.execute("SELECT AVG(confidence) FROM detected_threats")
    avg_confidence = cursor.fetchone()[0] or 95.0
    
    # Open anomalies remaining
    cursor.execute("SELECT COUNT(*) FROM detected_threats WHERE status = 'Open'")
    open_threats = cursor.fetchone()[0] or 0
    
    conn.close()
    return {
        "total_logs": total_logs,
        "total_anomalies": total_anomalies,
        "avg_risk": round(avg_risk, 2),
        "avg_confidence": round(avg_confidence, 1),
        "open_threats": open_threats
    }

def update_threat_status(threat_id, new_status, analyst_name):
    conn = get_connection()
    cursor = conn.cursor()
    
    # Fetch current threat details for the audit log
    cursor.execute("SELECT ip_address, threat_type FROM detected_threats WHERE id = ?", (threat_id,))
    threat = cursor.fetchone()
    if not threat:
        conn.close()
        return False
        
    cursor.execute("UPDATE detected_threats SET status = ? WHERE id = ?", (new_status, threat_id))
    conn.commit()
    
    details = f"Threat #{threat_id} ({threat['threat_type']} from IP {threat['ip_address']}) status set to '{new_status}'."
    log_action(analyst_name, "UPDATE_THREAT", details)
    conn.close()
    return True

# Settings Management
def get_setting(key, default_value=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row["value"]
    return default_value

def save_setting(key, value, username="system"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    log_action(username, "CHANGE_SETTING", f"Setting '{key}' modified to '{value}'.")
    conn.close()

# Initialize DB on import to ensure directories and files exist
init_db()
