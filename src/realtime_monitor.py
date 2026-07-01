import os
import random
import time
import pandas as pd
from datetime import datetime
from src.feature_extractor import FeatureExtractor
from src.anomaly_detector import AnomalyDetector

class RealTimeMonitor:
    def __init__(self, models_dir="models"):
        self.models_dir = models_dir
        self.extractor = FeatureExtractor(models_dir=models_dir)
        self.detector = AnomalyDetector(models_dir=models_dir)
        
        # Load pre-trained models
        try:
            self.extractor.load()
            self.detector.load()
            self.model_loaded = True
        except FileNotFoundError:
            self.model_loaded = False

    def generate_raw_log_entry(self, log_type="Apache Logs", anomaly_rate=0.08):
        """Generates a realistic log entry for simulation."""
        is_anomaly = random.random() < anomaly_rate
        
        ip_addr = f"192.168.1.{random.randint(1, 100)}" if not is_anomaly else f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"
        now = datetime.now()
        
        status_codes = [200, 201, 301, 302, 400, 401, 403, 404, 500, 502, 503]
        normal_status_weights = [0.6, 0.05, 0.05, 0.05, 0.05, 0.02, 0.02, 0.05, 0.05, 0.03, 0.03]
        anomaly_status_weights = [0.05, 0.0, 0.0, 0.0, 0.1, 0.3, 0.2, 0.05, 0.2, 0.05, 0.05]
        
        status = random.choices(status_codes, weights=anomaly_status_weights)[0] if is_anomaly else random.choices(status_codes, weights=normal_status_weights)[0]
        
        # Messages based on source type
        messages_normal = {
            "Apache Logs": [
                "GET /index.html HTTP/1.1",
                "GET /assets/css/style.css HTTP/1.1",
                "POST /api/v1/login HTTP/1.1",
                "GET /dashboard HTTP/1.1",
                "GET /favicon.ico HTTP/1.1"
            ],
            "Nginx Logs": [
                "GET /api/v2/users/profile HTTP/1.1",
                "GET /static/logo.png HTTP/1.1",
                "POST /api/v2/posts HTTP/1.1",
                "GET /about HTTP/1.1",
                "GET /products HTTP/1.1"
            ],
            "Windows Event Logs": [
                "Security Event ID 4624: Account logged on successfully",
                "System Event ID 7036: The Windows Installer service entered the running state",
                "Security Event ID 4672: Special privileges assigned to new logon",
                "System Event ID 7040: The start type of the IPsec service was changed",
                "Security Event ID 5058: Key file operation completed"
            ],
            "Linux Syslogs": [
                "systemd[1]: Started User Manager for UID 1000",
                "sshd[1243]: Connection closed by authenticating user admin 192.168.1.10 port 49552 [preauth]",
                "kernel: [ 2341.21] usb 1-1.2: New USB device found, idVendor=046d, idProduct=c52b",
                "cron[845]: (root) CMD ( /usr/local/bin/sys-cleanup.sh )",
                "systemd[1]: Stopped System Logging Service"
            ]
        }
        
        messages_anomaly = {
            "Apache Logs": [
                "GET /admin/db?query=UNION%20SELECT%20username,%20password%20FROM%20users HTTP/1.1",
                "POST /login HTTP/1.1 - Multiple failed login attempts",
                "GET /etc/passwd HTTP/1.1 - Unauthorized access attempt",
                "POST /api/upload HTTP/1.1 - Invalid payload format",
                "GET /api/v1/query?id=1%20OR%201=1 HTTP/1.1"
            ],
            "Nginx Logs": [
                "GET /wp-admin/index.php HTTP/1.1",
                "GET /config.json HTTP/1.1 - Unauthorized access attempt",
                "POST /api/v2/admin/roles HTTP/1.1 - HTTP 403 Forbidden",
                "GET /shell.php HTTP/1.1 - Page not found",
                "POST /payment HTTP/1.1 - Database connection timeout"
            ],
            "Windows Event Logs": [
                "Security Event ID 4625: An account failed to log on (failed login)",
                "Security Event ID 4697: A service was installed in the system (unauthorized root service)",
                "Security Event ID 4728: A member was added to a security-enabled global group (domain admin group addition)",
                "Security Event ID 1102: The audit log was cleared",
                "Security Event ID 4624: Account logged on successfully from external range"
            ],
            "Linux Syslogs": [
                "sshd[1245]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.4.2 user=root",
                "sudo[1540]: viewer : TTY=pts/0 ; PWD=/home/viewer ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
                "sshd[1555]: Invalid user admin from 10.0.12.5 port 55621",
                "kernel: [ 5510.12] Out of memory: Killed process 8443 (mysqld) total-vm:432104kB, anon-rss:152140kB",
                "systemd-logind[412]: Session 45 logged out - memory limit exceeded"
            ]
        }
        
        msg = random.choice(messages_anomaly[log_type]) if is_anomaly else random.choice(messages_normal[log_type])
        
        # Construct raw log format
        raw_log_str = ""
        if log_type == "Apache Logs":
            raw_log_str = f'{ip_addr} - - [{now.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{msg}" {status} {random.randint(100, 5000)}'
        elif log_type == "Nginx Logs":
            raw_log_str = f'{ip_addr} - - [{now.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{msg}" {status} {random.randint(100, 5000)} "-" "-"'
        elif log_type == "Windows Event Logs":
            raw_log_str = f'{now.strftime("%Y-%m-%d %H:%M:%S")} | {ip_addr} | Status {status} | {msg}'
        elif log_type == "Linux Syslogs":
            raw_log_str = f'{now.strftime("%b %d %H:%M:%S")} server {msg} [Status: {status}]'
            
        return {
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "ip_address": ip_addr,
            "status_code": status,
            "message": msg,
            "raw_log": raw_log_str
        }

    def process_and_evaluate(self, log_entry):
        """Runs the log entry through the ML feature extractor and anomaly detector."""
        if not self.model_loaded:
            # Fallback if model doesn't exist
            is_anomaly = log_entry["ip_address"].startswith("10.") or log_entry["status_code"] in [401, 403, 500]
            confidence = 88.5 if is_anomaly else 98.2
            threat_analysis = [{
                "timestamp": log_entry["timestamp"],
                "ip_address": log_entry["ip_address"],
                "status_code": log_entry["status_code"],
                "message": log_entry["message"],
                "threat_type": "DDoS Attack" if log_entry["status_code"] == 503 else "Unauthorized Entry Attempt",
                "severity": "Critical" if log_entry["status_code"] == 403 else "High",
                "confidence": confidence,
                "remediation": "✔ Block the offending IP at firewall level.\n✔ Review credentials.",
                "xai_explanations": "System flagged based on rule matches."
            }] if is_anomaly else []
            return is_anomaly, threat_analysis
            
        # 1. Build Single Row DataFrame
        df = pd.DataFrame([log_entry])
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['message'] = df['message'].fillna('')
        df['status_code'] = df['status_code'].fillna(200).astype(int)
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # 2. Extract Features using saved pipeline
        features = self.extractor.transform(df)
        
        # 3. Model Prediction
        anomalies = self.detector.detect(features)
        is_anomaly = bool(anomalies[0])
        
        # 4. Detailed Threat Classification
        threat_analysis = []
        if is_anomaly:
            threat_analysis = self.detector.analyze_threats(df, anomalies, features)
            
        return is_anomaly, threat_analysis
