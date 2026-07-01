from sklearn.ensemble import IsolationForest
import pickle
import os
import numpy as np
import pandas as pd
import re

class AnomalyDetector:
    def __init__(self, contamination=0.05, random_state=42, models_dir="models"):
        self.contamination = contamination
        self.random_state = random_state
        self.models_dir = models_dir
        self.model = IsolationForest(contamination=self.contamination, random_state=self.random_state)

    def fit(self, features):
        """Fits the Isolation Forest model on the training features."""
        print("Training Isolation Forest model...")
        self.model.fit(features)

    def detect(self, features):
        """Runs predictions using the model (requires fit or load first)."""
        print("Running anomaly detection model inference...")
        predictions = self.model.predict(features)
        
        # Convert -1 (anomaly) and 1 (normal) predictions to True/False
        anomalies = (predictions == -1)
        
        print(f"Anomaly detection complete. Flagged {sum(anomalies)} anomalies.")
        return anomalies

    def save(self):
        """Saves the Isolation Forest model to disk."""
        os.makedirs(self.models_dir, exist_ok=True)
        model_path = os.path.join(self.models_dir, "model.pkl")
        
        with open(model_path, "wb") as f:
            pickle.dump(self.model, f)
            
        print(f"Anomaly detector model saved to {self.models_dir}/")

    def load(self):
        """Loads the Isolation Forest model from disk."""
        model_path = os.path.join(self.models_dir, "model.pkl")
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Fitted model file not found at {model_path}. Please run training first.")
            
        with open(model_path, "rb") as f:
            self.model = pickle.load(f)
            
        print(f"Anomaly detector model loaded from {self.models_dir}/")

    # --- ADVANCED CYBERSECURITY & XAI FEATURES ---

    def analyze_threats(self, df, anomalies, features):
        """
        Analyzes flagged anomalies to determine threat type, confidence, severity, and remediation steps.
        Also calculates Explainable AI metrics based on feature values and decision scores.
        """
        # Calculate Isolation Forest anomaly scores (lower means more anomalous)
        decision_scores = self.model.decision_function(features)
        
        results = []
        
        for idx, is_anomaly in enumerate(anomalies):
            if not is_anomaly:
                continue
                
            row = df.iloc[idx]
            ip = row['ip_address']
            status = int(row['status_code'])
            msg = str(row['message'])
            score = decision_scores[idx]
            
            # 1. Compute Confidence Score
            # Map score (typically in [-0.5, 0.5]) to a 70% - 99.9% confidence range
            raw_confidence = 70.0 + (abs(score) * 60.0)
            confidence = min(max(raw_confidence, 70.0), 99.9)
            
            # 2. Threat Classification Heuristics
            threat_type = "Generic Anomaly"
            severity = "Medium"
            remediation = []
            xai_reasons = []
            
            msg_lower = msg.lower()
            
            # Check SQL Injection (SQLi)
            sqli_keywords = ['union', 'select', 'insert', 'drop', 'delete', 'update', 'or 1=1', '--', "'", 'exec', 'varchar']
            if any(kw in msg_lower for kw in sqli_keywords) or status in [500] and 'payload' in msg_lower:
                threat_type = "SQL Injection"
                severity = "Critical"
                remediation = [
                    "Block the offending IP address at the firewall level.",
                    "Review application inputs and ensure parameterized SQL queries are used.",
                    "Inspect database audit logs for unauthorized schema or data modifications.",
                    "Enable Web Application Firewall (WAF) SQLi protection rules.",
                    "Inspect database connection pool for open sessions."
                ]
                xai_reasons.append(f"SQL queries syntax/keywords detected in message: '{msg}'")
                if status == 500:
                    xai_reasons.append("Caused an internal server error (500), indicating potential crash exploit.")
            
            # Check Brute Force / Credential Stuffing
            elif 'failed' in msg_lower and ('login' in msg_lower or 'auth' in msg_lower or 'attempt' in msg_lower) or status == 401:
                threat_type = "Brute Force Attack"
                severity = "High"
                remediation = [
                    "Block IP address to halt active authorization attempts.",
                    "Temporarily lock targeted user accounts if threshold is exceeded.",
                    "Implement Multi-Factor Authentication (MFA) requirements.",
                    "Enable login CAPTCHA for repeated failures.",
                    "Trigger password reset request for targeted users."
                ]
                xai_reasons.append(f"Contains auth failure keywords: '{msg}'")
                if status == 401:
                    xai_reasons.append("HTTP 401 Unauthorized status code returned.")
                    
            # Check DDoS / High volume connections
            elif status in [503, 504, 502] or 'timeout' in msg_lower or 'limit exceeded' in msg_lower:
                threat_type = "DDoS / Resource Exhaustion"
                severity = "High"
                remediation = [
                    "Engage CDN / DDoS mitigation provider (e.g. Cloudflare).",
                    "Configure Rate Limiting on the API Gateway or Load Balancer.",
                    "Scale server instances or increase container CPU/Memory allocations.",
                    "Inspect active network connections (netstat) for SYN floods.",
                    "Establish IP blacklisting for high-volume nodes."
                ]
                xai_reasons.append("Log indicates system resource exhaustion or service unavailability.")
                if status in [503, 504]:
                    xai_reasons.append(f"HTTP {status} gateway timeout/service unavailable response.")
            
            # Check Unauthorized Access / Privilege Escalation
            elif 'unauthorized' in msg_lower or 'forbidden' in msg_lower or status == 403:
                threat_type = "Unauthorized Access"
                severity = "Critical" if 'admin' in msg_lower or 'root' in msg_lower else "High"
                remediation = [
                    "Revoke session tokens and reset access credentials immediately.",
                    "Audit access control lists (ACLs) and role configurations.",
                    "Validate security token expiration parameters.",
                    "Examine access paths for lateral movement attempts."
                ]
                xai_reasons.append(f"Explicit access denial message: '{msg}'")
                if status == 403:
                    xai_reasons.append("HTTP 403 Forbidden status code returned.")
                if 'admin' in msg_lower or 'root' in msg_lower:
                    threat_type = "Privilege Escalation"
                    xai_reasons.append("Targeted resource belongs to system administrator or root account.")
                    
            # Suspicious Login / Anomalous location
            elif 'logged in' in msg_lower and ip.startswith('10.'):
                threat_type = "Suspicious Login"
                severity = "Medium"
                remediation = [
                    "Verify user location and active session metadata.",
                    "Notify security analyst for manual review.",
                    "Prompt user for identity verification (MFA challenge)."
                ]
                xai_reasons.append(f"Login event originating from suspect private/internal subnet range: {ip}")
                
            # Default / Fallback
            else:
                if status >= 400 and status < 500:
                    threat_type = "Suspicious Client Action"
                    severity = "Medium"
                    xai_reasons.append(f"Client-side error status code {status} without known signature.")
                elif status >= 500:
                    threat_type = "Internal System Anomaly"
                    severity = "High"
                    xai_reasons.append(f"Server-side error status code {status} indicating software crash.")
                else:
                    threat_type = "Anomalous Log Pattern"
                    severity = "Low"
                    xai_reasons.append("Flagged by Isolation Forest due to statistical difference in feature variables.")
                
                remediation = [
                    "Examine the full traceback log entry manually.",
                    "Check network logs for concurrent activity from the same IP.",
                    "Verify deployment updates for potential regression bugs."
                ]
            
            # Add general explainability based on mathematical score
            xai_reasons.append(f"Statistical Anomaly Score: {abs(score):.4f} (Isolation Forest decision score threshold exceeded).")
            
            results.append({
                "timestamp": row['timestamp'].strftime("%Y-%m-%d %H:%M:%S") if isinstance(row['timestamp'], pd.Timestamp) else str(row['timestamp']),
                "ip_address": ip,
                "status_code": status,
                "message": msg,
                "threat_type": threat_type,
                "severity": severity,
                "confidence": round(confidence, 2),
                "remediation": "\n".join([f"✔ {step}" for step in remediation]),
                "xai_explanations": " | ".join(xai_reasons)
            })
            
        return results
