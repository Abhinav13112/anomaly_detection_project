import re
from datetime import datetime
from src.database import get_kpis, get_threats, get_analyses_history

class SecurityChatbot:
    def __init__(self):
        pass

    def get_response(self, query):
        """Processes user queries and returns HTML/Markdown formatted responses."""
        q_lower = query.lower().strip()
        
        # 1. Today's Threat Summary
        if any(w in q_lower for w in ["summary", "today", "status", "overview"]):
            kpis = get_kpis()
            history = get_analyses_history(limit=5)
            
            recent_files = ", ".join([h["filename"] for h in history]) if history else "No uploads yet"
            
            response = f"""
            ### 📊 LogSentrix System Summary ({datetime.now().strftime("%Y-%m-%d")})
            
            The current system security status is summarized below:
            - **Total Logs Processed**: {kpis['total_logs']:,}
            - **Anomalies Detected**: {kpis['total_anomalies']}
            - **Open Unresolved Threat Alerts**: {kpis['open_threats']}
            - **Infrastructure Risk Score**: `{kpis['avg_risk']}/100` (Low &lt; 20, Med &lt; 50, High &lt; 80, Critical &ge; 80)
            - **Mean Model Confidence**: `{kpis['avg_confidence']}%`
            - **Recent Uploaded Batches**: *{recent_files}*
            
            {"🔴 **Alert:** There are active unresolved threats! Please review the **Threat Detection Page**." if kpis['open_threats'] > 0 else "🟢 **Status:** All clear! No active open threats."}
            """
            return response
            
        # 2. Show Critical Threats
        elif any(w in q_lower for w in ["critical", "high threat", "show threat", "list threat"]):
            threats = get_threats(limit=10)
            critical_threats = [t for t in threats if t["severity"] in ["Critical", "High"]]
            
            if not critical_threats:
                return "🟢 **No active Critical or High severity threats found in the database.**"
            
            resp = "### 🚨 Active Critical & High Severity Threats\n\n"
            for t in critical_threats[:5]:
                resp += f"- **[{t['severity']}] {t['threat_type']}** from IP `{t['ip_address']}`\n"
                resp += f"  - Message: `{t['message']}`\n"
                resp += f"  - Confidence: `{t['confidence']}%` | Time: `{t['timestamp']}`\n"
                resp += f"  - Remediation Action: *{t['remediation'].replace('✔ ', '')[:100]}...*\n\n"
            return resp

        # 3. Explain Isolation Forest Anomaly Detection (Explainable AI)
        elif any(w in q_lower for w in ["why was this anomaly", "explain log", "how does it detect", "isolation forest", "xai", "why detected"]):
            return """
            ### 🧠 Explainable AI (XAI) & Model Logic
            
            LogSentrix AI uses a hybrid model comprising **Machine Learning** and **Heuristic Security Rules**:
            
            1. **ML Layer (Isolation Forest)**: 
               - The model extracts numerical features from log messages using a **TF-IDF vectorizer** (Term Frequency-Inverse Document Frequency) which converts the text keywords into spatial coordinates.
               - It encodes the **HTTP status codes** into numerical vectors using **One-Hot Encoding**.
               - The **Isolation Forest** algorithm isolate anomalous logs by recursively partitioning data points. Logs that require fewer splits to isolate are statistically flagged as anomalies.
            
            2. **Signature Classifier Layer**:
               - When the model flags an anomaly, the Signature Classifier runs regex-matching to identify specific threat signatures like SQL keywords (`SELECT`, `UNION`), brute force patterns (401 status code with repeated IPs), or privilege escalations (user invoking `/etc/shadow` or root access).
               
            3. **Confidence Scoring**:
               - Confidence is derived from the *anomaly score* (how far deep the sample is in the forest). A sample isolated very close to the root tree gets a higher confidence rating.
            """

        # 4. Explain SQL Injection
        elif "sql" in q_lower:
            return """
            ### 🛡 SQL Injection (SQLi) Overview
            
            **What it is:**  
            SQL Injection is a web vulnerability where an attacker injects malicious SQL statements into input fields to control database queries, bypass authorization, or retrieve confidential database records.
            
            **Detection Indicators:**  
            - Presence of database keywords: `UNION`, `SELECT`, `OR 1=1`, `INSERT`, `DROP TABLE`.
            - Special characters like quotes (`'`), double-dashes (`--`), or semicolons.
            
            **How to Fix (Remediation):**  
            1. Use **Parameterized Queries** (Prepared Statements) for all database operations.
            2. Implement strict input validation (allow-lists).
            3. Deploy a Web Application Firewall (WAF) to filter incoming payloads.
            4. Restrict database permissions (least privilege principle).
            """

        # 5. Explain Brute Force
        elif any(w in q_lower for w in ["brute force", "failed login", "password"]):
            return """
            ### 🛡 Brute Force Attacks
            
            **What it is:**  
            Brute force involves automated attempts to guess passwords, credentials, or encryption keys by trial-and-error to gain unauthorized account access.
            
            **Detection Indicators:**  
            - Frequent status code `401 Unauthorized` responses.
            - Multiple log messages stating `failed login attempt` from a single source IP in rapid succession.
            
            **How to Fix (Remediation):**  
            1. Block the source IP at the firewall / load balancer.
            2. Set account lockout policies (e.g., lock user after 5 failed attempts).
            3. Enforce **Multi-Factor Authentication (MFA)**.
            4. Implement login rate limiting (e.g. max 3 requests per minute per IP).
            """

        # 6. Explain DDoS
        elif any(w in q_lower for w in ["ddos", "dos", "timeout", "resource"]):
            return """
            ### 🛡 DDoS & Resource Exhaustion
            
            **What it is:**  
            Distributed Denial of Service (DDoS) attempts to disrupt network services by overwhelming systems with requests from multiple coordinated sources, causing resource exhaustion (CPU, Memory, Bandwidth).
            
            **Detection Indicators:**  
            - Spikes in response status codes like `503 Service Unavailable` or `504 Gateway Timeout`.
            - Messages referencing `Memory limit exceeded` or connection timeouts.
            
            **How to Fix (Remediation):**  
            1. Use a DDoS protection proxy (e.g. Cloudflare, AWS Shield).
            2. Configure rate limiting and request throttling.
            3. Implement scale-out groups (auto-scaling) to handle load.
            4. Identify and drop packet patterns using firewall rules.
            """

        # 7. Unrecognized query / Welcome
        else:
            return """
            ### 🤖 LogSentrix Security Assistant
            
            Welcome to the LogSentrix AI assistant. I can help analyze threat metrics, explain detection logic, and suggest security remediation actions.
            
            **Try asking me:**
            - *Give today's summary* (Calculates KPIs and list active counts)
            - *Show critical threats* (Lists recent critical alerts in the DB)
            - *Why was this anomaly detected?* (Explains Explainable AI (XAI) and Isolation Forest math)
            - *What is SQL Injection and how to fix it?*
            - *Explain Brute Force Attacks*
            - *How do I remediate a DDoS event?*
            """
            
# Instantiate global instance
chatbot = SecurityChatbot()
