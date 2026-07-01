import streamlit as st
import os
from datetime import datetime
from src.database import add_threat, get_setting

class AlertSystem:
    def __init__(self):
        pass

    def trigger_sound_alert(self):
        """Triggers an HTML5 Web Audio API beep alert in the browser."""
        # Simple JavaScript synthesizer beep - no assets or file downloads required!
        beep_html = """
        <div style="display:none;">
            <script>
                try {
                    var context = new (window.AudioContext || window.webkitAudioContext)();
                    // Alert sound sequence (dual beep)
                    function playBeep(freq, delay, duration) {
                        setTimeout(function() {
                            var osc = context.createOscillator();
                            var gain = context.createGain();
                            osc.type = 'triangle'; // softer than sine
                            osc.frequency.setValueAtTime(freq, context.currentTime);
                            gain.gain.setValueAtTime(0.1, context.currentTime); // volume 10%
                            
                            // Exponential decay
                            gain.gain.exponentialRampToValueAtTime(0.001, context.currentTime + duration);
                            
                            osc.connect(gain);
                            gain.connect(context.destination);
                            osc.start();
                            osc.stop(context.currentTime + duration);
                        }, delay);
                    }
                    playBeep(880, 0, 0.15); // first beep
                    playBeep(1200, 200, 0.25); // second beep
                } catch(e) {
                    console.error("Audio Context blocked or unsupported:", e);
                }
            </script>
        </div>
        """
        # Load setting from database
        sound_enabled = get_setting("sound_alerts_enabled", "True") == "True"
        if sound_enabled:
            st.markdown(beep_html, unsafe_allow_html=True)

    def trigger_mock_email(self, threat):
        """Simulates sending an email alert to the security distribution list."""
        recipient = get_setting("email_alerts_recipient", "security@company.com")
        email_enabled = get_setting("email_alerts_enabled", "False") == "True"
        
        email_content = f"""
        ======================================================================
        [LOGSENTRIX AI ALERT] SECURITY EXCEPTION DETECTED
        ======================================================================
        To: {recipient}
        Timestamp: {threat['timestamp']}
        Source IP: {threat['ip_address']}
        Severity: {threat['severity']}
        Threat Category: {threat['threat_type']}
        Detection Confidence: {threat['confidence']}%
        
        Log Message: 
        "{threat['message']}"
        
        Explainable AI Details:
        {threat['xai_explanations']}
        
        Suggested Remediation Action Plan:
        {threat['remediation']}
        ======================================================================
        """
        
        # Write to local simulated alert mailbox log
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        mailbox_path = os.path.join(log_dir, "simulated_emails.log")
        
        with open(mailbox_path, "a", encoding="utf-8") as f:
            f.write(email_content + "\n")
            
        # If active in Streamlit session, print to console as well
        print(f"[MAIL] Mock security email alert dispatched to {recipient} regarding {threat['threat_type']}")
        
        # Show toast in Streamlit if email alert is enabled in database
        if email_enabled:
            st.toast(f"📧 Alert Email sent to {recipient} regarding {threat['threat_type']}", icon="✉️")

    def generate_alerts(self, df, anomalies, analysis_id=None, save_to_db=True):
        """Processes and logs anomalies, saving to DB and trigger notifications."""
        # This function acts as a legacy bridge for main.py CLI AND the web UI
        from src.anomaly_detector import AnomalyDetector
        
        detector = AnomalyDetector()
        
        # Fit logic not needed here since we transform/load. We just extract details.
        # But wait, to run analyze_threats we need the numerical features.
        # In CLI context we don't have them here directly, so we can re-extract features if needed.
        # However, this method is primarily used in app.py / pages.
        # Let's check if features are passed or if we can mock a simple rule analyzer if features are not present.
        # Let's verify: we will handle both.
        
        print("\n" + "="*70)
        print("[!] AI ANOMALY DETECTION ALERTS [!]")
        print("="*70)
        
        df['is_anomaly'] = anomalies
        anomalous_logs = df[df['is_anomaly']]
        
        if anomalous_logs.empty:
            print("Status: Normal. No anomalies detected.")
            print("="*70 + "\n")
            return []
            
        # If we don't have the threat details, we extract them using rules
        # In a real run, this is called from pages/Upload.py or LiveMonitor.py with pre-calculated details
        threats_details = []
        
        for idx, row in anomalous_logs.iterrows():
            # Minimal extraction for CLI backward compatibility
            ip = row['ip_address']
            status = int(row['status_code'])
            msg = str(row['message'])
            
            # Simple rule mapping fallback
            threat_type = "Suspicious Client Activity" if status >= 400 else "Anomalous Event"
            severity = "High" if status in [401, 403, 500] else "Medium"
            confidence = 90.0
            remediation = "✔ Investigate logs.\n✔ Perform firewall audit."
            xai_explanations = f"Anomaly code {status} flagged during pipeline execution."
            
            # If details exist in column (already populated by advanced detector)
            if 'threat_type' in row:
                threat_type = row['threat_type']
                severity = row['severity']
                confidence = row['confidence']
                remediation = row['remediation']
                xai_explanations = row['xai_explanations']
                
            threat = {
                "timestamp": str(row['timestamp']),
                "ip_address": ip,
                "status_code": status,
                "message": msg,
                "threat_type": threat_type,
                "severity": severity,
                "confidence": confidence,
                "remediation": remediation,
                "xai_explanations": xai_explanations
            }
            
            # Print to stdout
            print(f"[ALERT] {threat['timestamp']} | IP: {threat['ip_address']} | "
                  f"Type: {threat['threat_type']} ({threat['severity']}) | Confidence: {threat['confidence']}%")
            
            # Save to SQLite Database
            if save_to_db:
                add_threat(
                    analysis_id=analysis_id,
                    timestamp=threat['timestamp'],
                    ip_address=threat['ip_address'],
                    status_code=threat['status_code'],
                    message=threat['message'],
                    threat_type=threat['threat_type'],
                    severity=threat['severity'],
                    confidence=threat['confidence'],
                    remediation=threat['remediation']
                )
                
            # Trigger notifications
            self.trigger_mock_email(threat)
            
            # Streamlit-specific actions
            if 'authenticated' in st.session_state:
                icon_map = {"Critical": "🚨", "High": "🔥", "Medium": "⚠️", "Low": "ℹ️"}
                st.toast(f"{icon_map.get(severity, '⚠️')} **{threat_type}** ({severity}) from `{ip}`", icon="🛡️")
                
            threats_details.append(threat)
            
        # Play sound if any alerts triggered
        if threats_details and 'authenticated' in st.session_state:
            self.trigger_sound_alert()
            
        print("="*70)
        print(f"Summary: System generated {len(threats_details)} alerts.")
        print("="*70 + "\n")
        
        return threats_details
