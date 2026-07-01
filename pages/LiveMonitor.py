import streamlit as st
import time
import pandas as pd
from datetime import datetime
from src.authentication import init_auth_state, load_custom_css, logout, enforce_permission
from src.database import log_action, get_setting
from src.realtime_monitor import RealTimeMonitor
from src.alert_system import AlertSystem

# 1. Enforce Authentication (Analyst/Admin needed)
init_auth_state()
if not st.session_state.authenticated:
    st.switch_page("app.py")
    st.stop()

enforce_permission(["Admin", "Security Analyst"])

# 2. Load Custom CSS
load_custom_css()

# 3. Sidebar Configuration
with st.sidebar:
    st.markdown(f"""
    <div class="cyber-card" style="padding: 10px; text-align: center; border-left: 3px solid #00f2fe;">
        <h3 style="margin: 0; color: #fff; font-family: 'Share Tech Mono';">🛡️ LOGSENTRIX AI</h3>
        <span style="font-size: 0.8rem; color: #9ca3af;">SIEM SECURITY CONSOLE</span>
    </div>
    """, unsafe_allow_html=True)
    
    st.sidebar.markdown("---")
    
    st.markdown(f"""
    <div class="cyber-card" style="margin-bottom: 20px;">
        <div style="font-size: 0.8rem; color: #9ca3af;">Active Operator:</div>
        <div style="font-weight: bold; color: #00f2fe; font-size: 1.1rem;">@{st.session_state.username}</div>
        <div style="font-size: 0.75rem; background: rgba(155, 81, 224, 0.2); border: 1px solid rgba(155, 81, 224, 0.4); border-radius: 4px; padding: 2px 6px; display: inline-block; margin-top: 5px; color: #d8b4fe;">
            {st.session_state.role}
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    if st.sidebar.button("🔐 Terminate Session", use_container_width=True):
        logout()

# Initialize monitor state
if "monitoring" not in st.session_state:
    st.session_state.monitoring = False
if "live_alerts" not in st.session_state:
    st.session_state.live_alerts = []
if "log_console_history" not in st.session_state:
    st.session_state.log_console_history = []

# 4. Header
st.markdown("<h1 class='cyber-title'>🔥 REAL-TIME THREAT MONITORING</h1>", unsafe_allow_html=True)
st.markdown("<p class='cyber-subtitle'>Stream live endpoint system logs and monitor for active cyber intrusions.</p>", unsafe_allow_html=True)

# 5. Configurations Panel
st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
st.subheader("⚙️ Live Feed Configuration")

col_c1, col_c2, col_c3 = st.columns(3)
with col_c1:
    log_source = st.selectbox(
        "Select Log Stream Source:", 
        options=["Apache Logs", "Nginx Logs", "Windows Event Logs", "Linux Syslogs"]
    )
with col_c2:
    refresh_rate = st.slider("Simulated Ingestion Delay (s)", min_value=0.5, max_value=4.0, value=1.0, step=0.5)
with col_c3:
    anomaly_rate = st.slider("Simulated Anomaly Ratio (%)", min_value=1.0, max_value=30.0, value=8.0, step=1.0) / 100.0

col_btn_start, col_btn_clear = st.columns([3, 1])
with col_btn_start:
    if st.session_state.monitoring:
        stop_btn = st.button("🔴 HALT FEED MONITORING", use_container_width=True)
        if stop_btn:
            st.session_state.monitoring = False
            log_action(st.session_state.username, "STOP_LIVE_MONITOR", f"Halted live monitoring stream for {log_source}.")
            st.rerun()
    else:
        start_btn = st.button("🟢 INITIATE LIVE MONITORING", use_container_width=True)
        if start_btn:
            st.session_state.monitoring = True
            log_action(st.session_state.username, "START_LIVE_MONITOR", f"Started live monitoring stream for {log_source}.")
            st.rerun()
            
with col_btn_clear:
    if st.button("🧹 Clear Streams", use_container_width=True):
        st.session_state.live_alerts = []
        st.session_state.log_console_history = []
        st.success("Buffer cleared.")
        time.sleep(0.5)
        st.rerun()

st.markdown("</div>", unsafe_allow_html=True)

# 6. Stream Status Lights
st.markdown("""
<div style='display: flex; gap: 20px; font-family: "Share Tech Mono"; margin-bottom: 20px;'>
    <div style='background:rgba(16,185,129,0.1); border:1px solid #10b981; padding: 4px 10px; border-radius:4px; color:#10b981;'>🟢 SERVER CONNECTED</div>
    <div style='background:rgba(16,185,129,0.1); border:1px solid #10b981; padding: 4px 10px; border-radius:4px; color:#10b981;'>🟢 DATABASE CONNECTED</div>
    <div style='background:rgba(0,242,254,0.1); border:1px solid #00f2fe; padding: 4px 10px; border-radius:4px; color:#00f2fe;'>🔍 PIPELINE ENFORCED</div>
</div>
""", unsafe_allow_html=True)

# 7. Live Terminal & Active Alerts Columns
col_term, col_active_alerts = st.columns([5, 4])

with col_term:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("📟 Live Endpoint Shell Stream")
    
    # Text placeholder for terminal
    console_placeholder = st.empty()
    
    # Format log console output
    console_text = ""
    for log_item in reversed(st.session_state.log_console_history):
        if " [STATUS: 200]" in log_item or "200" in log_item:
            console_text += f"<span style='color: #10b981;'>{log_item}</span>\n"
        elif "failed" in log_item.lower() or "UNION" in log_item or "HTTP 40" in log_item:
            console_text += f"<span style='color: #ef4444; font-weight: bold;'>{log_item}</span>\n"
        else:
            console_text += f"<span>{log_item}</span>\n"
            
    if not console_text:
        console_text = "Console inactive. Click 'INITIATE LIVE MONITORING' to launch system event generator..."
        
    console_placeholder.markdown(
        f"<div class='cyber-console' style='height: 380px;'><pre style='color:#38bdf8; font-family: monospace; white-space: pre-wrap;'>{console_text}</pre></div>",
        unsafe_allow_html=True
    )
    st.markdown("</div>", unsafe_allow_html=True)

with col_active_alerts:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("🚨 Live Intrusion Ticker")
    
    if not st.session_state.live_alerts:
        st.info("No threats flagged in active session buffer.")
    else:
        for t in reversed(st.session_state.live_alerts[-5:]): # Show last 5 alerts
            sev = t['severity']
            sev_badge = f"<span style='background:rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color:#fca5a5; padding: 2px 6px; border-radius: 4px; font-size:0.75rem;'>{sev}</span>"
            
            st.markdown(f"""
            <div style="background:rgba(220, 38, 38, 0.08); border-left: 3px solid #ef4444; border-radius: 4px; padding: 8px; margin-bottom: 10px;">
                <div style="font-weight: bold; color: #fff;">{t['threat_type']} {sev_badge}</div>
                <div style="font-size: 0.8rem; color: #9ca3af;">Host: <code style="color:#00f2fe;">{t['ip_address']}</code> | Time: {t['timestamp']}</div>
                <div style="font-size: 0.8rem; color: #e2e8f0; font-family: monospace; margin-top:2px;">"{t['message']}"</div>
            </div>
            """, unsafe_allow_html=True)
            
    st.markdown("</div>", unsafe_allow_html=True)

# 8. Loop execution when monitoring is enabled
if st.session_state.monitoring:
    # Initialize monitor
    monitor = RealTimeMonitor()
    alerter = AlertSystem()
    
    # Generate single log
    entry = monitor.generate_raw_log_entry(log_type=log_source, anomaly_rate=anomaly_rate)
    
    # Append log to console history
    st.session_state.log_console_history.append(entry["raw_log"])
    if len(st.session_state.log_console_history) > 30: # Limit history size
        st.session_state.log_console_history.pop(0)
        
    # Evaluate anomaly status
    is_anomaly, threat_details = monitor.process_and_evaluate(entry)
    
    if is_anomaly and threat_details:
        threat = threat_details[0]
        # Append alert to active session list
        st.session_state.live_alerts.append(threat)
        
        # Insert threat details in database and trigger alert triggers
        alerter.generate_alerts(
            df=pd.DataFrame([entry]),
            anomalies=[True],
            analysis_id=None,
            save_to_db=True
        )
        
    # Wait for the defined refresh rate and rerun to pull the next event
    time.sleep(refresh_rate)
    st.rerun()
