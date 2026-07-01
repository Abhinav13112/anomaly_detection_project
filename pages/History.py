import streamlit as st
import pandas as pd
from src.authentication import init_auth_state, load_custom_css, logout, enforce_permission
from src.database import get_analyses_history, get_audit_logs

# 1. Enforce Authentication
init_auth_state()
if not st.session_state.authenticated:
    st.switch_page("app.py")
    st.stop()

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

# 4. Header
st.markdown("<h1 class='cyber-title'>📁 AUDIT HISTORY & RUNS</h1>", unsafe_allow_html=True)
st.markdown("<p class='cyber-subtitle'>Review previous batch log analysis runs and operator activity logs.</p>", unsafe_allow_html=True)

# 5. Tabs for History & Auditing
tab_runs, tab_audits = st.tabs(["📂 Log Analysis Runs", "📋 User Action Audit Trail"])

with tab_runs:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("Previous Log Batch Analyses")
    
    # Load analysis history
    runs = get_analyses_history(limit=100)
    
    if not runs:
        st.info("No logs analysis history found. Run a log analysis pipeline on the Upload page.")
    else:
        df_runs = pd.DataFrame(runs)
        
        # Clean column names
        df_runs.columns = ["Run ID", "Filename", "Execution Time", "Total Logs", "Anomalies Count", "Confidence Score", "Risk Rating", "Pipeline Status"]
        
        # Sort by run ID descending
        df_runs = df_runs.sort_values(by="Run ID", ascending=False)
        
        st.dataframe(
            df_runs.style.map(
                lambda val: 'color: #ef4444; font-weight: bold;' if isinstance(val, float) and val > 75 
                else ('color: #10b981; font-weight: bold;' if val == 'Completed' else ''),
                subset=['Risk Rating', 'Pipeline Status']
            ),
            use_container_width=True,
            hide_index=True
        )
        
    st.markdown("</div>", unsafe_allow_html=True)

with tab_audits:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("Console Operator Logs (RBAC Logged)")
    
    # Load audits
    audits = get_audit_logs(limit=200)
    
    if not audits:
        st.info("No operator actions recorded.")
    else:
        df_audits = pd.DataFrame(audits)
        df_audits.columns = ["Timestamp", "Operator User", "Action Triggered", "Detail Summary"]
        
        # Search & Filter
        search_user = st.text_input("Filter by Operator Name:", placeholder="e.g. admin")
        
        filtered_audits = df_audits
        if search_user:
            filtered_audits = df_audits[df_audits["Operator User"].str.contains(search_user, case=False)]
            
        st.dataframe(
            filtered_audits.style.map(
                lambda val: 'color: #9b51e0; font-weight: bold;' if val in ['DB_INIT', 'CREATE_USER', 'CHANGE_SETTING']
                else ('color: #00f2fe; font-weight: bold;' if val in ['RUN_ANALYSIS', 'UPDATE_THREAT'] else ''),
                subset=['Action Triggered']
            ),
            use_container_width=True,
            hide_index=True
        )
        
    st.markdown("</div>", unsafe_allow_html=True)
