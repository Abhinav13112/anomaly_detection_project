import streamlit as st
from src.authentication import init_auth_state, load_custom_css, logout

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
st.markdown("<h1 class='cyber-title'>ℹ️ ABOUT LOGSENTRIX AI</h1>", unsafe_allow_html=True)
st.markdown("<p class='cyber-subtitle'>LogSentrix AI Security Information and Event Management (SIEM) Platform.</p>", unsafe_allow_html=True)

# 5. Architecture Details
st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
st.subheader("🛠️ SIEM Core Architectures")

st.markdown("""
LogSentrix AI is an advanced, AI-driven cybersecurity dashboard engineered to analyze multi-source network transaction logs, extract linguistic and response-code patterns, and flag anomalous activities.

### Key Technical Pillars
1. **Unsupervised Machine Learning**: Powered by an **Isolation Forest** model fitted on log vectors. It calculates structural distances of incoming log events from clusters of historical baselines to flag suspicious records without requiring predefined labels.
2. **Dynamic Log Classification Rules**: Combines statistical anomaly thresholds with strict regex-based signatures to classify anomalies into distinct threat vectors (SQL Injection, Brute Force Attacks, privilege escalation, etc.) with corresponding severity indexes.
3. **Operator Incident Response Hub**: Enables real-time incident updates, filtering/sorting audit caches, and reviewing structured AI-suggested mitigation action items.
4. **Offline AI Security Assistant**: An built-in virtual analyst chatbot designed to query statistics and offer context-aware security checklists entirely offline.
5. **Interactive Data Science Visualizations**: Rendered using Plotly Express overlays, tracing temporal traffic anomalies, host IP profiles, and model performance histograms.
""")
st.markdown("</div>", unsafe_allow_html=True)

# 6. Technical Specifications Cards
st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
st.subheader("📊 System Specifications")

col_s1, col_s2 = st.columns(2)
with col_s1:
    st.markdown("""
    **Core Technologies**
    - **Frontend Layer**: Streamlit Web Framework (v1.58.0)
    - **Visualization Library**: Plotly Express
    - **Persistence Engine**: SQLite3
    - **Report Compiler**: ReportLab (PDF) & openpyxl (Excel)
    """)
with col_s2:
    st.markdown("""
    **Machine Learning Stack**
    - **Classifier Model**: Scikit-Learn Isolation Forest
    - **Feature Extractor**: Term Frequency TF-IDF Text Vectorization
    - **Status Encoder**: Sklearn One-Hot Encoder
    - **Confidence Mapping**: Decision Boundaries Distance Function
    """)
st.markdown("</div>", unsafe_allow_html=True)
