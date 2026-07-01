import streamlit as st
from src.authentication import init_auth_state, load_custom_css, render_sidebar

# 1. Enforce Authentication
init_auth_state()
if not st.session_state.authenticated:
    st.switch_page("app.py")
    st.stop()

# 2. Load Custom CSS
load_custom_css()

# 3. Sidebar Configuration
render_sidebar()

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
