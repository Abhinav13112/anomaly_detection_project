import streamlit as st
import os
from src.authentication import init_auth_state, load_custom_css, logout
from src.database import get_kpis, get_threats
from src.report_generator import generate_pdf_report, generate_excel_report, generate_csv_report, generate_json_report

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
st.markdown("<h1 class='cyber-title'>📥 SECURITY AUDIT REPORTS</h1>", unsafe_allow_html=True)
st.markdown("<p class='cyber-subtitle'>Compile and export system analysis metrics and threat classifications for compliance audits.</p>", unsafe_allow_html=True)

# 5. Main Card Interface
st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
st.subheader("📊 Choose Report Format")
st.write("Generate and download a comprehensive report summarizing all logs and anomaly incidents captured by the SIEM engine.")

# Fetch active threat statistics
kpis = get_kpis()
threats = get_threats(limit=2000)
threat_dicts = [dict(t) for t in threats]

os.makedirs("reports", exist_ok=True)

# Grid Layout for Download Formats
col_pdf, col_xlsx = st.columns(2)
col_csv, col_json = st.columns(2)

with col_pdf:
    st.markdown("""
    <div style='background:rgba(255, 255, 255, 0.03); border:1px dashed rgba(255, 255, 255, 0.1); border-radius:8px; padding:15px; text-align:center; margin-bottom:15px;'>
        <div style='font-size:3rem;'>📕</div>
        <h4 style='margin:5px 0;'>Executive PDF Summary</h4>
        <span style='font-size:0.8rem; color:#9ca3af;'>Best for executive review & printing. Contains stylized charts summaries, KPIs, and remediation guide.</span>
    </div>
    """, unsafe_allow_html=True)
    
    pdf_path = os.path.join("reports", "logsentrix_audit_report.pdf")
    try:
        generate_pdf_report(kpis, threat_dicts, pdf_path)
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        st.download_button(
            label="Download PDF Report",
            data=pdf_bytes,
            file_name="logsentrix_security_report.pdf",
            mime="application/pdf",
            use_container_width=True
        )
    except Exception as e:
        st.error(f"Error generating PDF: {str(e)}")

with col_xlsx:
    st.markdown("""
    <div style='background:rgba(255, 255, 255, 0.03); border:1px dashed rgba(255, 255, 255, 0.1); border-radius:8px; padding:15px; text-align:center; margin-bottom:15px;'>
        <div style='font-size:3rem;'>📗</div>
        <h4 style='margin:5px 0;'>Multi-Sheet Excel Audit</h4>
        <span style='font-size:0.8rem; color:#9ca3af;'>Best for database auditing. Sheets contain Executive Summary, Security Alerts log, and Remediation Guide.</span>
    </div>
    """, unsafe_allow_html=True)
    
    excel_path = os.path.join("reports", "logsentrix_audit_report.xlsx")
    try:
        generate_excel_report(kpis, threat_dicts, excel_path)
        with open(excel_path, "rb") as f:
            excel_bytes = f.read()
        st.download_button(
            label="Download Excel Sheet",
            data=excel_bytes,
            file_name="logsentrix_security_report.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True
        )
    except Exception as e:
        st.error(f"Error generating Excel: {str(e)}")

with col_csv:
    st.markdown("""
    <div style='background:rgba(255, 255, 255, 0.03); border:1px dashed rgba(255, 255, 255, 0.1); border-radius:8px; padding:15px; text-align:center; margin-bottom:15px;'>
        <div style='font-size:3rem;'>📄</div>
        <h4 style='margin:5px 0;'>Raw CSV Alerts Log</h4>
        <span style='font-size:0.8rem; color:#9ca3af;'>Flat CSV file containing only the table database of all flagged threats. Easily imported into external dashboards.</span>
    </div>
    """, unsafe_allow_html=True)
    
    csv_path = os.path.join("reports", "logsentrix_audit_report.csv")
    try:
        generate_csv_report(threat_dicts, csv_path)
        with open(csv_path, "rb") as f:
            csv_bytes = f.read()
        st.download_button(
            label="Download CSV File",
            data=csv_bytes,
            file_name="logsentrix_security_report.csv",
            mime="text/csv",
            use_container_width=True
        )
    except Exception as e:
        st.error(f"Error generating CSV: {str(e)}")

with col_json:
    st.markdown("""
    <div style='background:rgba(255, 255, 255, 0.03); border:1px dashed rgba(255, 255, 255, 0.1); border-radius:8px; padding:15px; text-align:center; margin-bottom:15px;'>
        <div style='font-size:3rem;'>🌐</div>
        <h4 style='margin:5px 0;'>JSON Log Payloads</h4>
        <span style='font-size:0.8rem; color:#9ca3af;'>Fully structured JSON dump of security alerts. Ideal for programmatic ingestion into security tools.</span>
    </div>
    """, unsafe_allow_html=True)
    
    json_path = os.path.join("reports", "logsentrix_audit_report.json")
    try:
        generate_json_report(threat_dicts, json_path)
        with open(json_path, "rb") as f:
            json_bytes = f.read()
        st.download_button(
            label="Download JSON File",
            data=json_bytes,
            file_name="logsentrix_security_report.json",
            mime="application/json",
            use_container_width=True
        )
    except Exception as e:
        st.error(f"Error generating JSON: {str(e)}")

st.markdown("</div>", unsafe_allow_html=True)
