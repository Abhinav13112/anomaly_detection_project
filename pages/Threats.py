import streamlit as st
import pandas as pd
from src.authentication import init_auth_state, load_custom_css, enforce_permission, has_role, render_sidebar
from src.database import get_threats, update_threat_status

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
st.markdown("<h1 class='cyber-title'>🚨 THREAT DETECTION CENTER</h1>", unsafe_allow_html=True)
st.markdown("<p class='cyber-subtitle'>Real-time incident response queue. Analyze anomalies, change issue states, and view AI remediation guides.</p>", unsafe_allow_html=True)

# 5. Fetch Threat Logs
threats = get_threats(limit=500)

if not threats:
    st.markdown("<div class='cyber-card-alert' style='text-align:center;'>", unsafe_allow_html=True)
    st.subheader("🟢 Security Alerts Queue Clear")
    st.write("No threat incidents recorded. Upload logs on the Ingest page or run the Live Simulator to monitor traffic.")
    if st.button("Go to Log Ingest", use_container_width=True):
        st.switch_page("pages/Upload.py")
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

# Convert threats list to Pandas DataFrame
df = pd.DataFrame([dict(row) for row in threats])

# 6. Filters & Search Section
st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
st.subheader("🔍 Filter Alerts Queue")

col_f1, col_f2, col_f3 = st.columns(3)
with col_f1:
    search_ip = st.text_input("Search Source IP Address", placeholder="e.g. 10.0.")
with col_f2:
    filter_severity = st.multiselect("Severity Level", options=["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
with col_f3:
    filter_status = st.multiselect("Incident Status", options=["Open", "In Progress", "Resolved"], default=["Open", "In Progress", "Resolved"])

# Apply Filters
filtered_df = df.copy()
if search_ip:
    filtered_df = filtered_df[filtered_df['ip_address'].str.contains(search_ip, case=False)]
if filter_severity:
    filtered_df = filtered_df[filtered_df['severity'].isin(filter_severity)]
if filter_status:
    filtered_df = filtered_df[filtered_df['status'].isin(filter_status)]

st.write(f"Showing **{len(filtered_df)}** threat alerts matching filters.")
st.markdown("</div>", unsafe_allow_html=True)

# 7. Main Grid Layout & Action Panel Split
col_table, col_actions = st.columns([5, 3])

with col_table:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("🖥️ Alerts Datagrid")
    
    # Selection helpers
    selected_row_id = None
    
    if filtered_df.empty:
        st.info("No threats match your current filters.")
    else:
        # Display custom styled table rows with radio selection
        # Streamlit doesn't natively support interactive tables without ag-grid,
        # so a standard radio button selector or a dataframe selection widget is very stable.
        # Let's use st.dataframe with selection state or a simple radio/selectbox for incident selection.
        # selectbox is extremely clean and reliable!
        threat_options = [f"#{row['id']} - [{row['severity']}] {row['threat_type']} | IP: {row['ip_address']}" for _, row in filtered_df.iterrows()]
        
        selected_option = st.selectbox("Select Incident to Investigate & Remediate:", options=threat_options)
        
        if selected_option:
            selected_row_id = int(selected_option.split(" - ")[0].replace("#", ""))
            
        # Display the datagrid
        display_cols = ["id", "timestamp", "ip_address", "status_code", "threat_type", "severity", "confidence", "status"]
        st.dataframe(
            filtered_df[display_cols].style.map(
                lambda val: 'color: #ef4444; font-weight: bold;' if val == 'Critical' 
                else ('color: #f97316;' if val == 'High' 
                else ('color: #10b981;' if val == 'Resolved' 
                else ('color: #eab308;' if val == 'In Progress' else ''))),
                subset=['severity', 'status']
            ),
            use_container_width=True,
            hide_index=True
        )
    st.markdown("</div>", unsafe_allow_html=True)

with col_actions:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("🛡️ AI Recommendation Panel")
    
    if not selected_row_id:
        st.info("Select an incident from the datagrid to view AI recommendations and action plans.")
    else:
        # Fetch threat details
        threat_row = df[df['id'] == selected_row_id].iloc[0]
        
        # Threat Details
        st.markdown(f"""
        <div style="border-left: 4px solid #ef4444; padding-left: 10px; margin-bottom: 15px;">
            <div style="font-size:0.8rem; color:#9ca3af; text-transform:uppercase;">Threat Vector</div>
            <h4 style="margin:2px 0; color:#fff;">{threat_row['threat_type']}</h4>
            <span style="font-size:0.8rem; color:#9ca3af;">Confidence: <b>{threat_row['confidence']}%</b> | Source IP: <code style="color:#d4c5ff;">{threat_row['ip_address']}</code></span>
        </div>
        """, unsafe_allow_html=True)
        
        # Explainable AI Explanation Box
        st.markdown("<div style='background:rgba(0,0,0,0.2); padding:10px; border-radius:6px; margin-bottom:15px;'>", unsafe_allow_html=True)
        st.write("📖 **Explainable AI (XAI) Trigger:**")
        st.write(threat_row.get('xai_explanations') or "No explainable details logged for this alert.")
        st.write(f"**Log Message:** `{threat_row['message']}`")
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Interactive Remediation Tasks Checklist
        st.write("✔️ **Security Remediation Action Items:**")
        remediation_items = threat_row['remediation'].replace("✔ ", "").split("\n")
        for item in remediation_items:
            if item.strip():
                st.markdown(f"""
                <div class="rec-item">
                    <span class="rec-item-icon">✔</span>
                    <span>{item.strip()}</span>
                </div>
                """, unsafe_allow_html=True)
                
        # Status Action Board (RBAC restricted)
        st.markdown("---")
        st.subheader("⚙️ Incident Management")
        
        col_status_select, col_status_submit = st.columns([2, 1])
        with col_status_select:
            status_index = ["Open", "In Progress", "Resolved"].index(threat_row['status'])
            new_status = st.selectbox("Change Status:", options=["Open", "In Progress", "Resolved"], index=status_index)
        with col_status_submit:
            st.write(" ") # Padding spacer
            st.write(" ")
            update_btn = st.button("Apply", use_container_width=True)
            
        if update_btn:
            # Check permissions: Analysts and Admins can update status, Viewers cannot
            if not has_role(["Admin", "Security Analyst"]):
                st.error("🚫 Access Denied: You do not have permissions to modify incident status.")
            elif new_status == threat_row['status']:
                st.warning("Status is unchanged.")
            else:
                success = update_threat_status(selected_row_id, new_status, st.session_state.username)
                if success:
                    st.success(f"Incident #{selected_row_id} changed to '{new_status}'!")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("Failed to update status.")
                    
    st.markdown("</div>", unsafe_allow_html=True)
