import streamlit as st
from src.authentication import init_auth_state, load_custom_css, enforce_permission, has_role, render_sidebar
from src.database import get_setting, save_setting, create_user

# 1. Enforce Authentication (Analyst/Admin needed to see/edit settings)
init_auth_state()
if not st.session_state.authenticated:
    st.switch_page("app.py")
    st.stop()

enforce_permission(["Admin", "Security Analyst"])

# 2. Load Custom CSS
load_custom_css()

# 3. Sidebar Configuration
render_sidebar()

# 4. Header
st.markdown("<h1 class='cyber-title'>⚙️ CONSOLE CONFIGURATION</h1>", unsafe_allow_html=True)
st.markdown("<p class='cyber-subtitle'>Tune anomaly detection model parameters and edit alerts notification triggers.</p>", unsafe_allow_html=True)

# 5. Load settings from database
db_threshold = float(get_setting("detection_threshold", "0.08"))
db_refresh = int(get_setting("auto_refresh_interval", "5"))
db_email_enabled = get_setting("email_alerts_enabled", "False") == "True"
db_email_rec = get_setting("email_alerts_recipient", "security@company.com")
db_sound_enabled = get_setting("sound_alerts_enabled", "True") == "True"
db_model = get_setting("active_model", "Isolation Forest")

# 6. Tab layout for Settings Panels
tab_detection, tab_alerts, tab_users = st.tabs(["🧠 AI Detection Threshold", "🔔 Alert Triggers", "👤 Admin User Accounts"])

with tab_detection:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("Isolation Forest Parameters")
    
    selected_model = st.selectbox(
        "Active Classifier Architecture:", 
        options=["Isolation Forest", "One-Class SVM (Experimental)", "Autoencoder (Deep Learning)"],
        index=["Isolation Forest", "One-Class SVM (Experimental)", "Autoencoder (Deep Learning)"].index(db_model)
    )
    
    st.write("Isolation Forest contamination rate sets the statistical percentage of anomalies expected in normal log profiles.")
    selected_threshold = st.slider(
        "Contamination Rate (Anomaly Threshold):", 
        min_value=0.01, 
        max_value=0.20, 
        value=db_threshold, 
        step=0.01,
        help="Higher contamination flags more logs, increasing false positives. Lower contamination flags only highly isolated events."
    )
    
    if st.button("Apply Model Settings", use_container_width=True):
        save_setting("detection_threshold", str(selected_threshold), st.session_state.username)
        save_setting("active_model", selected_model, st.session_state.username)
        st.success("AI model configuration updated in database.")
        time.sleep(0.5)
        st.rerun()
        
    st.markdown("</div>", unsafe_allow_html=True)

with tab_alerts:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("Notification Channels Setup")
    
    selected_sound = st.toggle("Enable Browser Alarm Sounds", value=db_sound_enabled, help="Plays synth beep alarms in client browser when anomaly is flagged.")
    selected_email = st.toggle("Enable Email Notifications (Mocked)", value=db_email_enabled, help="Triggers dispatch of logs to recipient mail box.")
    selected_email_rec = st.text_input("Security Response Email Recipient:", value=db_email_rec)
    
    if st.button("Save Alert Configurations", use_container_width=True):
        save_setting("sound_alerts_enabled", str(selected_sound), st.session_state.username)
        save_setting("email_alerts_enabled", str(selected_email), st.session_state.username)
        save_setting("email_alerts_recipient", selected_email_rec, st.session_state.username)
        st.success("Notifications settings updated successfully.")
        time.sleep(0.5)
        st.rerun()
        
    st.markdown("</div>", unsafe_allow_html=True)

with tab_users:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("Register Console Operator Account")
    
    # RBAC protection: Only Admins can register new users!
    if not has_role("Admin"):
        st.warning("🔒 Access Blocked: Only Administrator accounts can manage operator profiles.")
    else:
        new_username = st.text_input("Operator Username:", placeholder="e.g. analyst_bob")
        new_password = st.text_input("Password Input:", type="password", placeholder="Set password...")
        new_role = st.selectbox("Assign Permission Role:", options=["Viewer", "Security Analyst", "Admin"])
        
        if st.button("Provision Operator Profile", use_container_width=True):
            if not new_username or not new_password:
                st.error("Please fill in username and password fields.")
            else:
                success = create_user(new_username, new_password, new_role, st.session_state.username)
                if success:
                    st.success(f"User account @{new_username} successfully provisioned as {new_role}!")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("Username already registered in system directory.")
                    
    st.markdown("</div>", unsafe_allow_html=True)
