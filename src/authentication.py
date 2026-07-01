import streamlit as st
from src.database import verify_user, log_action
import os

def load_custom_css():
    """Loads custom CSS style overrides into the Streamlit application."""
    css_path = os.path.join("assets", "css", "style.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            css_content = f.read()
        st.markdown(f"<style>{css_content}</style>", unsafe_allow_html=True)

def init_auth_state():
    """Initializes session state variables for authentication."""
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "username" not in st.session_state:
        st.session_state.username = None
    if "role" not in st.session_state:
        st.session_state.role = None

def logout():
    """Logs the current user out and clears session state."""
    if st.session_state.authenticated:
        log_action(st.session_state.username, "LOG_OUT", "User logged out successfully.")
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.role = None
    st.rerun()

def login_screen():
    """Renders a beautiful Glassmorphism login screen."""
    load_custom_css()
    
    # Visual Container
    st.markdown("<div class='animated-logo'>LOGSENTRIX AI</div>", unsafe_allow_html=True)
    st.markdown("<div style='text-align: center; color: #9ca3af; margin-bottom: 2rem;'>NEXT-GENERATION SECURITY INFORMATION & EVENT MANAGEMENT</div>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
        st.subheader("🔑 Security Console Login")
        
        username = st.text_input("Username", placeholder="Enter username...")
        password = st.text_input("Password", type="password", placeholder="Enter password...")
        
        login_btn = st.button("Authenticate", use_container_width=True)
        
        if login_btn:
            if not username or not password:
                st.error("Please fill in both fields.")
            else:
                user = verify_user(username, password)
                if user:
                    st.session_state.authenticated = True
                    st.session_state.username = user["username"]
                    st.session_state.role = user["role"]
                    log_action(user["username"], "LOG_IN", f"User logged in with role '{user['role']}'")
                    st.success(f"Authenticated as {user['role']}!")
                    st.rerun()
                else:
                    st.error("Access Denied: Invalid username or password.")
                    
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Info notice
        st.markdown("""
        <div style='font-size: 0.8rem; text-align: center; color: #6b7280; margin-top: 1.5rem;'>
            Demo Accounts:<br>
            • Admin: admin / admin123<br>
            • Analyst: analyst / analyst123<br>
            • Viewer: viewer / viewer123
        </div>
        """, unsafe_allow_html=True)

def has_role(required_roles):
    """Checks if the logged-in user matches any of the required roles."""
    if not st.session_state.authenticated:
        return False
    if isinstance(required_roles, str):
        return st.session_state.role == required_roles
    return st.session_state.role in required_roles

def enforce_permission(required_roles):
    """Enforces that the user has specific roles. Displays alert and halts page execution if not."""
    if not has_role(required_roles):
        st.error("🚫 Access Denied: You do not have permissions to perform this action.")
        st.stop()
