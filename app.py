import streamlit as st
from src.authentication import init_auth_state, login_screen, logout, load_custom_css, render_sidebar

# 1. Config page settings
st.set_page_config(
    page_title="LogSentrix AI Security Control",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Initialize auth state variables
init_auth_state()

# 3. Handle routing / page display
if not st.session_state.authenticated:
    # Hide sidebar when unauthenticated
    st.markdown("""
        <style>
            [data-testid="stSidebar"] {
                display: none !important;
            }
        </style>
    """, unsafe_allow_html=True)
    
    # Display login screen
    login_screen()
else:
    # If authenticated, render a quick landing page or auto-redirect to Dashboard
    load_custom_css()
    render_sidebar()
    
    # Redirect to Dashboard page automatically
    st.switch_page("pages/Dashboard.py")
