import streamlit as st
from src.authentication import init_auth_state, login_screen, logout, load_custom_css

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
    
    # Render customized branding inside sidebar
    with st.sidebar:
        st.markdown(f"""
        <div class="cyber-card" style="padding: 10px; text-align: center; border-left: 3px solid #00f2fe;">
            <h3 style="margin: 0; color: #fff; font-family: 'Share Tech Mono';">🛡️ LOGSENTRIX AI</h3>
            <span style="font-size: 0.8rem; color: #9ca3af;">SIEM SECURITY CONSOLE</span>
        </div>
        """, unsafe_allow_html=True)
        
        st.sidebar.markdown("---")
        
        # Display Profile info
        st.markdown(f"""
        <div class="cyber-card" style="margin-bottom: 20px;">
            <div style="font-size: 0.8rem; color: #9ca3af;">Authenticated User:</div>
            <div style="font-weight: bold; color: #00f2fe; font-size: 1.1rem;">@{st.session_state.username}</div>
            <div style="font-size: 0.75rem; background: rgba(155, 81, 224, 0.2); border: 1px solid rgba(155, 81, 224, 0.4); border-radius: 4px; padding: 2px 6px; display: inline-block; margin-top: 5px; color: #d8b4fe;">
                {st.session_state.role}
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Add logout option
        if st.sidebar.button("🔐 Terminate Session", use_container_width=True):
            logout()
            
    # Redirect to Dashboard page automatically
    st.switch_page("pages/Dashboard.py")
