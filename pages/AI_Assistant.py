import streamlit as st
from src.authentication import init_auth_state, load_custom_css, logout
from src.chatbot import chatbot

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
st.markdown("<h1 class='cyber-title'>💬 AI SECURITY ASSISTANT</h1>", unsafe_allow_html=True)
st.markdown("<p class='cyber-subtitle'>Ask the LogSentrix AI model questions regarding recent log anomalies, threat vectors, or mitigation check-lists.</p>", unsafe_allow_html=True)

# 5. Initialize Chat History
if "chat_history" not in st.session_state:
    st.session_state.chat_history = [
        {
            "role": "assistant",
            "content": """
            ### 🤖 LogSentrix Security Assistant Launched
            
            How can I help you secure system endpoints today? Here are some recommended queries you can ask:
            - **"Give today's summary"** (Fetch current SIEM KPIs and threat levels)
            - **"Show critical threats"** (List active high/critical severity alerts)
            - **"Why was this anomaly detected?"** (Explain the Isolation Forest & TF-IDF vectorizer logic)
            - **"Explain SQL Injection attacks and how to prevent them"**
            - **"How do I remediate a DDoS connection timeout event?"**
            """
        }
    ]

# 6. Render Conversation History
for msg in st.session_state.chat_history:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# 7. User Input & Query Evaluation
user_input = st.chat_input("Enter your security command or question...")

if user_input:
    # Append user question
    st.session_state.chat_history.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)
        
    # Query Chatbot
    bot_response = chatbot.get_response(user_input)
    
    # Append bot reply
    st.session_state.chat_history.append({"role": "assistant", "content": bot_response})
    with st.chat_message("assistant"):
        st.markdown(bot_response)
