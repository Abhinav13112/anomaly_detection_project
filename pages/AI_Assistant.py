import streamlit as st
from src.authentication import init_auth_state, load_custom_css, render_sidebar
from src.chatbot import chatbot

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
