import streamlit as st

st.set_page_config(page_title="LogSentrix AI", layout="centered")

col1, col2 = st.columns([1,4])

with col1:
    st.image("LogSentrixAi logo.png", width=80)

with col2:
    st.title("LogSentrix AI")
    st.caption("Transforming System Logs into Actionable Intelligence.")

uploaded_file = st.file_uploader(
    "Upload a Log File",
    type=["csv", "log", "txt"]
)

if uploaded_file:
    st.success("✅ File uploaded successfully!")
