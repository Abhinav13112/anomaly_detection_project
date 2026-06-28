import streamlit as st

st.title("AI-Driven Anomaly Detection System")
st.write("Welcome to the Log Analysis Project")

uploaded_file = st.file_uploader("Upload a log file")

if uploaded_file:
    st.success("File uploaded successfully!")
    # Call your prediction function here
