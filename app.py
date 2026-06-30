import streamlit as st

st.title("LogSentrix AI")
st.write("Transforming System Logs into Actionable Intelligence..")

uploaded_file = st.file_uploader("Upload a log file")

if uploaded_file:
    st.success("File uploaded successfully!")
    # Call your prediction function here
