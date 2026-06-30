import streamlit as st

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="LogSentrix AI",
    page_icon="assets/LogSentrixAi logo.png",
    layout="centered"
)

# ---------------- CUSTOM CSS ----------------
st.markdown("""
<style>

.block-container{
    padding-top:2rem;
    padding-bottom:2rem;
}

.logo{
    display:flex;
    justify-content:center;
    margin-bottom:15px;
}

.title{
    text-align:center;
    font-size:52px;
    font-weight:800;
    color:white;
    margin-bottom:0;
}

.tagline{
    text-align:center;
    color:#B8C2CC;
    font-size:20px;
    margin-bottom:35px;
}

.upload-box{
    border:2px dashed #3B82F6;
    border-radius:20px;
    padding:25px;
    background-color:#111827;
}

</style>
""", unsafe_allow_html=True)

# ---------------- LOGO ----------------
st.markdown('<div class="logo">', unsafe_allow_html=True)
st.image("assets/LogSentrixAi logo.png", width=180)
st.markdown("</div>", unsafe_allow_html=True)

# ---------------- TITLE ----------------
st.markdown(
    '<p class="title">LogSentrix AI</p>',
    unsafe_allow_html=True
)

# ---------------- TAGLINE ----------------
st.markdown(
    '<p class="tagline">Transforming System Logs into Actionable Intelligence.</p>',
    unsafe_allow_html=True
)

st.divider()

st.subheader("📂 Upload Your Log File")

st.markdown('<div class="upload-box">', unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    "",
    type=["csv", "log", "txt"],
    help="Supported formats: CSV, LOG, TXT"
)

st.markdown("</div>", unsafe_allow_html=True)

if uploaded_file is not None:
    st.success("✅ File uploaded successfully!")

    st.info(f"**File Name:** {uploaded_file.name}")
