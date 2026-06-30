import streamlit as st

# ---------------- PAGE CONFIG ---------------- #

st.set_page_config(
    page_title="LogSentrix AI",
    page_icon="asserts/logo.png",
    layout="centered"
)

# ---------------- CUSTOM CSS ---------------- #

st.markdown("""
<style>

.stApp{
    background:#0E1117;
}

.block-container{
    max-width:950px;
    padding-top:2rem;
}

/* HERO CARD */

.hero{

    background:linear-gradient(135deg,#0B1220,#111827);

    border:1px solid rgba(59,130,246,.35);

    border-radius:25px;

    padding:40px;

    text-align:center;

    box-shadow:0px 0px 35px rgba(37,99,235,.15);

}

.hero-title{

    font-size:52px;

    font-weight:800;

    color:white;

    margin-top:10px;

}

.hero-sub{

    font-size:18px;

    color:#AAB4C3;

    margin-top:-10px;

}

/* Upload Card */

.upload-card{

    background:#161B22;

    border-radius:20px;

    padding:30px;

    margin-top:35px;

    border:1px solid #2B3648;

}

/* Footer */

.footer{

    text-align:center;

    color:#6B7280;

    margin-top:40px;

    font-size:14px;

}

</style>
""", unsafe_allow_html=True)

# ---------------- HERO SECTION ---------------- #

st.markdown('<div class="hero">', unsafe_allow_html=True)

st.image("asserts/logo.png", width=170)

st.markdown(
'<div class="hero-title">LogSentrix AI</div>',
unsafe_allow_html=True
)

st.markdown(
'<div class="hero-sub">Transforming System Logs into Actionable Intelligence</div>',
unsafe_allow_html=True
)

st.markdown("</div>", unsafe_allow_html=True)

# ---------------- SPACING ---------------- #

st.write("")
st.write("")

# ---------------- UPLOAD CARD ---------------- #

st.markdown('<div class="upload-card">', unsafe_allow_html=True)

st.subheader("📂 Upload Log File")

st.caption("Supported file formats: CSV • LOG • TXT")

uploaded_file = st.file_uploader(
    "",
    type=["csv", "log", "txt"],
    label_visibility="collapsed"
)

st.markdown("</div>", unsafe_allow_html=True)

# ---------------- FILE DETAILS ---------------- #

if uploaded_file is not None:

    st.success("✅ File uploaded successfully!")

    c1, c2 = st.columns(2)

    with c1:
        st.metric("File Name", uploaded_file.name)

    with c2:
        st.metric("File Size", f"{uploaded_file.size/1024:.2f} KB")

    st.write("")

    if st.button("🚀 Analyze Logs", use_container_width=True):

        with st.spinner("Analyzing logs..."):

            # Your prediction function goes here

            st.success("Analysis Completed Successfully!")

# ---------------- FOOTER ---------------- #

st.markdown("""
<div class='footer'>

LogSentrix AI © 2026

</div>
""", unsafe_allow_html=True)
