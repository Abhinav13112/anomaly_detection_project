import streamlit as st
import pandas as pd
import numpy as np
from src.authentication import init_auth_state, load_custom_css, logout
from src.database import get_threats, get_kpis

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
st.markdown("<h1 class='cyber-title'>📊 CYBER THREAT ANALYTICS</h1>", unsafe_allow_html=True)
st.markdown("<p class='cyber-subtitle'>Interactive security data visualizations and machine learning models metrics.</p>", unsafe_allow_html=True)

# 5. Fetch Threat Alerts
threats_list = get_threats(limit=1000)

if not threats_list:
    st.markdown("<div class='cyber-card-alert' style='text-align:center;'>", unsafe_allow_html=True)
    st.subheader("⚠️ No Analytics Data Available")
    st.write("Please run the log ingestion pipeline first on the Upload page to generate threats history data.")
    if st.button("Ingest Log Files Now", use_container_width=True):
        st.switch_page("pages/Upload.py")
    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

# Import Plotly (we expect it's installed or currently installing)
try:
    import plotly.express as px
    import plotly.graph_objects as go
except ImportError:
    st.error("Plotly is currently installing or failed to load. Please wait a moment and refresh this page.")
    st.stop()

# 6. Load DataFrame
df = pd.DataFrame(threats_list)

# Preprocess DataFrame for chart aggregations
df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['day_name'] = df['timestamp'].dt.day_name()

# Custom neon colors for Plotly charts
cyber_colors = ['#00f2fe', '#9b51e0', '#ff007f', '#eab308', '#ef4444', '#10b981']

# 7. Row 1: High Level Threat Summaries
col_sev, col_types = st.columns(2)

with col_sev:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("🔴 Severity Distribution")
    
    # Agg severity counts
    sev_counts = df['severity'].value_counts().reset_index()
    sev_counts.columns = ['Severity', 'Count']
    
    # Map colors to match severity importance
    color_map = {
        "Critical": "#ef4444",
        "High": "#f97316",
        "Medium": "#eab308",
        "Low": "#3b82f6"
    }
    
    fig_pie = px.pie(
        sev_counts, 
        values='Count', 
        names='Severity', 
        hole=0.4,
        color='Severity',
        color_discrete_map=color_map,
        template='plotly_dark'
    )
    fig_pie.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(t=10, b=10, l=10, r=10),
        legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5)
    )
    st.plotly_chart(fig_pie, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

with col_types:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("🛡️ Attack Vector Categories")
    
    # Agg threat categories
    threat_counts = df['threat_type'].value_counts().reset_index()
    threat_counts.columns = ['Threat Category', 'Count']
    
    fig_bar_types = px.bar(
        threat_counts,
        x='Count',
        y='Threat Category',
        orientation='h',
        color='Count',
        color_continuous_scale=['#9b51e0', '#00f2fe'],
        template='plotly_dark'
    )
    fig_bar_types.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(t=10, b=10, l=10, r=10),
        coloraxis_showscale=False
    )
    st.plotly_chart(fig_bar_types, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

# 8. Row 2: Temporal Trends & Host Analysis
col_trend, col_ip = st.columns(2)

with col_trend:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("📈 Hourly Threat Activity Trend")
    
    # Group threats by hour of day
    hourly_threats = df.groupby('hour').size().reset_index(name='Incidents')
    
    # Ensure all 24 hours are represented
    all_hours = pd.DataFrame({'hour': range(24)})
    hourly_threats = pd.merge(all_hours, hourly_threats, on='hour', how='left').fillna(0)
    
    fig_trend = px.line(
        hourly_threats,
        x='hour',
        y='Incidents',
        labels={'hour': 'Hour of Day (0-23)', 'Incidents': 'Alert Counts'},
        template='plotly_dark'
    )
    fig_trend.update_traces(
        line=dict(color='#00f2fe', width=3),
        fill='tozeroy',
        fillcolor='rgba(0, 242, 254, 0.1)'
    )
    fig_trend.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(showgrid=False, tickmode='linear', tick0=0, dtick=4),
        yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)'),
        margin=dict(t=10, b=10, l=10, r=10)
    )
    st.plotly_chart(fig_trend, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

with col_ip:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("💀 Top 10 Offending Source IPs")
    
    # Top 10 source IPs
    top_ips = df['ip_address'].value_counts().head(10).reset_index()
    top_ips.columns = ['Source IP', 'Alert Count']
    
    fig_ips = px.bar(
        top_ips,
        x='Source IP',
        y='Alert Count',
        color='Alert Count',
        color_continuous_scale=['#00f2fe', '#ff007f'],
        template='plotly_dark'
    )
    fig_ips.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)'),
        margin=dict(t=10, b=10, l=10, r=10),
        coloraxis_showscale=False
    )
    st.plotly_chart(fig_ips, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

# 9. Row 3: Heatmap (Exploits timeline vs category) & Confidence Histogram
col_heat, col_hist = st.columns(2)

with col_heat:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("🔥 Threat Activity Heatmap (Hour vs Threat)")
    
    # Create pivot table
    pivot_df = df.groupby(['hour', 'threat_type']).size().unstack(fill_value=0)
    
    fig_heat = px.imshow(
        pivot_df,
        labels=dict(x="Threat Category", y="Hour of Day", color="Occurrences"),
        color_continuous_scale='Viridis',
        template='plotly_dark'
    )
    fig_heat.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(t=10, b=10, l=10, r=10),
        coloraxis_showscale=True
    )
    st.plotly_chart(fig_heat, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

with col_hist:
    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("🎯 ML Prediction Confidence Histogram")
    
    fig_hist = px.histogram(
        df,
        x='confidence',
        nbins=20,
        labels={'confidence': 'Model Confidence (%)'},
        template='plotly_dark',
        color_discrete_sequence=['#9b51e0']
    )
    fig_hist.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)'),
        margin=dict(t=10, b=10, l=10, r=10)
    )
    st.plotly_chart(fig_hist, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)
