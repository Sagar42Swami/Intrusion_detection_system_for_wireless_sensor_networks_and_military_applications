import streamlit as st
import pandas as pd
import numpy as np

st.set_page_config(layout="wide")

# ------------------ HEADER ------------------
st.title("🛡️ IDS Dashboard")

# ------------------ TOP METRICS ------------------
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", "1,245", "+12.5%")
col2.metric("Critical Alerts", "245", "")
col3.metric("Current Threats", "8", "4 High Risk")
col4.success("System Health: Operational")

# ------------------ CHARTS ------------------
st.markdown("## 📊 Threat Activity")

col5, col6 = st.columns([2, 1])

# Line chart (Threat Activity)
days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
critical = [120, 150, 200, 180, 230, 270, 250]
total = [80, 100, 140, 120, 170, 190, 200]

df = pd.DataFrame({
    "Days": days,
    "Critical Alerts": critical,
    "Total Alerts": total
}).set_index("Days")

col5.line_chart(df)

# Pie Chart (Alert Severity)
severity_data = pd.DataFrame({
    "Severity": ["High", "Medium", "Low"],
    "Percentage": [30, 45, 25]
})

col6.write("### Alert Severity")
col6.bar_chart(severity_data.set_index("Severity"))

# ------------------ RECENT ALERTS ------------------
st.markdown("## 🚨 Recent Alerts")

alerts = [
    "🔴 Critical | Ransomware Activity Detected (5 min ago)",
    "🟠 High | Brute Force Login Attempt (15 min ago)",
    "🟡 Medium | Suspicious Network Scan (25 min ago)",
    "🔴 Critical | SQL Injection Attack (45 min ago)",
    "🔵 Low | Unusual Outbound Traffic (1 hr ago)"
]

for alert in alerts:
    st.write(alert)

# ------------------ ACTIVE THREATS TABLE ------------------
st.markdown("## 🧾 Active Threats")

data = {
    "Alert": ["Ransomware", "SQL Injection", "Brute Force", "Malware"],
    "Severity": ["High", "Medium", "High", "Medium"],
    "Source IP": ["192.168.1.45", "203.0.113.22", "104.26.88.12", "198.51.100.33"],
    "Target IP": ["10.0.0.5", "192.168.2.10", "10.0.1.15", "172.16.5.20"],
    "Time": ["5 min ago", "12 min ago", "20 min ago", "30 min ago"]
}

df_table = pd.DataFrame(data)
st.dataframe(df_table, use_container_width=True)

# ------------------ NETWORK TRAFFIC ------------------
st.markdown("## 🌐 Network Traffic")

col7, col8 = st.columns(2)

col7.metric("Incoming Traffic", "850 MB/s")
col8.metric("Outgoing Traffic", "475 MB/s")

traffic = np.random.randint(100, 900, 20)
st.bar_chart(traffic)

# ------------------ SYSTEM LOGS ------------------
st.markdown("## 📜 System Logs")

logs = [
    "2022-07-21 | Failed login attempt from 203.0.113.45",
    "2022-07-21 | Malicious file download blocked",
    "2022-07-20 | IDS signature update completed",
    "2022-07-20 | Network scan detected"
]

for log in logs:
    st.text(log)