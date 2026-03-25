import streamlit as st

st.title("IDS - Intrusion Detection System")
st.subheader("Welcome to the Intrusion Detection System (IDS) dashboard!")  
st.text("This dashboard provides insights and visualizations related to network security and intrusion detection.")
st.write("Here you can explore various metrics, analyze network traffic, and monitor potential security threats in real-time.") 

op1=st.selectbox("Select a metric to visualize:", ["Network Traffic", "Intrusion Attempts", "Top Attack Sources", "Real-time Alerts"])
st.write(f"You selected: {op1}")
st.success("This feature is under development. Stay tuned for updates!")
