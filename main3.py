import streamlit as st
import pandas as pd

st.title("IDS - Intrusion Detection System")
st.subheader("Welcome to the Intrusion Detection System (IDS) dashboard!")                      
st.text("This dashboard provides insights and visualizations related to network security and intrusion detection.")

file=st.file_uploader("Upload your network traffic data (CSV format)", type=["csv"])
if file is not None:
    data = pd.read_csv(file)
    st.write("Data Preview:")
    st.dataframe(data.head())
    
    st.write("Data Summary:")
    st.write(data.describe())
    
    st.write("Data Visualization:")
    st.line_chart(data['dbytes'])  # Assuming 'network_traffic' is a column in the CSV