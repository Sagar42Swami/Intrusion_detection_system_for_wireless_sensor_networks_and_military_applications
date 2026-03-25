import streamlit as st
from PIL import Image   

st.title("IDS - Intrusion Detection System")

if st.button("Show IDS Image"):
    image = Image.open("ids.png")  
    st.image(image, caption="Intrusion Detection System Visualization", width=300)
    
c1 = st.checkbox("Show IDS Metrics")

if c1:
    st.write("Here you can explore various metrics related to network security and intrusion detection.")
    
    o1 = st.radio("Select a metric to visualize:", 
                  ["Network Traffic", "Intrusion Attempts", "Top Attack Sources", "Real-time Alerts"])
    
    st.write(f"You selected (Radio): {o1}")
    
    o2 = st.selectbox("Select another metric:", 
                      ["Network Traffic", "Intrusion Attempts", "Top Attack Sources", "Real-time Alerts"])
    
    st.write(f"You selected (Dropdown): {o2}")
    
    level = st.slider("Select alert level:", 0, 10, 5)
    st.write(f"Alert level set to: {level}")
    
    val= st.number_input("Enter a threshold value:", min_value=0, max_value=100, value=50)
    st.write(f"Threshold value set to: {val}")
    
    attack_sources = st.text_input("Enter top attack sources (comma separated):")
    st.write(f"Top attack sources: {attack_sources}")
    
    DATE = st.date_input("Select a date for analysis:")
    st.write(f"Selected date: {DATE}")
    
    c1,c2=st.columns(2)
    
    with c1:
        st.header("Intrusion Attempts Over Time")
        b1= st.button("Show Intrusion Attempts Chart")
        if b1:
            image = Image.open("ids.png")  
            st.image(image, caption="Intrusion Attempts Over Time", width=300)
        st.write("Intrusion Attempts Over Time")
        st.line_chart([10, 20, 15, 30, 25])  # Placeholder data
        
    with c2:
        st.header("Top Attack Sources")
        st.write("Top Attack Sources")
        st.bar_chart([5, 10, 15, 20])  # Placeholder data
        
sidebar = st.sidebar
sidebar.header("IDS Settings")  

with st.expander("Show attack options "):
    st.write("""1.Network Traffic"2. "Intrusion Attempts" """)
    
st.markdown('### Show alert levels ')
st.markdown('> Show alert levels ')
