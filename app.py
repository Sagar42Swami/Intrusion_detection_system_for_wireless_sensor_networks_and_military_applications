import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

# --- 1. TACTICAL CONFIGURATION ---
# Mapping model integers to human-readable military categories
MAP_LABELS = {
    0: "Analysis", 1: "Backdoor", 2: "DoS", 3: "Exploits", 
    4: "Fuzzers", 5: "Generic", 6: "Normal", 7: "Reconnaissance", 
    8: "Shellcode", 9: "Worms"
}

ATTACK_KNOWLEDGE_BASE = {
    "DoS": {"Sev": "HIGH", "Desc": "Resource exhaustion flood.", "Act": "Enable rate-limiting."},
    "Exploits": {"Sev": "CRITICAL", "Desc": "Protocol vulnerability targeted.", "Act": "Patch firmware."},
    "Fuzzers": {"Sev": "MEDIUM", "Desc": "Random data crash attempt.", "Act": "Flush node buffers."},
    "Reconnaissance": {"Sev": "LOW", "Desc": "Network topology mapping.", "Act": "Enable stealth mode."},
    "Normal": {"Sev": "SAFE", "Desc": "Standard operational traffic.", "Act": "None."}
}

# --- 2. AUTHENTICATION ---
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "threat_history" not in st.session_state:
    st.session_state["threat_history"] = []

if not st.session_state["authenticated"]:
    st.title("🛡️ Military IDS Login")
    u = st.text_input("Operator ID")
    p = st.text_input("Access Token", type="password")
    if st.button("Authenticate"):
        if u == "admin" and p == "wsn_secure_2024":
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Access Denied")
else:
    # --- 3. SIDEBAR GAUGE & NAVIGATION ---
    st.sidebar.title("📡 System Monitor")
    
    # Threat Level Gauge Logic
    recent_alerts = [a for a in st.session_state["threat_history"] if a != "Normal"]
    threat_val = min(len(recent_alerts) * 20, 100)
    st.sidebar.write(f"**Current Threat Level:** {threat_val}%")
    st.sidebar.progress(threat_val)
    
    if st.sidebar.button("Reset Logs"):
        st.session_state["threat_history"] = []
        st.rerun()

    page = st.sidebar.radio("Navigation", ["Real-time Detection", "Comparative Analytics"])

    try:
        model = joblib.load('military_ids_model.pkl')
        feature_names = joblib.load('feature_names.pkl')
    except:
        st.sidebar.warning("Model files missing. Please run the training notebook.")

    # --- 4. PAGE: REAL-TIME DETECTION ---
    if page == "Real-time Detection":
        st.title("🚀 Tactical Node Audit")
        
        with st.form("input_form"):
            st.subheader("Core Sensor Parameters")
            c1, c2 = st.columns(2)
            with c1:
                dur = st.number_input("Duration (dur)", value=0.12, format="%.6f")
                rate = st.number_input("Packet Rate", value=74.0)
                sttl = st.number_input("Source TTL (sttl)", value=252.0)
            with c2:
                sload = st.number_input("Source Load (sload)", value=14158.0)
                dload = st.number_input("Dest Load (dload)", value=8495.0)
                spkts = st.number_input("Source Packets (spkts)", value=6.0)
            
            submit = st.form_submit_button("Analyze Traffic")

        if submit:
            # Build full feature vector
            input_dict = {f: 0.0 for f in feature_names}
            input_dict.update({"dur": dur, "rate": rate, "sttl": sttl, "sload": sload, "dload": dload, "spkts": spkts})
            
            input_df = pd.DataFrame([input_dict])
            raw_pred = model.predict(input_df[feature_names])[0]
            
            # Translate raw integer to tactical name
            prediction = MAP_LABELS.get(raw_pred, str(raw_pred))
            st.session_state["threat_history"].append(prediction)
            
            if prediction == "Normal" or raw_pred == 6:
                st.success("✅ STATUS: SECURE")
            else:
                details = ATTACK_KNOWLEDGE_BASE.get(prediction, {"Sev": "HIGH", "Desc": "Anomalous traffic.", "Act": "Isolate node."})
                st.error(f"🚨 ALERT: {prediction} DETECTED")
                with st.expander("🔍 TACTICAL BRIEFING", expanded=True):
                    col_a, col_b = st.columns(2)
                    col_a.metric("Severity", details["Sev"])
                    col_a.write(f"**Summary:** {details['Desc']}")
                    col_b.write(f"**Recommended Action:** :red[{details['Act']}]")

    # --- 5. PAGE: ANALYTICS ---
    elif page == "Comparative Analytics":
        st.title("📊 Model Robustness Metrics")
        
        @st.cache_data
        def get_stats():
            df = pd.read_csv('UNSW_NB15_training-set.csv')
            X = df.drop(['id', 'proto', 'service', 'state', 'attack_cat', 'label'], axis=1)
            y = df['label']
            xtr, xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=32)
            
            results = []
            m_list = {"KNN": KNeighborsClassifier(), "DT": DecisionTreeClassifier(max_depth=20), "RF": RandomForestClassifier()}
            for n, m in m_list.items():
                m.fit(xtr, ytr)
                p = m.predict(xte)
                results.append({"Model": n, "Accuracy": accuracy_score(yte, p), "Precision": precision_score(yte, p, average='weighted'), "Recall": recall_score(yte, p, average='weighted'), "F1": f1_score(yte, p, average='weighted')})
            return pd.DataFrame(results)

        stats_df = get_stats()
        st.table(stats_df)
        
        fig, ax = plt.subplots(figsize=(10, 4))
        sns.barplot(data=stats_df.melt(id_vars="Model"), x="variable", y="value", hue="Model", ax=ax)
        plt.ylim(0.85, 1.0)
        st.pyplot(fig)