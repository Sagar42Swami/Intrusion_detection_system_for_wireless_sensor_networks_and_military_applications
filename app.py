from datetime import datetime
import random
import time

import joblib
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier

st.set_page_config(
    page_title="Military IDS Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

AUTH_CONFIG = {
    "Admin": {"user": "admin", "token": "wsn_secure_2024"},
    "Analyst": {"user": "analyst", "token": "wsn_analyst_2024"},
    "Operator": {"user": "operator", "token": "wsn_operator_2024"},
}
TRAINING_DATA = "UNSW_NB15_training-set.csv"
MODEL_FILE = "models/military_ids_model2.pkl"
FEATURE_FILE = "models/feature_names2.pkl"
MODEL_ENCODER = "models/label_encoder2.pkl"

PRIMARY_INPUTS = [
    "dur", "rate", "sttl", "dttl", "sload", "dload",
    "spkts", "dpkts", "sbytes", "dbytes", "ct_state_ttl", "ct_srv_dst",
]

FEATURE_LABELS = {
    "dur": "Duration",
    "rate": "Packet Rate",
    "sttl": "Source TTL",
    "dttl": "Destination TTL",
    "sload": "Source Load",
    "dload": "Destination Load",
    "spkts": "Source Packets",
    "dpkts": "Destination Packets",
    "sbytes": "Source Bytes",
    "dbytes": "Destination Bytes",
    "sinpkt": "Source Inter-Packet Gap",
    "dinpkt": "Destination Inter-Packet Gap",
    "sjit": "Source Jitter",
    "djit": "Destination Jitter",
    "ct_state_ttl": "State/TTL Count",
    "ct_srv_dst": "Service to Destination Count",
    "ct_srv_src": "Service to Source Count",
    "ct_dst_src_ltm": "Dst-Source Lifetime Count",
    "ct_dst_ltm": "Destination Lifetime Count",
    "ct_src_ltm": "Source Lifetime Count",
    "ct_src_dport_ltm": "Source-to-DPort Lifetime Count",
    "ct_dst_sport_ltm": "Destination-to-SPort Lifetime Count",
    "smean": "Mean Source Packet Size",
    "dmean": "Mean Destination Packet Size",
}

THREAT_KNOWLEDGE_BASE = {
    "Analysis": {
        "severity": "LOW",
        "summary": "Traffic resembles analytical probing or controlled inspection activity.",
        "impact": "Could be benign testing, but also useful reconnaissance groundwork.",
        "action": "Verify operator intent and keep the source under observation.",
    },
    "Backdoor": {
        "severity": "CRITICAL",
        "summary": "Persistence-oriented command traffic is strongly suggested.",
        "impact": "Unauthorized remote control or covert beaconing may already be active.",
        "action": "Quarantine the node, rotate credentials, and inspect persistence mechanisms.",
    },
    "Generic": {
        "severity": "CRITICAL",
        "summary": "Broad-spectrum high-volume traffic with strong flood characteristics.",
        "impact": "Likely service saturation with minimal downstream response traffic.",
        "action": "Throttle ingress traffic, isolate the segment, and rotate exposed services.",
    },
    "DoS": {
        "severity": "HIGH",
        "summary": "Traffic profile resembles denial-of-service style exhaustion.",
        "impact": "Node responsiveness may collapse under sustained load spikes.",
        "action": "Enable rate limiting and move the node to a protected network policy.",
    },
    "Exploits": {
        "severity": "HIGH",
        "summary": "Targeted interaction pattern with elevated TTL and focused service activity.",
        "impact": "Higher probability of protocol abuse or attempted remote execution.",
        "action": "Patch exposed services and review command-channel integrity immediately.",
    },
    "Fuzzers": {
        "severity": "MEDIUM",
        "summary": "Irregular input profile consistent with parser stress traffic.",
        "impact": "Potential instability, malformed payload processing, or degraded service health.",
        "action": "Enable stricter validation and inspect suspicious payload samples.",
    },
    "Reconnaissance": {
        "severity": "MEDIUM",
        "summary": "Low-interaction probing pattern consistent with service discovery.",
        "impact": "Adversary may be mapping attack paths before escalation.",
        "action": "Increase logging, suppress banners, and flag the origin for monitoring.",
    },
    "Shellcode": {
        "severity": "CRITICAL",
        "summary": "Payload-delivery behavior resembles shellcode-oriented exploitation.",
        "impact": "Memory corruption or code execution attempts may be in progress.",
        "action": "Isolate the endpoint and validate binaries before restoring service.",
    },
    "Worms": {
        "severity": "CRITICAL",
        "summary": "Propagation-friendly attack pattern suggests self-spreading behavior.",
        "impact": "There is elevated risk of lateral movement across peer nodes.",
        "action": "Segment the network immediately and scan adjacent nodes for spread.",
    },
    "Normal": {
        "severity": "SAFE",
        "summary": "Traffic remains close to learned normal operating conditions.",
        "impact": "No immediate operational degradation expected.",
        "action": "Continue observation.",
    },
}

LOW_CONFIDENCE_ALERTS = {
    "Analysis": "Analysis detections currently favor recall over precision. Treat this as an early-warning signal and confirm with surrounding telemetry before escalation.",
    "Backdoor": "Backdoor detections are still precision-weak after rebalancing. Validate with host logs, session history, and persistence indicators before acting on this label alone.",
}

PROFILE_FEATURES = [
    "rate", "sload", "dload", "sttl", "dttl", "spkts",
    "dpkts", "ct_state_ttl", "ct_srv_dst", "ct_dst_src_ltm", "smean", "dmean",
]
PLOT_FEATURES = [
    "rate", "sload", "dload", "sttl", "dttl",
    "spkts", "dpkts", "ct_state_ttl", "ct_srv_dst", "ct_dst_src_ltm",
]
DISPLAY_COLUMNS = ["timestamp", "status", "risk_score", "predicted_label", "severity", "top_signal"]
DATA_COLUMNS = ["id", "proto", "service", "state", "attack_cat", "label"]
SIMULATION_ORDER = [
    "Normal",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Analysis",
    "Backdoor",
    "Shellcode",
    "Worms",
]


def inject_styles():
    st.markdown(
        """
        <style>
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        .stApp {
            background:
                radial-gradient(circle at 14% 18%, rgba(32, 201, 151, 0.12), transparent 20%),
                radial-gradient(circle at 84% 16%, rgba(64, 145, 255, 0.12), transparent 18%),
                radial-gradient(circle at 50% 82%, rgba(22, 163, 74, 0.08), transparent 24%),
                linear-gradient(180deg, #010404 0%, #03110d 26%, #041a1a 56%, #06131c 100%);
            color: #e7f4ef;
        }
        .stApp::before {
            content: "";
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image:
                linear-gradient(rgba(86, 160, 128, 0.06) 1px, transparent 1px),
                linear-gradient(90deg, rgba(86, 160, 128, 0.06) 1px, transparent 1px);
            background-size: 36px 36px;
            mask-image: linear-gradient(180deg, rgba(0,0,0,0.24), rgba(0,0,0,0.06));
        }
        .block-container { padding-top: 1.1rem; padding-bottom: 1.4rem; max-width: 1380px; }
        h1, h2, h3, h4 { letter-spacing: 0.01em; }
        p, label, div { font-size: 1rem; }
        .animated-gradient-text {
            background: linear-gradient(90deg, #8b5cf6, #ec4899, #60a5fa, #8b5cf6);
            background-size: 240% 240%;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: gradientShift 7s ease infinite;
        }
        .animated-gradient-subtle {
            background: linear-gradient(90deg, #22c55e, #38bdf8, #a855f7, #ec4899);
            background-size: 260% 260%;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: gradientShift 8s ease infinite;
        }
        .hero, .panel, .metric-card {
            border: 1px solid rgba(88, 164, 125, 0.24);
            box-shadow: 0 0 0 1px rgba(64, 145, 255, 0.04), 0 18px 44px rgba(0, 0, 0, 0.28), 0 0 22px rgba(32, 201, 151, 0.06);
        }
        .hero {
            padding: 1.2rem 1.35rem;
            border-radius: 22px;
            background:
                linear-gradient(135deg, rgba(3, 22, 18, 0.97), rgba(4, 16, 26, 0.96)),
                radial-gradient(circle at top right, rgba(64, 145, 255, 0.14), transparent 38%);
            margin-bottom: 0.7rem;
        }
        .hero h1 { margin: 0 0 0.3rem 0; font-size: 2.2rem; font-weight: 800; }
        .hero p { margin: 0; color: #9ab6ae; line-height: 1.5; font-size: 1.03rem; }
        .panel {
            background:
                linear-gradient(160deg, rgba(6, 24, 21, 0.96), rgba(5, 14, 24, 0.97)),
                radial-gradient(circle at top left, rgba(32, 201, 151, 0.06), transparent 34%);
            border-radius: 18px;
            padding: 0.85rem 0.95rem;
            margin-bottom: 0.7rem;
        }
        .metric-card {
            background:
                linear-gradient(160deg, rgba(7, 28, 23, 0.98), rgba(6, 14, 24, 0.98)),
                radial-gradient(circle at top left, rgba(32, 201, 151, 0.08), transparent 40%);
            border-radius: 18px;
            padding: 0.9rem 1rem;
            min-height: 108px;
        }
        .metric-label { color: #8ea9a0; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.3rem; }
        .metric-value { font-size: 2.05rem; font-weight: 780; color: #eef7f3; line-height: 1.05; text-shadow: 0 0 10px rgba(32, 201, 151, 0.08); }
        .metric-sub { color: #8ba59f; font-size: 0.93rem; margin-top: 0.35rem; }
        .status-safe { color: #39d98a; text-shadow: 0 0 12px rgba(57, 217, 138, 0.16); }
        .status-watch { color: #f4c95d; text-shadow: 0 0 10px rgba(244, 201, 93, 0.14); }
        .status-alert { color: #ff6b6b; text-shadow: 0 0 10px rgba(255, 107, 107, 0.16); }
        .briefing {
            border-left: 4px solid #2dd4bf;
            background: linear-gradient(135deg, rgba(45, 212, 191, 0.11), rgba(64, 145, 255, 0.04));
            border-radius: 12px;
            padding: 0.8rem 0.95rem;
            margin-top: 0.65rem;
        }
        .section-title { margin-bottom: 0.55rem; font-size: 1.12rem; font-weight: 700; }
        .stCaption { color: #8fa99f !important; font-size: 0.92rem !important; }
        div[data-testid="stMetric"] { border-radius: 14px; }
        div[data-testid="stDataFrame"] {
            border: 1px solid rgba(88, 164, 125, 0.18);
            border-radius: 14px;
            overflow: hidden;
        }
        div[data-testid="stAlert"] {
            border-radius: 14px;
            border: 1px solid rgba(88, 164, 125, 0.18);
            box-shadow: 0 0 18px rgba(32, 201, 151, 0.07);
        }
        .stButton > button {
            border-radius: 12px;
            border: 1px solid rgba(58, 136, 104, 0.34);
            background: linear-gradient(180deg, rgba(7, 35, 27, 0.96), rgba(5, 17, 24, 0.98));
            color: #ecf7f1;
            font-weight: 600;
            padding: 0.45rem 0.8rem;
            box-shadow: 0 0 14px rgba(32, 201, 151, 0.08);
        }
        .stButton > button:hover {
            border-color: rgba(64, 145, 255, 0.42);
            box-shadow: 0 0 18px rgba(64, 145, 255, 0.14);
        }
        div[data-testid="stTextInput"] input, div[data-testid="stNumberInput"] input, div[data-testid="stSelectbox"] div[data-baseweb="select"] {
            border-radius: 12px;
            border: 1px solid rgba(88, 164, 125, 0.2);
            background: rgba(4, 18, 18, 0.95);
            color: #eef7f3;
            font-size: 1rem;
        }
        div[data-testid="stSidebar"] {
            background:
                linear-gradient(180deg, rgba(4, 16, 15, 0.99), rgba(5, 20, 24, 0.99)),
                radial-gradient(circle at top right, rgba(32, 201, 151, 0.08), transparent 38%);
        }
        .status-banner-text {
            font-weight: 700;
            letter-spacing: 0.02em;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def init_state():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if "events" not in st.session_state:
        st.session_state["events"] = []
    if "last_result" not in st.session_state:
        st.session_state["last_result"] = None
    if "user_role" not in st.session_state:
        st.session_state["user_role"] = "Operator"
    if "demo_seeded" not in st.session_state:
        st.session_state["demo_seeded"] = False


def apply_simulation_preset(preset_name, feature_names, reference):
    profile = reference["attack_profiles"].get(preset_name, {})
    defaults = reference["defaults"]
    for feature in feature_names:
        st.session_state[f"input_{feature}"] = float(profile.get(feature, defaults.get(feature, 0.0)))
    st.session_state["active_preset"] = preset_name


def generate_source_ip():
    return f"10.{random.randint(10, 99)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def seed_demo_events():
    if st.session_state["demo_seeded"] or st.session_state["events"]:
        return
    demo_rows = [
        ("Normal", "Secure", 91, "SAFE", "Packet Rate"),
        ("DoS", "Critical", 94, "HIGH", "Source Load"),
        ("Reconnaissance", "Watch", 73, "MEDIUM", "State/TTL Count"),
        ("Exploits", "Critical", 89, "HIGH", "Source TTL"),
        ("Normal", "Secure", 88, "SAFE", "Duration"),
        ("Fuzzers", "Watch", 69, "MEDIUM", "Destination Packets"),
        ("Backdoor", "Critical", 62, "CRITICAL", "Service to Destination Count"),
        ("Analysis", "Watch", 58, "LOW", "Packet Rate"),
    ]
    for idx, (label, status, confidence, severity, signal) in enumerate(demo_rows, start=1):
        st.session_state["events"].append(
            {
                "timestamp": f"2026-03-31 09:{idx:02d}:00",
                "status": status,
                "risk_score": float(confidence),
                "predicted_label": label,
                "severity": severity,
                "top_signal": signal,
                "source_ip": generate_source_ip(),
                "feed_type": "Simulated",
            }
        )
    st.session_state["demo_seeded"] = True


@st.cache_resource
# def load_assets():
#     model = joblib.load(MODEL_FILE)
#     feature_names = joblib.load(FEATURE_FILE)
#     model_classes = list(getattr(model, "classes_", []))
#     return model, feature_names, model_classes
def load_assets():
    model = joblib.load(MODEL_FILE)
    feature_names = joblib.load(FEATURE_FILE)
    label_encoder = joblib.load(MODEL_ENCODER)
    return model, feature_names, label_encoder


@st.cache_data(show_spinner=False)
def load_reference_data():
    usecols = list(dict.fromkeys(DATA_COLUMNS + PRIMARY_INPUTS + PROFILE_FEATURES + PLOT_FEATURES + ["sinpkt", "dinpkt", "sjit", "djit", "ct_srv_src", "ct_dst_ltm", "ct_src_ltm"]))
    df = pd.read_csv(TRAINING_DATA, usecols=usecols)
    numeric = [col for col in df.columns if col not in DATA_COLUMNS]
    normal_df = df[df["label"] == 0]
    attack_df = df[df["label"] == 1]

    normal_iqr_series = normal_df[numeric].quantile(0.75) - normal_df[numeric].quantile(0.25)
    normal_iqr = {k: (v if pd.notna(v) and v > 0 else 1.0) for k, v in normal_iqr_series.to_dict().items()}

    class_dist = df["attack_cat"].value_counts().reset_index()
    class_dist.columns = ["attack_cat", "count"]
    binary_dist = df["label"].map({0: "Normal", 1: "Attack"}).value_counts().reset_index()
    binary_dist.columns = ["status", "count"]

    return {
        "defaults": normal_df[numeric].median().to_dict(),
        "normal_medians": normal_df[numeric].median().to_dict(),
        "attack_medians": attack_df[numeric].median().to_dict(),
        "normal_iqr": normal_iqr,
        "attack_profiles": df.groupby("attack_cat")[PROFILE_FEATURES].median().to_dict("index"),
        "class_distribution": class_dist,
        "binary_distribution": binary_dist,
        "row_count": int(len(df)),
        "attack_ratio": float(df["label"].mean()),
        "top_attack": str(class_dist.iloc[0]["attack_cat"]),
    }


@st.cache_data(show_spinner=False)
def get_model_benchmarks():
    df = pd.read_csv(TRAINING_DATA)
    x_data = df.drop(["id", "proto", "service", "state", "attack_cat", "label"], axis=1)
    y_data = df["attack_cat"]
    x_train, x_test, y_train, y_test = train_test_split(
        x_data, y_data, test_size=0.2, random_state=32, stratify=y_data
    )
    models = {
        "KNN": KNeighborsClassifier(),
        "Decision Tree": DecisionTreeClassifier(max_depth=20, random_state=32),
        "Random Forest": RandomForestClassifier(n_estimators=120, random_state=32, n_jobs=1),
    }

    rows = []
    for name, estimator in models.items():
        estimator.fit(x_train, y_train)
        preds = estimator.predict(x_test)
        rows.append(
            {
                "Model": name,
                "Accuracy": accuracy_score(y_test, preds),
                "Precision": precision_score(y_test, preds, average="weighted", zero_division=0),
                "Recall": recall_score(y_test, preds, average="weighted", zero_division=0),
                "F1": f1_score(y_test, preds, average="weighted", zero_division=0),
            }
        )
    return pd.DataFrame(rows)


def format_number(value):
    value = float(value)
    if value == 0:
        return "0"
    if abs(value) >= 1_000_000:
        return f"{value / 1_000_000:.2f}M"
    if abs(value) >= 1_000:
        return f"{value / 1_000:.1f}K"
    if abs(value) >= 100:
        return f"{value:.0f}"
    if abs(value) >= 10:
        return f"{value:.1f}"
    return f"{value:.3f}".rstrip("0").rstrip(".")


def render_metric_card(label, value, subtitle="", status_class=""):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value {status_class}">{value}</div>
            <div class="metric-sub">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def determine_status(risk_score, predicted_label):
    if predicted_label == "Normal" and risk_score < 40:
        return "Secure"
    if predicted_label == "Normal":
        return "Watch"
    if risk_score >= 70:
        return "Critical"
    if THREAT_KNOWLEDGE_BASE.get(predicted_label, {}).get("severity") == "CRITICAL":
        return "Critical"
    if risk_score >= 45:
        return "Watch"
    return "Watch"


def profile_signal_direction(value, baseline):
    if value > baseline:
        return "above"
    if value < baseline:
        return "below"
    return "at"


def compute_top_signals(input_row, reference, count=5):
    rows = []
    for feature in PLOT_FEATURES:
        baseline = float(reference["normal_medians"].get(feature, 0.0))
        scale = float(reference["normal_iqr"].get(feature, 1.0))
        value = float(input_row.get(feature, 0.0))
        delta = (value - baseline) / scale
        rows.append(
            {
                "feature": feature,
                "label": FEATURE_LABELS.get(feature, feature),
                "value": value,
                "baseline": baseline,
                "severity": abs(delta),
                "delta": delta,
                "direction": profile_signal_direction(value, baseline),
            }
        )
    top = sorted(rows, key=lambda item: item["severity"], reverse=True)[:count]
    return top, rows


def build_input_controls(feature_names, reference):
    defaults = reference["defaults"]
    values = {}

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Live Telemetry Intake</div>', unsafe_allow_html=True)
    st.caption(
        "Primary controls are exposed below. Remaining model features are backfilled with normal-operating medians from the UNSW reference set."
    )
    col_a, col_b, col_c = st.columns(3)
    columns = [col_a, col_b, col_c]

    for index, feature in enumerate([f for f in PRIMARY_INPUTS if f in feature_names]):
        default_value = float(defaults.get(feature, 0.0))
        state_key = f"input_{feature}"
        if state_key not in st.session_state:
            st.session_state[state_key] = default_value
        with columns[index % 3]:
            values[feature] = st.number_input(
                FEATURE_LABELS.get(feature, feature),
                value=float(st.session_state[state_key]),
                step=max(abs(default_value) * 0.05, 0.01),
                format="%.6f",
                key=state_key,
            )

    advanced = [f for f in ["sinpkt", "dinpkt", "sjit", "djit", "smean", "dmean", "ct_srv_src", "ct_dst_ltm", "ct_src_ltm"] if f in feature_names]
    if advanced:
        with st.expander("Advanced Timing And Session Controls"):
            adv_cols = st.columns(3)
            for index, feature in enumerate(advanced):
                default_value = float(defaults.get(feature, 0.0))
                state_key = f"input_{feature}"
                if state_key not in st.session_state:
                    st.session_state[state_key] = default_value
                with adv_cols[index % 3]:
                    values[feature] = st.number_input(
                        FEATURE_LABELS.get(feature, feature),
                        value=float(st.session_state[state_key]),
                        step=max(abs(default_value) * 0.05, 0.01),
                        format="%.6f",
                        key=state_key,
                    )
    st.markdown("</div>", unsafe_allow_html=True)

    full_row = {feature: float(defaults.get(feature, 0.0)) for feature in feature_names}
    full_row.update(values)
    return full_row


def render_login():
    _, center, _ = st.columns([1, 1.25, 1])
    with center:
        st.markdown(
            """
            <div class="hero" style="margin-top: 3.5rem;">
                <h1 class="animated-gradient-text">Military IDS Command Center</h1>
                <p>Secure access is required before opening the threat-detection console. The UI combines the production classifier, the UNSW reference dataset, and comparative notebook insights into one operational dashboard.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        with st.form("login_form"):
            st.markdown('<div class="panel">', unsafe_allow_html=True)
            role = st.selectbox("Access Role", list(AUTH_CONFIG.keys()))
            operator = st.text_input("Operator ID")
            token = st.text_input("Access Token", type="password")
            submit = st.form_submit_button("Authenticate")
            st.caption("Demo credentials: admin / wsn_secure_2024, analyst / wsn_analyst_2024, operator / wsn_operator_2024")
            st.markdown("</div>", unsafe_allow_html=True)
        if submit:
            with st.spinner("Validating secure access..."):
                time.sleep(0.8)
            selected_config = AUTH_CONFIG[role]
            normalized_operator = operator.strip().lower()
            normalized_token = token.strip()
            if normalized_operator == selected_config["user"] and normalized_token == selected_config["token"]:
                st.session_state["authenticated"] = True
                st.session_state["user_role"] = role
                st.success(f"Access Granted. {role} privileges enabled.")
                st.rerun()
            else:
                st.error("Unauthorized Access Attempt. Verify role, operator ID, and token.")


def render_sidebar(reference):
    st.sidebar.markdown("## System Monitor")
    events = st.session_state["events"]
    scans = len(events)
    alerts = sum(1 for event in events if event["status"] != "Secure")
    avg_risk = sum(event["risk_score"] for event in events) / scans if scans else 0.0
    latest = events[-1] if events else None

    st.sidebar.caption(f"Role: {st.session_state.get('user_role', 'Operator')}")
    st.sidebar.metric("Recorded Scans", scans)
    st.sidebar.metric("Active Alerts", alerts)
    st.sidebar.metric("Average Risk", f"{avg_risk:.0f}%")
    st.sidebar.metric("Dataset Attack Ratio", f"{reference['attack_ratio'] * 100:.1f}%")

    if latest:
        st.sidebar.markdown(
            f"""
            <div class="briefing">
                <strong>Latest Assessment</strong><br/>
                {latest['status']}<br/>
                {latest['risk_score']:.0f}% risk<br/>
                Category: {latest['predicted_label']}
            </div>
            """,
            unsafe_allow_html=True,
        )

    if st.sidebar.button("Reset Session Logs"):
        st.session_state["events"] = []
        st.session_state["last_result"] = None
        st.rerun()

    return st.sidebar.radio("Navigation", ["Real-time Detection", "Comparative Analytics"])


def render_result_panels(result, signal_rows, input_row):
    status_class = {
        "Secure": "status-safe",
        "Watch": "status-watch",
        "Critical": "status-alert",
    }.get(result["status"], "")

    if result["predicted_label"] == "Normal":
        st.success(f"Live Assessment: Normal traffic detected with {result['risk_score']:.0f}% confidence.")
        st.markdown(
            '<div class="status-banner-text animated-gradient-subtle">Operational state stable. Traffic signature remains within expected mission parameters.</div>',
            unsafe_allow_html=True,
        )
    else:
        st.error(
            f"Live Alert: {result['predicted_label']} detected at {result['risk_score']:.0f}% confidence. Severity: {result['severity']}."
        )
        st.markdown(
            f'<div class="status-banner-text animated-gradient-text">Threat escalation active: {result["predicted_label"]} pattern confirmed by live analysis.</div>',
            unsafe_allow_html=True,
        )

    top_cols = st.columns(4)
    with top_cols[0]:
        render_metric_card("Threat Status", result["status"], "Operational classification", status_class)
    with top_cols[1]:
        render_metric_card("Confidence", f"{result['risk_score']:.0f}%", "Top multiclass probability", status_class)
    with top_cols[2]:
        render_metric_card("Predicted Category", result["predicted_label"], "Direct model output")
    with top_cols[3]:
        render_metric_card("Runner-Up", result["runner_up"], "Second most likely family")

    detail_cols = st.columns([1.2, 1, 1])
    with detail_cols[0]:
        knowledge = result["knowledge"]
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Tactical Briefing")
        st.markdown(
            f"""
            <div class="briefing">
                <strong>Severity:</strong> {knowledge['severity']}<br/>
                <strong>Summary:</strong> {knowledge['summary']}<br/>
                <strong>Operational Impact:</strong> {knowledge['impact']}<br/>
                <strong>Recommended Action:</strong> {knowledge['action']}
            </div>
            """,
            unsafe_allow_html=True,
        )
        low_confidence_note = LOW_CONFIDENCE_ALERTS.get(result["predicted_label"])
        if low_confidence_note:
            st.warning(low_confidence_note)
        st.markdown("</div>", unsafe_allow_html=True)

    with detail_cols[1]:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Why Detected?")
        for signal in signal_rows[:4]:
            st.metric(
                signal["label"],
                format_number(signal["value"]),
                delta=f"{signal['direction']} baseline by {signal['severity']:.1f} sigma",
            )
        st.markdown("</div>", unsafe_allow_html=True)

    with detail_cols[2]:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Telemetry Snapshot")
        rows = []
        for feature in ["rate", "sload", "dload", "sttl", "spkts", "dpkts"]:
            rows.append({"Metric": FEATURE_LABELS.get(feature, feature), "Value": format_number(input_row.get(feature, 0.0))})
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown("### Explainability Summary")
    for signal in signal_rows[:3]:
        st.write(f"- {signal['label']} moved {signal['direction']} baseline by {signal['severity']:.1f} sigma")
    st.markdown("</div>", unsafe_allow_html=True)

    chart_cols = st.columns(2)
    with chart_cols[0]:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Anomaly Signature")
        chart_df = pd.DataFrame(signal_rows).sort_values("delta")
        fig, ax = plt.subplots(figsize=(7, 4.2))
        colors = ["#ff6b6b" if value > 0 else "#7dd3fc" for value in chart_df["delta"]]
        ax.barh(chart_df["label"], chart_df["delta"], color=colors)
        ax.axvline(0, color="#9fb3bd", linewidth=1)
        ax.set_xlabel("Deviation From Normal Baseline (sigma units)")
        ax.set_ylabel("")
        ax.set_facecolor("#0b1721")
        fig.patch.set_facecolor("#0b1721")
        ax.tick_params(colors="#dce6eb")
        ax.xaxis.label.set_color("#dce6eb")
        sns.despine(ax=ax, left=False, bottom=False)
        st.pyplot(fig, clear_figure=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with chart_cols[1]:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Current Vs Baseline")
        compare_rows = []
        for feature in ["rate", "sload", "dload", "sttl", "ct_state_ttl", "ct_srv_dst"]:
            compare_rows.append(
                {
                    "Metric": FEATURE_LABELS.get(feature, feature),
                    "Current": format_number(input_row.get(feature, 0.0)),
                    "Normal Baseline": format_number(result["reference"]["normal_medians"].get(feature, 0.0)),
                    "Predicted Family Baseline": format_number(
                        result["reference"]["attack_profiles"].get(result["predicted_label"], {}).get(feature, result["reference"]["attack_medians"].get(feature, 0.0))
                    ),
                }
            )
        st.dataframe(pd.DataFrame(compare_rows), hide_index=True, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)


def render_history(events):
    if not events:
        st.info("No session detections yet. Submit telemetry to populate the history timeline.")
        return

    history_df = pd.DataFrame(events)
    chart_cols = st.columns(2)
    with chart_cols[0]:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Risk Timeline")
        timeline = history_df[["timestamp", "risk_score"]].copy()
        timeline["timestamp"] = pd.to_datetime(timeline["timestamp"])
        st.line_chart(timeline.set_index("timestamp"))
        st.markdown("</div>", unsafe_allow_html=True)

    with chart_cols[1]:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Session Threat Mix")
        mix = history_df["predicted_label"].value_counts().reset_index()
        mix.columns = ["Profile", "Count"]
        fig, ax = plt.subplots(figsize=(6.3, 4.2))
        ax.pie(
            mix["Count"],
            labels=mix["Profile"],
            autopct="%1.0f%%",
            startangle=90,
            colors=sns.color_palette("crest", len(mix)),
            textprops={"color": "#dce6eb"},
        )
        fig.patch.set_facecolor("#0b1721")
        ax.set_facecolor("#0b1721")
        st.pyplot(fig, clear_figure=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown("### Detection Log")
    display_df = history_df[DISPLAY_COLUMNS].rename(
        columns={
            "timestamp": "Timestamp",
            "status": "Status",
            "risk_score": "Risk Score",
            "predicted_label": "Predicted Category",
            "severity": "Severity",
            "top_signal": "Top Signal",
        }
    )
    if "source_ip" in history_df.columns:
        display_df.insert(1, "Source IP", history_df["source_ip"])
    if "feed_type" in history_df.columns:
        display_df["Feed"] = history_df["feed_type"]
    display_df["Risk Score"] = display_df["Risk Score"].map(lambda value: f"{value:.0f}%")
    st.dataframe(display_df, hide_index=True, use_container_width=True)
    csv_bytes = display_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Export Detection Report (CSV)",
        data=csv_bytes,
        file_name="ids_detection_report.csv",
        mime="text/csv",
    )
    st.markdown("</div>", unsafe_allow_html=True)


def render_detection_page(model, feature_names, reference, label_encoder):
    st.markdown(
        """
        <div class="hero">
            <h1 class="animated-gradient-text">Threat Detection Command Center</h1>
            <p>This dashboard now uses the exported production classifier for direct multiclass threat-family detection. The reference dataset still powers the anomaly explanation and baseline comparisons, but the detected category shown here comes from the model itself.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    ops_cols = st.columns(4)
    with ops_cols[0]:
        render_metric_card("Firewall", "Active", "Perimeter filtering engaged", "status-safe")
    with ops_cols[1]:
        render_metric_card("IDS Engine", "Running", "Multiclass detection online", "status-safe")
    with ops_cols[2]:
        render_metric_card("Connected Nodes", "24", "Simulated secure mesh links")
    with ops_cols[3]:
        #render_metric_card("Model", type(model.named_steps["classifier"]).__name__, "Dataset: UNSW-NB15")
        render_metric_card("Model", type(model).__name__, "Dataset: UNSW-NB15")

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown('<h3 class="animated-gradient-subtle">Simulation Presets</h3>', unsafe_allow_html=True)
    st.caption("Use one click to auto-fill the telemetry form with median feature values from the selected attack family.")
    preset_cols = st.columns(5)
    available_presets = [name for name in SIMULATION_ORDER if name in reference["attack_profiles"]]
    for index, preset_name in enumerate(available_presets):
        with preset_cols[index % 5]:
            if st.button(f"Simulate {preset_name}", key=f"preset_{preset_name}"):
                apply_simulation_preset(preset_name, feature_names, reference)
                st.rerun()
    active_preset = st.session_state.get("active_preset")
    if active_preset:
        st.info(f"Active preset: {active_preset}")
    st.markdown("</div>", unsafe_allow_html=True)

    with st.form("detection_form"):
        input_row = build_input_controls(feature_names, reference)
        submitted = st.form_submit_button("Analyze Traffic Signature")

    if submitted:
        with st.spinner("Analyzing traffic..."):
            time.sleep(1.2)
        input_df = pd.DataFrame([input_row])[feature_names]
        #predicted_label = str(model.predict(input_df)[0])
        pred = model.predict(input_df)[0]
        predicted_label = label_encoder.inverse_transform([pred])[0]
        probability = model.predict_proba(input_df)[0] if hasattr(model, "predict_proba") else []
        #class_labels = list(getattr(model, "classes_", []))
        class_labels = label_encoder.classes_
        score_map = {
            str(label): float(score)
            for label, score in zip(class_labels, probability)
        }
        ranked = sorted(score_map.items(), key=lambda item: item[1], reverse=True)
        risk_score = ranked[0][1] * 100 if ranked else (100.0 if predicted_label != "Normal" else 0.0)
        runner_up = ranked[1][0] if len(ranked) > 1 else "None"
        knowledge = THREAT_KNOWLEDGE_BASE.get(predicted_label, THREAT_KNOWLEDGE_BASE["Normal"])

        signal_rows, _ = compute_top_signals(input_row, reference)
        status = determine_status(risk_score, predicted_label)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        result = {
            "timestamp": timestamp,
            "status": status,
            "risk_score": risk_score,
            "predicted_label": predicted_label,
            "runner_up": runner_up,
            "severity": knowledge["severity"],
            "knowledge": knowledge,
            "top_signal": signal_rows[0]["label"],
            "reference": reference,
        }

        st.session_state["last_result"] = {"result": result, "signals": signal_rows, "input_row": input_row}
        st.session_state["events"].append(
            {
                "timestamp": timestamp,
                "status": status,
                "risk_score": risk_score,
                "predicted_label": predicted_label,
                "severity": knowledge["severity"],
                "top_signal": signal_rows[0]["label"],
                "source_ip": generate_source_ip(),
                "feed_type": "Live",
            }
        )

    if st.session_state["last_result"]:
        payload = st.session_state["last_result"]
        render_result_panels(payload["result"], payload["signals"], payload["input_row"])

    recent_alerts = [event for event in st.session_state["events"] if event["predicted_label"] != "Normal"][-5:]
    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown('<h3 class="animated-gradient-subtle">Live Alert Feed</h3>', unsafe_allow_html=True)
    if recent_alerts:
        alert_rows = []
        for event in reversed(recent_alerts):
            alert_rows.append(
                {
                    "Timestamp": event["timestamp"],
                    "Source IP": event.get("source_ip", "N/A"),
                    "Threat": event["predicted_label"],
                    "Severity": event["severity"],
                    "Confidence": f"{event['risk_score']:.0f}%",
                    "Feed": event.get("feed_type", "Live"),
                }
            )
        st.dataframe(pd.DataFrame(alert_rows), hide_index=True, use_container_width=True)
    else:
        st.info("No attack events have been detected in this session yet.")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("## Session Intelligence")
    render_history(st.session_state["events"])


def render_analytics_page(reference):
    st.markdown(
        """
        <div class="hero">
            <h1 class="animated-gradient-text">Comparative Analytics</h1>
            <p>The notebooks and datasets are consolidated here to show class composition, family signatures, and multiclass model robustness. This keeps the analytics screen useful for operators instead of looking like a generic model demo.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    top_cols = st.columns(4)
    with top_cols[0]:
        render_metric_card("Reference Rows", f"{reference['row_count']:,}", "UNSW training records")
    with top_cols[1]:
        render_metric_card("Attack Prevalence", f"{reference['attack_ratio'] * 100:.1f}%", "Attack vs normal split")
    with top_cols[2]:
        render_metric_card("Top Attack Family", reference["top_attack"], "Most common attack category")
    with top_cols[3]:
        render_metric_card("Reference Features", "39", "Exported to the production model")

    dist_cols = st.columns(2)
    with dist_cols[0]:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Attack Category Distribution")
        dist_df = reference["class_distribution"]
        fig, ax = plt.subplots(figsize=(7.2, 4.8))
        sns.barplot(data=dist_df, x="count", y="attack_cat", palette="mako", ax=ax)
        ax.set_xlabel("Rows")
        ax.set_ylabel("")
        ax.set_facecolor("#0b1721")
        fig.patch.set_facecolor("#0b1721")
        ax.tick_params(colors="#dce6eb")
        ax.xaxis.label.set_color("#dce6eb")
        sns.despine(ax=ax)
        st.pyplot(fig, clear_figure=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with dist_cols[1]:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Normal Vs Attack Split")
        binary_df = reference["binary_distribution"]
        fig, ax = plt.subplots(figsize=(6.7, 4.8))
        ax.pie(
            binary_df["count"],
            labels=binary_df["status"],
            autopct="%1.1f%%",
            startangle=90,
            colors=["#39d98a", "#ff6b6b"],
            textprops={"color": "#dce6eb"},
        )
        fig.patch.set_facecolor("#0b1721")
        ax.set_facecolor("#0b1721")
        st.pyplot(fig, clear_figure=True)
        st.markdown("</div>", unsafe_allow_html=True)

    compare_cols = st.columns(2)
    with compare_cols[0]:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Baseline Median Shift")
        rows = []
        for feature in ["rate", "sload", "dload", "sttl", "spkts", "ct_state_ttl", "ct_srv_dst", "ct_dst_src_ltm"]:
            rows.append(
                {
                    "Metric": FEATURE_LABELS.get(feature, feature),
                    "Normal": format_number(reference["normal_medians"].get(feature, 0.0)),
                    "Attack": format_number(reference["attack_medians"].get(feature, 0.0)),
                }
            )
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with compare_cols[1]:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown("### Attack Family Signatures")
        rows = []
        for family in ["Generic", "DoS", "Exploits", "Fuzzers", "Reconnaissance"]:
            profile = reference["attack_profiles"].get(family)
            if profile:
                rows.append(
                    {
                        "Family": family,
                        "Rate": format_number(profile["rate"]),
                        "Source Load": format_number(profile["sload"]),
                        "Destination Load": format_number(profile["dload"]),
                        "Source TTL": format_number(profile["sttl"]),
                        "Packets": format_number(profile["spkts"]),
                    }
                )
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    st.markdown("### Baseline Model Benchmarks")
    benchmark_df = get_model_benchmarks()
    st.dataframe(
        benchmark_df.style.format({"Accuracy": "{:.3f}", "Precision": "{:.3f}", "Recall": "{:.3f}", "F1": "{:.3f}"}),
        hide_index=True,
        use_container_width=True,
    )
    fig, ax = plt.subplots(figsize=(9.5, 4.2))
    melted = benchmark_df.melt(id_vars="Model", var_name="Metric", value_name="Score")
    sns.barplot(data=melted, x="Metric", y="Score", hue="Model", palette="rocket", ax=ax)
    ax.set_ylim(0.80, 1.0)
    ax.set_facecolor("#0b1721")
    fig.patch.set_facecolor("#0b1721")
    ax.tick_params(colors="#dce6eb")
    ax.xaxis.label.set_color("#dce6eb")
    ax.yaxis.label.set_color("#dce6eb")
    legend = ax.legend(facecolor="#0b1721", edgecolor="#1f3d4d")
    for text in legend.get_texts():
        text.set_color("#dce6eb")
    sns.despine(ax=ax)
    st.pyplot(fig, clear_figure=True)
    st.markdown("</div>", unsafe_allow_html=True)

    st.info("The production model exported in the notebook is now multiclass on `attack_cat`. The baseline tables still use dataset medians so operators can compare live traffic against both normal behavior and category-specific signatures.")


def main():
    inject_styles()
    init_state()
    if not st.session_state["authenticated"]:
        render_login()
        return

    try:
        #model, feature_names, _ = load_assets()
        model, feature_names, label_encoder = load_assets()
        reference = load_reference_data()
    except Exception as exc:
        st.error(f"Required model or dataset assets could not be loaded: {exc}")
        return

    seed_demo_events()
    page = render_sidebar(reference)
    if page == "Real-time Detection":
        render_detection_page(model, feature_names, reference, label_encoder)
    else:
        render_analytics_page(reference)


if __name__ == "__main__":
    main()
