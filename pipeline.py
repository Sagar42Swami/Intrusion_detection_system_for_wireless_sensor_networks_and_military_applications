# ============================================
# INTRUSION DETECTION SYSTEM - PIPELINE
# ============================================

import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier

# --------------------------------------------
# Phase 1: Environment Setup
# --------------------------------------------
os.makedirs("models", exist_ok=True)

# --------------------------------------------
# Phase 1.2: Data Acquisition
# --------------------------------------------
print("📥 Loading dataset...")

df_train = pd.read_csv("data/UNSW_NB15_training-set.csv")
df_test = pd.read_csv("data/UNSW_NB15_testing-set.csv")

df = pd.concat([df_train, df_test]).drop_duplicates()

print(f"✅ Dataset Loaded: {df.shape}")

# --------------------------------------------
# Phase 2: Feature Selection (ONLY 5 FEATURES)
# --------------------------------------------
selected_features = ["dur", "proto", "sbytes", "dbytes", "rate"]

# Keep only required columns
df = df[selected_features + ["label"]]

print("✅ Selected Features:", selected_features)

# --------------------------------------------
# Phase 2.1: Data Cleaning
# --------------------------------------------
df.drop_duplicates(inplace=True)
df.fillna(0, inplace=True)

# --------------------------------------------
# Phase 2.2: Label Encoding (ONLY proto)
# --------------------------------------------
encoders = {}

if "proto" in df.columns:
    le = LabelEncoder()
    df["proto"] = le.fit_transform(df["proto"].astype(str))
    encoders["proto"] = le

print("✅ Encoding Completed")

# --------------------------------------------
# Phase 2.4: Train-Test Split (80/20)
# --------------------------------------------
X = df.drop("label", axis=1)
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("✅ Data Split Completed")

# --------------------------------------------
# Phase 3: Model Training (Pipeline)
# --------------------------------------------
print("⚙️ Training Model...")

ids_pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("classifier", RandomForestClassifier(n_estimators=100, random_state=42))
])

ids_pipeline.fit(X_train, y_train)

print("✅ Model Training Complete")

# --------------------------------------------
# Phase 4: (Optional Quick Evaluation)
# --------------------------------------------
accuracy = ids_pipeline.score(X_test, y_test)
print(f"📊 Model Accuracy: {accuracy:.4f}")

# --------------------------------------------
# Phase 5.1: Save Artifacts
# --------------------------------------------
print("💾 Saving artifacts...")

joblib.dump(ids_pipeline, "models/military_ids_model.pkl")
joblib.dump(encoders, "models/encoders.pkl")
joblib.dump(selected_features, "models/features.pkl")

print("✅ Production Pipeline Complete. Artifacts Exported.")