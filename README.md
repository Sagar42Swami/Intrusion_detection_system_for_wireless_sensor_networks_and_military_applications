# Military IDS Command Center

An easy-to-use Intrusion Detection System (IDS) project for analyzing network traffic and identifying possible cyberattacks using machine learning.

This project combines:

- a Streamlit web dashboard for real-time threat analysis
- pretrained machine learning models for attack classification
- UNSW-NB15 / Bot-IoT dataset artifacts for reference and benchmarking
- analytics views to compare normal and malicious traffic behavior

The app is designed to feel like an operational monitoring console instead of a simple ML demo.

## What This Project Does

The system takes network traffic features as input and predicts whether the traffic is normal or belongs to an attack category such as:

- `DoS`
- `Exploits`
- `Fuzzers`
- `Reconnaissance`
- `Backdoor`
- `Shellcode`
- `Worms`
- `Analysis`
- `Generic`
- `Normal`

In the dashboard, the model output is combined with:

- confidence scores
- severity labels
- recommended response actions
- baseline comparisons against reference data
- a session history of detections

This makes the project useful for demonstration, academic presentation, and prototype security monitoring workflows.

## Main Features

- Secure login screen with role-based demo access
- Real-time detection form for live telemetry input
- One-click simulation presets for known attack families
- Threat explanation panels showing why a traffic sample was flagged
- Comparative analytics dashboard with dataset summaries and model benchmarks
- Detection history with export to CSV
- Cached reference data for faster repeated runs
- CLI utility for running saved model predictions outside the Streamlit UI

## How The System Works

### 1. Input

The app accepts core network telemetry features such as:

- duration
- packet rate
- source and destination TTL
- source and destination load
- packet counts
- byte counts
- session/state features

Only the main features are exposed in the dashboard by default. Remaining required model features are automatically filled using median values from the reference dataset.

### 2. Prediction

The application loads a pretrained model bundle from the `models/` folder and predicts the most likely traffic category.

The app currently tries model bundles in order and uses the first one that loads successfully:

- `xgboost_multiclass`
- `sklearn_pipeline`

### 3. Interpretation

After prediction, the app:

- calculates a confidence-based risk score
- maps the predicted class to a severity level
- shows likely signals that caused the detection
- compares the input against normal and attack-family baselines
- stores the result in the current session log

### 4. Analytics

The analytics page uses dataset statistics and benchmark comparisons to help explain how the model behaves across attack classes.

## Project Structure

```text
updated/
├─ app.py                              # Main Streamlit IDS dashboard
├─ requirement.txt                     # Python dependencies
├─ UNSW_NB15_training-set.csv          # Reference training dataset
├─ UNSW_NB15_testing-set.csv           # Reference testing dataset
├─ Bot-IoT.csv                         # Additional dataset artifact
├─ military_ids_model.pkl              # Large saved model artifact
├─ feature_names.pkl                   # Feature list for saved model
├─ models/
│  ├─ military_ids_model.pkl           # Saved sklearn pipeline bundle
│  ├─ military_ids_model2.pkl          # Saved multiclass XGBoost bundle
│  ├─ feature_names*.pkl               # Feature name artifacts
│  ├─ label_encoder*.pkl               # Label encoders for multiclass models
│  ├─ load_and_predict.py              # CLI prediction helper
│  ├─ reference_data.joblib            # Cached dataset summaries
│  └─ benchmark_data.joblib            # Cached benchmark results
├─ Military_IDS_Production.ipynb       # Notebook work for model development
├─ Military_IDS_Analysis.ipynb         # Notebook-based analysis
└─ figures.ipynb                       # Visualization notebook
```

## Requirements

Install Python 3.10+ if possible. Then install the dependencies listed in `requirement.txt`.

Main libraries used:

- `streamlit`
- `pandas`
- `numpy`
- `matplotlib`
- `seaborn`
- `scikit-learn`
- `joblib`
- `xgboost`

## Installation

### 1. Clone or open the project folder

If you already have the folder locally, move into it:

```powershell
cd F:\project\updated
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```powershell
pip install -r requirement.txt
```

## Run The Streamlit App

Start the dashboard with:

```powershell
streamlit run app.py
```

After that, Streamlit will open a local browser tab, usually at:

```text
http://localhost:8501
```

## Demo Login Credentials

The app includes built-in demo credentials:

| Role | Operator ID | Access Token |
|---|---|---|
| Admin | `admin` | `wsn_secure_2024` |
| Analyst | `analyst` | `wsn_analyst_2024` |
| Operator | `operator` | `wsn_operator_2024` |

These are hardcoded for demonstration purposes and should not be used in a real deployment.

## Using The Dashboard

### Real-time Detection

On the main page, you can:

- enter network feature values manually
- use simulation buttons to auto-fill attack patterns
- run a detection using `Analyze Traffic Signature`
- review confidence, severity, top signals, and recommended actions

### Comparative Analytics

The analytics page shows:

- attack category distribution
- normal vs attack split
- median feature differences
- attack family signature comparisons
- benchmark scores for baseline ML models

### Detection History

Every detection in the session is saved and displayed as:

- a timeline
- a threat mix chart
- a tabular detection log

You can export this log as a CSV report from the dashboard.

## Run A Prediction From The Command Line

The project also includes a small CLI helper:

```powershell
python models\load_and_predict.py --help
```

Important:

- you must provide all required features for the chosen bundle
- feature names must exactly match the saved model feature list
- the tool prints the predicted label and class probabilities when available

Example workflow:

1. Run `python models\load_and_predict.py --help`
2. Check the required feature names from the saved feature artifact
3. Pass every feature as `--feature name=value`

Available bundles in the CLI utility:

- `model1`
- `model2`
- `model5`

## Datasets Used

This project includes artifacts related to:

- `UNSW_NB15_training-set.csv`
- `UNSW_NB15_testing-set.csv`
- `Bot-IoT.csv`

The Streamlit dashboard mainly uses the UNSW-NB15 training data to build reference baselines such as:

- normal medians
- attack medians
- class distribution
- attack family profiles

## Model Notes

- The dashboard loads saved models from `models/`.
- The production UI is focused on multiclass attack-family detection.
- The app computes benchmark comparisons between KNN, Decision Tree, Random Forest, and XGBoost.
- Reference summaries are cached in `models/reference_data.joblib`.
- Benchmark outputs are cached in `models/benchmark_data.joblib`.

## Limitations

- This is a prototype / academic-style IDS dashboard, not a hardened enterprise security platform.
- Login credentials are hardcoded for demo use.
- Predictions depend entirely on offline trained artifacts already stored in the project.
- The dashboard accepts feature values manually rather than ingesting live packet captures directly.
- Large model and dataset files make the project storage-heavy.

## Suggested Future Improvements

- Replace hardcoded authentication with secure user management
- Add live packet capture or log ingestion
- Add REST API endpoints for programmatic prediction
- Add model retraining scripts and reproducible training pipelines
- Add Docker support
- Add unit tests and model validation tests
- Add feature descriptions for non-technical users

## Who This Project Is For

This project is especially useful for:

- students building a cybersecurity or machine learning final-year project
- researchers preparing an IDS demonstration
- instructors showing how ML can be applied to network threat detection
- teams building a prototype SOC-style monitoring dashboard

## Quick Start

If you want the shortest path:

```powershell
cd F:\project\updated
python -m venv .venv
.venv\Scripts\activate
pip install -r requirement.txt
streamlit run app.py
```

Then log in with:

- username: `admin`
- token: `wsn_secure_2024`

## Summary

This Military IDS project is a machine learning-based intrusion detection dashboard that classifies network traffic into multiple attack categories, explains the result with baseline comparisons, and presents everything in a clean Streamlit command-center interface.

It is a strong project for demo, academic, and prototype use because it combines model inference, analytics, explainability, and reporting in one place.
