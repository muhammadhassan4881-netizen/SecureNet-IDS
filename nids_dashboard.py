# Install required packages if not installed
# pip install streamlit scikit-learn pandas joblib
import os

import joblib
import numpy as np
import pandas as pd
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

MODEL_PATH = "model.pkl"
SCALER_PATH = "scaler.pkl"
FEATURE_NAMES = [
    'logged_in', 'count', 'serror_rate', 'srv_serror_rate', 'same_srv_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'service_http', 'flag_S0', 'flag_SF'
]
CLASS_LABELS = {0: 'Normal', 1: 'Attack'}
PROBABILITY_LABELS = ['Normal', 'Attack']


def train_and_save_model():
    """Train a 13-feature model and save model/scaler files."""
    np.random.seed(42)
    n_samples = 7000
    X = np.zeros((n_samples, len(FEATURE_NAMES)))

    X[:, 0] = np.random.choice([0, 1], size=n_samples, p=[0.35, 0.65])
    X[:, 1] = np.random.randint(0, 501, size=n_samples)
    X[:, 2:5] = np.random.rand(n_samples, 3)
    X[:, 5] = np.random.randint(0, 256, size=n_samples)
    X[:, 6] = np.random.randint(0, 256, size=n_samples)
    X[:, 7:10] = np.random.rand(n_samples, 3)
    X[:, 10:] = np.random.choice([0, 1], size=(n_samples, 3), p=[0.5, 0.5])

    attack_score = (
        (X[:, 0] == 0).astype(int)
        + (X[:, 1] > 120).astype(int)
        + (X[:, 2] > 0.65).astype(int)
        + (X[:, 3] > 0.55).astype(int)
        + (X[:, 7] > 0.65).astype(int)
        + (X[:, 10] == 1).astype(int)
        + (X[:, 11] == 0).astype(int)
    )
    y = (attack_score >= 3).astype(int)
    if y.mean() < 0.2:
        extra_attacks = np.random.rand(n_samples) < 0.15
        y = np.where(extra_attacks, 1, y)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_scaled, y)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    return model, scaler


def load_model_and_scaler():
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        if getattr(model, 'n_features_in_', None) == len(FEATURE_NAMES) and len(getattr(scaler, 'mean_', [])) == len(FEATURE_NAMES):
            return model, scaler
    return train_and_save_model()


model, scaler = load_model_and_scaler()

st.title("Network Intrusion Detection System (NIDS)")
st.sidebar.header("Input Network Features")


def user_input():
    logged_in = st.sidebar.selectbox('logged_in (1=Yes, 0=No)', [0, 1])
    count = st.sidebar.slider('count', 0, 500, 100)
    serror_rate = st.sidebar.slider('serror_rate', 0.0, 1.0, 0.5)
    srv_serror_rate = st.sidebar.slider('srv_serror_rate', 0.0, 1.0, 0.5)
    same_srv_rate = st.sidebar.slider('same_srv_rate', 0.0, 1.0, 0.5)
    dst_host_count = st.sidebar.slider('dst_host_count', 0, 255, 100)
    dst_host_srv_count = st.sidebar.slider('dst_host_srv_count', 0, 255, 100)
    dst_host_same_srv_rate = st.sidebar.slider('dst_host_same_srv_rate', 0.0, 1.0, 0.5)
    dst_host_serror_rate = st.sidebar.slider('dst_host_serror_rate', 0.0, 1.0, 0.5)
    dst_host_srv_serror_rate = st.sidebar.slider('dst_host_srv_serror_rate', 0.0, 1.0, 0.5)
    service_http = st.sidebar.selectbox('service_http (1=HTTP, 0=Other)', [0, 1])
    flag_S0 = st.sidebar.selectbox('flag_S0 (1=Yes, 0=No)', [0, 1])
    flag_SF = st.sidebar.selectbox('flag_SF (1=Yes, 0=No)', [0, 1])

    return pd.DataFrame([{
        'logged_in': logged_in,
        'count': count,
        'serror_rate': serror_rate,
        'srv_serror_rate': srv_serror_rate,
        'same_srv_rate': same_srv_rate,
        'dst_host_count': dst_host_count,
        'dst_host_srv_count': dst_host_srv_count,
        'dst_host_same_srv_rate': dst_host_same_srv_rate,
        'dst_host_serror_rate': dst_host_serror_rate,
        'dst_host_srv_serror_rate': dst_host_srv_serror_rate,
        'service_http': service_http,
        'flag_S0': flag_S0,
        'flag_SF': flag_SF
    }])


input_df = user_input()
st.subheader('User Input features')
st.write(input_df)

input_df = input_df[FEATURE_NAMES]
input_scaled = scaler.transform(input_df.values)

prediction = model.predict(input_scaled)[0]
probabilities = model.predict_proba(input_scaled)[0]

st.subheader('Prediction')
st.write(f"Detected: **{CLASS_LABELS.get(int(prediction), str(prediction))}**")

st.subheader("Class Probabilities:")
prob_df = pd.DataFrame({
    'Class': PROBABILITY_LABELS,
    'Probability': probabilities
})
st.write(prob_df)

st.subheader("Class Probability Bar Chart:")
st.bar_chart(prob_df.set_index('Class'))
