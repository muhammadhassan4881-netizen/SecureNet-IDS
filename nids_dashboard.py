# Install required packages if not installed
# pip install streamlit scikit-learn xgboost pandas
import streamlit as st
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
import matplotlib.pyplot as plt


# Load your trained model (save your trained model as 'model.pkl')
model = joblib.load("model.pkl")

# Title
st.title("Network Intrusion Detection System (NIDS)")

# Sidebar for input features
st.sidebar.header("Input Network Features")

# Collect user input
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

    # Add more features as per your final selected 13 features
    data = {
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
    }
    features = pd.DataFrame(data, index=[0])
    return features

input_df = user_input()

# Show input
st.subheader('User Input features')
st.write(input_df)
# Make prediction
prediction = model.predict(input_df)

# Output prediction
st.subheader('Prediction')
labels = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'R2L', 4: 'U2R'}
st.write(f"Detected: **{labels[int(prediction[0])]}**")

# Predict probabilities
probabilities = model.predict_proba(input_df)[0]

# Display probabilities table
st.subheader("Class Probabilities:")
labels_list = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
prob_df = pd.DataFrame({'Class': labels_list, 'Probability': probabilities})
st.write(prob_df)


# Plot Bar Chart
st.subheader("Class Probability Bar Chart:")
st.bar_chart(prob_df.set_index('Class'))
