# NIDS
# Network Intrusion Detection System (NIDS) using Machine Learning
Network_Intrusion_detection_system

This project implements a machine learning-based Network Intrusion Detection System (NIDS) using the NSL-KDD dataset.

---

## 🚀 Project Overview

- **Dataset**: NSL-KDD
- import kagglehub
  path = kagglehub.dataset_download("hassan06/nslkdd")

print("Path to dataset files:", path)
- **Techniques used**:
  - Data Discretization using `KBinsDiscretizer`
  - Feature Selection using `SelectKBest` (Mutual Information)
  - Class Imbalance Handling using `ADASYN`
  - Model Training with `XGBoost` `Random forest` `KNN` `Naive Bayes` `Decision Trees`
  - Interactive Deployment using `Streamlit` `Hugging Face`

---

## 🔧 Model Pipeline

1. **Data Preprocessing:**
   - OneHotEncoding for categorical variables.
   - Discretization of continuous features into bins.
   - Feature Selection (Top 13 features selected).
   - Oversampling minority classes using ADASYN.

2. **Model Training:**
   - Trained using `XGBoostClassifier`(best model amomg all) in dashboard  on selected features.

3. **Deployment:**
   - Interactive web-based dashboard built using Streamlit. Deployed using Hugging Face

---

## 🔑 Selected Features Used

- `logged_in`
- `count`
- `serror_rate`
- `srv_serror_rate`
- `same_srv_rate`
- `dst_host_count`
- `dst_host_srv_count`
- `dst_host_same_srv_rate`
- `dst_host_serror_rate`
- `dst_host_srv_serror_rate`
- `service_http`
- `flag_S0`
- `flag_SF`

---

## 📊 Dashboard Features

- User input interface for 13 selected features.
- Real-time prediction of attack class.
- Displays:
  - Prediction class label
  - Class probabilities
  - Bar chart visualization

---

## 🏗 Deployment Instructions

### 1️⃣ Clone Repository

```bash
git clone https://github.com/your-username/nids-dashboard.git
cd nids-dashboard
"# SecureNet-IDS" 
