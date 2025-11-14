# Network Traffic Anomaly Detection
My first AI web application that uses Streamlit designed to examine PCAP files and flag unusual network activity using the IsolationForest algorithm.

You can:

- Upload a Wireshark `.pcap` / `.pcapng` file
- Extract per–time-window traffic statistics
- Run unsupervised anomaly detection on those windows using IsolationForest
- See which time windows look the most suspicious

---

## 🔧 Tech Stack I used

- **Python** (tested with Python 3.11)
- **Streamlit** – web UI
- **Scapy** – parsing PCAP files
- **pandas** – data handling
- **scikit-learn** – IsolationForest anomaly detection
- **joblib** – (this is optional) used for model persistence

---

# How to Run?

- use venv and make sure of the requierments.txt
- Run using: streamlit run app/streamlit_app.py

---

## 📂 Project Structure

```text
network-traffic-anomaly-detection/
├─ app/
│  └─ streamlit_app.py        # Streamlit GUI
├─ src/
│  ├─ __init__.py
│  ├─ features.py             # PCAP → per-window feature extraction
│  └─ model.py                # AnomalyDetector (IsolationForest)
├─ tmp/                       # created at runtime for uploaded files
├─ requirements.txt
└─ README.md

---
