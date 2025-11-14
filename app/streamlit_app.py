import os
import sys
import pandas as pd
import streamlit as st

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from src.features import extract_features_from_pcap
from src.model import AnomalyDetector

st.title("Network Traffic Anomaly Detection")

st.write(
    "Upload a Wireshark capture file (.pcap or .pcapng). "
    "The app will extract per-window traffic statistics and "
    "run an unsupervised anomaly detector (IsolationForest) "
    "on the same capture."
)

uploaded_file = st.file_uploader(
    "Choose a PCAP file",
    type=["pcap", "pcapng"]
)

if uploaded_file is not None:
    st.success("File uploaded successfully!")
    st.write(f"**File name:** {uploaded_file.name}")
    st.write(f"**File size:** {uploaded_file.size} bytes")

    tmp_dir = os.path.join(PROJECT_ROOT, "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_path = os.path.join(tmp_dir, uploaded_file.name)

    with open(tmp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.write(f"Saved upload to: `{tmp_path}`")

    # Extract features
    with st.spinner("Parsing PCAP and extracting per-window features..."):
        df = extract_features_from_pcap(tmp_path, window_size=60)

    if df.empty:
        st.error("No packets found in this capture or parsing failed.")
    else:
        st.subheader("Per-window traffic statistics")
        st.dataframe(df.head())

        st.subheader("Packets per time window")
        if "total_packets" in df.columns:
            st.line_chart(df["total_packets"])

        st.subheader("Overall summary")
        total_packets = int(df["total_packets"].sum())
        total_bytes = int(df["total_bytes"].sum())
        st.write(f"**Total packets (all windows):** {total_packets}")
        st.write(f"**Total bytes (all windows):** {total_bytes}")

        st.markdown("---")
        st.subheader("Anomaly detection on this capture")

        contamination = st.slider(
            "Assumed fraction of anomalous windows (contamination)",
            min_value=0.01,
            max_value=0.5,
            value=0.1,
            step=0.01,
        )

        if st.button("Run anomaly detection"):
            detector = AnomalyDetector(contamination=contamination)
            detector.fit(df)
            scores = detector.score(df)
            df["anomaly_score"] = scores

            st.subheader("Anomaly score per window")
            st.line_chart(df["anomaly_score"])

            st.subheader("Top suspicious windows")
            st.dataframe(
                df.sort_values("anomaly_score", ascending=False).head(10)
            )
else:
    st.info("No file uploaded yet.")
