import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = [
    "total_packets",
    "total_bytes",
    "unique_src_ips",
    "unique_dst_ips",
    "unique_src_ports",
    "unique_dst_ports",
    "tcp_count",
    "udp_count",
    "other_count",
    "avg_packet_size",
]

class AnomalyDetector:
    def __init__(self, contamination=0.1, random_state=42):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state
        )

    def fit(self, df: pd.DataFrame):
        X = df[FEATURE_COLUMNS].values
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)

    def score(self, df: pd.DataFrame):
        X = df[FEATURE_COLUMNS].values
        X_scaled = self.scaler.transform(X)
        scores = -self.model.score_samples(X_scaled)
        return scores