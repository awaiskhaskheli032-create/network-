"""
detector.py
------------
Unsupervised anomaly detection for network traffic using
Isolation Forest (scikit-learn).
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler

FEATURE_COLUMNS = [
    "packet_size",
    "packet_rate",
    "port",
    "duration",
    "unique_ports_contacted",
    "protocol_enc",
]


class AnomalyDetector:
    def __init__(self, contamination=0.1, random_state=42):
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )
        self.scaler = StandardScaler()
        self.protocol_encoder = LabelEncoder()
        self.is_fitted = False

    def _prepare_features(self, df: pd.DataFrame, fit_encoder=False):
        df = df.copy()
        if fit_encoder:
            df["protocol_enc"] = self.protocol_encoder.fit_transform(df["protocol"])
        else:
            known = set(self.protocol_encoder.classes_)
            df["protocol_enc"] = df["protocol"].apply(
                lambda p: self.protocol_encoder.transform([p])[0] if p in known else -1
            )
        return df[FEATURE_COLUMNS]

    def fit(self, df: pd.DataFrame):
        X = self._prepare_features(df, fit_encoder=True)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True

    def predict(self, df: pd.DataFrame):
        if not self.is_fitted:
            raise RuntimeError("Model must be fit() before predict().")

        X = self._prepare_features(df, fit_encoder=False)
        X_scaled = self.scaler.transform(X)

        scores = self.model.decision_function(X_scaled)
        preds = self.model.predict(X_scaled)

        result = df.copy()
        result["anomaly_score"] = scores
        result["is_anomaly"] = preds == -1
        return result
