import time
import pandas as pd
import streamlit as st
import plotly.graph_objs as go

from traffic_generator import generate_batch, live_stream_step
from detector import AnomalyDetector

st.set_page_config(page_title="Network Traffic Anomaly Detector", page_icon="📡", layout="wide")

if "detector" not in st.session_state:
    training_data = generate_batch(n_normal=300, n_anomaly=0)
    det = AnomalyDetector(contamination=0.08)
    det.fit(training_data)
    st.session_state.detector = det
    st.session_state.history = pd.DataFrame()
    st.session_state.alerts = []
    st.session_state.running = False
    st.session_state.total_packets = 0
    st.session_state.total_anomalies = 0

st.title("📡 Real-Time Network Traffic Anomaly Detector")
st.caption("Telecommunications Engineering Project • Unsupervised ML (Isolation Forest) • Simulated live traffic feed")

st.sidebar.header("⚙️ Controls")
speed = st.sidebar.slider("Stream speed (packets/refresh)", 1, 20, 5)
anomaly_prob = st.sidebar.slider("Simulated anomaly rate", 0.01, 0.30, 0.08)
window_size = st.sidebar.slider("Rolling window size (rows shown)", 20, 300, 100)

start = st.sidebar.button("▶ Start / Resume Stream")
stop = st.sidebar.button("⏸ Pause Stream")
reset = st.sidebar.button("🔄 Reset Session")

if start:
    st.session_state.running = True
if stop:
    st.session_state.running = False
if reset:
    st.session_state.history = pd.DataFrame()
    st.session_state.alerts = []
    st.session_state.total_packets = 0
    st.session_state.total_anomalies = 0
    st.session_state.running = False

st.sidebar.markdown("---")
st.sidebar.metric("Total Packets Analyzed", st.session_state.total_packets)
st.sidebar.metric("Total Anomalies Flagged", st.session_state.total_anomalies)

if st.session_state.running:
    new_rows = []
    for _ in range(speed):
        row, actually_anomalous = live_stream_step(anomaly_probability=anomaly_prob)
        new_rows.append(row)
    batch = pd.concat(new_rows, ignore_index=True)

    scored = st.session_state.detector.predict(batch)
    st.session_state.history = pd.concat([st.session_state.history, scored], ignore_index=True).tail(window_size)

    st.session_state.total_packets += len(scored)
    new_anomalies = scored[scored["is_anomaly"]]
    st.session_state.total_anomalies += len(new_anomalies)

    for _, r in new_anomalies.iterrows():
        st.session_state.alerts.insert(0, f"🚨 {r['attack_type'].upper()} suspected — port {r['port']}, rate {r['packet_rate']:.0f} pkt/s, score {r['anomaly_score']:.3f}")
    st.session_state.alerts = st.session_state.alerts[:15]

hist = st.session_state.history
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Live Packet Rate & Anomaly Markers")
    if not hist.empty:
        fig = go.Figure()
        fig.add_trace(go.Scatter(y=hist["packet_rate"], mode="lines", name="Packet Rate", line=dict(color="#00CC96")))
        anomaly_points = hist[hist["is_anomaly"]]
        fig.add_trace(go.Scatter(x=anomaly_points.index, y=anomaly_points["packet_rate"], mode="markers", name="Anomaly", marker=dict(color="red", size=10, symbol="x")))
        fig.update_layout(height=400, margin=dict(l=10, r=10, t=30, b=10), xaxis_title="Packet sequence", yaxis_title="Packets/sec")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Press **▶ Start / Resume Stream** in the sidebar to begin.")

with col2:
    st.subheader("🚨 Live Alerts")
    if st.session_state.alerts:
        for a in st.session_state.alerts:
            st.error(a)
    else:
        st.success("No anomalies detected yet.")

st.subheader("Recent Traffic Log")
if not hist.empty:
    display_df = hist.tail(15)[["packet_size", "packet_rate", "port", "protocol", "duration", "unique_ports_contacted", "anomaly_score", "is_anomaly"]]
    st.dataframe(display_df.style.apply(lambda row: ["background-color: #ffcccc" if row["is_anomaly"] else "" for _ in row], axis=1), use_container_width=True)

if st.session_state.running:
    time.sleep(1)
    st.rerun()
