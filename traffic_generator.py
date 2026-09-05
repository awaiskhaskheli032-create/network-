import numpy as np
import pandas as pd

PROTOCOLS = ["TCP", "UDP", "ICMP"]


def generate_normal_traffic(n=1):
    data = {
        "packet_size": np.random.normal(500, 100, n).clip(40, 1500),
        "packet_rate": np.random.normal(50, 15, n).clip(1, 200),
        "port": np.random.choice([80, 443, 22, 53, 8080], n),
        "protocol": np.random.choice(PROTOCOLS, n, p=[0.7, 0.25, 0.05]),
        "duration": np.random.exponential(2.0, n).clip(0.01, 30),
        "unique_ports_contacted": np.random.poisson(2, n).clip(1, 10),
    }
    return pd.DataFrame(data)


def generate_anomalous_traffic(n=1, kind=None):
    if kind is None:
        kind = np.random.choice(["ddos", "port_scan", "data_exfil"])

    if kind == "ddos":
        data = {
            "packet_size": np.random.normal(60, 10, n).clip(20, 200),
            "packet_rate": np.random.normal(800, 150, n).clip(400, 2000),
            "port": np.random.choice([80, 443], n),
            "protocol": np.random.choice(["TCP", "UDP"], n, p=[0.5, 0.5]),
            "duration": np.random.exponential(0.1, n).clip(0.001, 1),
            "unique_ports_contacted": np.random.poisson(1, n).clip(1, 3),
        }
    elif kind == "port_scan":
        data = {
            "packet_size": np.random.normal(64, 5, n).clip(40, 100),
            "packet_rate": np.random.normal(300, 50, n).clip(100, 600),
            "port": np.random.randint(1, 65535, n),
            "protocol": np.random.choice(["TCP"], n),
            "duration": np.random.exponential(0.05, n).clip(0.001, 0.5),
            "unique_ports_contacted": np.random.poisson(40, n).clip(15, 100),
        }
    else:
        data = {
            "packet_size": np.random.normal(1400, 50, n).clip(1000, 1500),
            "packet_rate": np.random.normal(200, 30, n).clip(100, 400),
            "port": np.random.choice([21, 443, 8443], n),
            "protocol": np.random.choice(["TCP"], n),
            "duration": np.random.normal(20, 5, n).clip(10, 60),
            "unique_ports_contacted": np.random.poisson(2, n).clip(1, 5),
        }

    df = pd.DataFrame(data)
    df["attack_type"] = kind
    return df


def generate_batch(n_normal=90, n_anomaly=10):
    normal = generate_normal_traffic(n_normal)
    normal["attack_type"] = "normal"
    anomaly = generate_anomalous_traffic(n_anomaly)
    batch = pd.concat([normal, anomaly], ignore_index=True)
    return batch.sample(frac=1).reset_index(drop=True)


def live_stream_step(anomaly_probability=0.08):
    if np.random.random() < anomaly_probability:
        row = generate_anomalous_traffic(1)
        return row, True
    else:
        row = generate_normal_traffic(1)
        row["attack_type"] = "normal"
        return row, False
