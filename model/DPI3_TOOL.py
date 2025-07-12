import time
import numpy as np
import joblib
import onnxruntime as ort
import pandas as pd
import os
from nfstream import NFStreamer
import csv

# ==== Load Required Artifacts ====
scaler = joblib.load("scaler.pkl")
features = joblib.load("features.pkl")
with open("threshold.txt") as f:
    threshold = float(f.read().strip())

# ==== Load ONNX Autoencoder ====
session = ort.InferenceSession("autoencoder_model.onnx")
input_name = session.get_inputs()[0].name
output_name = session.get_outputs()[0].name

# ==== Output CSV Logger Setup ====
log_filename = "live_detection_log.csv"
if not os.path.exists(log_filename):
    with open(log_filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "MSE", "Prediction"] + features)

print("[🔍] Starting continuous live prediction (IPv4 + IPv6)...\n")

# ==== Initialize NFStreamer ====
streamer = NFStreamer(
    source="wlan0",  # Change to "eth0" if needed
    statistical_analysis=True,
    snapshot_length=1536,
    active_timeout=1,
    accounting_mode=0,
    udps=None
)

# ==== Real-time flow analysis ====
try:
    for flow in streamer:
        try:
            src_ip = getattr(flow, "src_ip", "N/A")
            dst_ip = getattr(flow, "dst_ip", "N/A")

            feats = [
                getattr(flow, "bidirectional_duration_ms", 0),
                getattr(flow, "src2dst_packets", 0),
                getattr(flow, "dst2src_packets", 0),
                getattr(flow, "src2dst_bytes", 0),
                getattr(flow, "dst2src_bytes", 0),
                getattr(flow, "bidirectional_mean_piat_ms", 0),
                getattr(flow, "bidirectional_stddev_piat_ms", 0),
                getattr(flow, "bidirectional_max_piat_ms", 0),
                getattr(flow, "bidirectional_min_piat_ms", 0),
                getattr(flow, "src2dst_duration_ms", 0),
                getattr(flow, "src2dst_mean_piat_ms", 0),
                getattr(flow, "src2dst_stddev_piat_ms", 0),
                getattr(flow, "src2dst_max_piat_ms", 0),
                getattr(flow, "src2dst_min_piat_ms", 0),
                getattr(flow, "dst2src_duration_ms", 0),
                getattr(flow, "dst2src_mean_piat_ms", 0),
                getattr(flow, "dst2src_stddev_piat_ms", 0),
                getattr(flow, "dst2src_max_piat_ms", 0),
                getattr(flow, "dst2src_min_piat_ms", 0),
                getattr(flow, "src2dst_mean_ps", 0),
                getattr(flow, "dst2src_mean_ps", 0),
                getattr(flow, "dst_port", 0),
            ]

            # === Predict ===
            x_df = pd.DataFrame([feats], columns=features)
            x_scaled = scaler.transform(x_df).astype(np.float32)
            pred = session.run([output_name], {input_name: x_scaled})[0]
            mse = np.mean(np.power(x_scaled - pred, 2))
            label = "ATTACK 🚨" if mse > threshold else "BENIGN ✅"
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            # === Print live prediction ===
            print(f"[{timestamp}] {src_ip} → {dst_ip} | MSE: {mse:.6f} → {label}")

            # === Save to CSV ===
            with open(log_filename, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, src_ip, dst_ip, mse, label] + feats)

        except Exception as fe:
            print("[⚠️] Flow prediction error:", fe)

except KeyboardInterrupt:
    print("\n[⛔] Detection stopped by user.")
