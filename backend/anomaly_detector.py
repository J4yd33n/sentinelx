from sklearn.ensemble import IsolationForest
import numpy as np
import socket
import re
import json
try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
from traffic_analyzer import TrafficAnalyzer

class AnomalyDetector:
    def __init__(self, use_lstm=False):
        self.isolation_model = IsolationForest(contamination=0.05, random_state=42)
        self.use_lstm = use_lstm and TORCH_AVAILABLE
        if self.use_lstm:
            self.lstm_model = nn.Sequential(
                nn.LSTM(6, 32, batch_first=True),
                nn.Linear(32, 16),
                nn.ReLU(),
                nn.Linear(16, 1),
                nn.Sigmoid()
            )
        self.target_ip = None

    def resolve_url_to_ip(self, url):
        """Resolve a URL to an IP address."""
        try:
            url = re.sub(r'^https?://', '', url)
            return socket.gethostbyname(url)
        except socket.gaierror:
            print(f"Error: Unable to resolve URL '{url}' to an IP address.")
            return None

    def is_valid_ip(self, ip):
        """Validate an IP address."""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False

    def get_target(self):
        """Prompt user for target IP or web address."""
        print("\nEnter target IP address or web address (e.g., 192.168.1.1 or example.com):")
        target = input("Target: ").strip()
        if self.is_valid_ip(target):
            self.target_ip = target
        else:
            self.target_ip = self.resolve_url_to_ip(target)
        if self.target_ip:
            print(f"Analyzing traffic for target IP: {self.target_ip}")
        else:
            print("Invalid input. Analyzing all traffic.")
        return self.target_ip

    def filter_traffic(self, traffic_data):
        """Filter traffic data for packets involving the target IP."""
        if not self.target_ip:
            return traffic_data
        filtered = [pkt for pkt in traffic_data if pkt.get("src_ip") == self.target_ip or pkt.get("dst_ip") == self.target_ip]
        if not filtered:
            print(f"No traffic data matches the target IP: {self.target_ip}")
        return filtered

    def extract_features(self, traffic_data):
        """Turn traffic data into features for the AI model, grouped by src_ip."""
        features_by_ip = {}
        for pkt in traffic_data:
            src_ip = pkt.get("src_ip", "0.0.0.0")
            if src_ip not in features_by_ip:
                features_by_ip[src_ip] = []
            try:
                last_octet = int(pkt["src_ip"].split(".")[-1])
            except (ValueError, KeyError):
                last_octet = 0
            feature = [
                pkt.get("timestamp", 0),
                pkt.get("packet_size", 0),
                last_octet,
                pkt.get("src_port", 0),
                pkt.get("dst_port", 0),
                1 if pkt.get("tls_handshake", False) else 0
            ]
            features_by_ip[src_ip].append(feature)
        return {ip: np.array(feats) for ip, feats in features_by_ip.items()}

    def prepare_lstm_data(self, features):
        """Prepare data for LSTM (sequences of 10 packets)."""
        if len(features) < 10:
            return np.array([]).reshape(0, 10, 6)
        sequences = []
        for i in range(len(features) - 10):
            sequences.append(features[i:i+10])
        return np.array(sequences)

    def train(self, traffic_data):
        """Train IsolationForest and optionally LSTM models per device."""
        filtered_traffic = self.filter_traffic(traffic_data)
        if not filtered_traffic:
            print("No traffic data matches the target IP.")
            return
        features_by_ip = self.extract_features(filtered_traffic)
        self.isolation_models = {}
        if self.use_lstm and TORCH_AVAILABLE:
            self.lstm_models = {}
        for src_ip, features in features_by_ip.items():
            if len(features) > 0:
                # Train IsolationForest
                self.isolation_models[src_ip] = IsolationForest(contamination=0.05, random_state=42)
                self.isolation_models[src_ip].fit(features)
                print(f"IsolationForest model trained for {src_ip}")
                
                # Train LSTM
                if self.use_lstm and TORCH_AVAILABLE:
                    lstm_features = self.prepare_lstm_data(features)
                    if len(lstm_features) > 0:
                        self.lstm_models[src_ip] = nn.Sequential(
                            nn.LSTM(6, 32, batch_first=True),
                            nn.Linear(32, 16),
                            nn.ReLU(),
                            nn.Linear(16, 1),
                            nn.Sigmoid()
                        )
                        lstm_features = torch.tensor(lstm_features, dtype=torch.float32)
                        labels = torch.zeros(len(lstm_features), dtype=torch.float32)
                        optimizer = torch.optim.Adam(self.lstm_models[src_ip].parameters(), lr=0.001)
                        criterion = nn.BCELoss()
                        for _ in range(10):
                            optimizer.zero_grad()
                            outputs, _ = self.lstm_models[src_ip](lstm_features)
                            outputs = outputs.squeeze(-1)
                            loss = criterion(outputs, labels)
                            loss.backward()
                            optimizer.step()
                        print(f"LSTM model trained for {src_ip}")
        if not features_by_ip:
            print("No data to train on.")

    def predict(self, traffic_data):
        """Predict anomalies using IsolationForest and optionally LSTM per device."""
        filtered_traffic = self.filter_traffic(traffic_data)
        if not filtered_traffic:
            print("No traffic data matches the target IP.")
            return [{"packet": pkt, "anomaly": False} for pkt in traffic_data]
        features_by_ip = self.extract_features(filtered_traffic)
        results = []
        for pkt in traffic_data:
            src_ip = pkt.get("src_ip", "0.0.0.0")
            features = features_by_ip.get(src_ip, np.array([]))
            anomaly = False
            if len(features) > 0 and src_ip in self.isolation_models:
                iso_prediction = self.isolation_models[src_ip].predict([features[-1]])[0]
                iso_anomaly = iso_prediction == -1
                if self.use_lstm and TORCH_AVAILABLE and src_ip in self.lstm_models:
                    lstm_features = self.prepare_lstm_data(features)
                    if len(lstm_features) > 0:
                        lstm_features = torch.tensor(lstm_features[-1:], dtype=torch.float32)
                        lstm_prediction = self.lstm_models[src_ip](lstm_features)[0].squeeze(-1).detach().numpy() > 0.5
                        anomaly = iso_anomaly or lstm_prediction
                    else:
                        anomaly = iso_anomaly
                else:
                    anomaly = iso_anomaly
            results.append({"packet": pkt, "anomaly": anomaly})
        return results

if __name__ == "__main__":
    detector = AnomalyDetector(use_lstm=TORCH_AVAILABLE)
    detector.get_target()
    try:
        with open("logs/traffic_analysis.json", "r") as f:
            traffic_data = json.load(f)
        print(f"Loaded {len(traffic_data)} packets from logs/traffic_analysis.json")
    except FileNotFoundError:
        print("No traffic_analysis.json found. Capturing live traffic...")
        analyzer = TrafficAnalyzer(interface="eth0")
        analyzer.capture_traffic(duration=30)  # Increased duration
        traffic_data = analyzer.analyze_traffic()
        print(f"Captured {len(traffic_data)} packets")
    detector.train(traffic_data)
    anomalies = detector.predict(traffic_data)
    for anomaly in anomalies:
        if anomaly["anomaly"]:
            print(f"Anomaly detected: {anomaly['packet']}")
