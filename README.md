# SentinelX - Next-Generation Cybersecurity Tool

**SentinelX** is a network traffic monitoring and anomaly detection tool designed for 2035–2045 cybersecurity challenges. It uses `IsolationForest` and optional PyTorch LSTM models to detect anomalies, with a terminal dashboard and Tkinter GUI for visualization. Features include target IP/URL filtering, SQLite storage, and automatic IP blocking.

## Features
- Prompts for target IP or web address (e.g., `192.168.1.1` or `https://google.com`) to filter traffic.
- Loads traffic from `logs/traffic_analysis.json` or captures live traffic (60 seconds).
- Displays target IP in terminal header.
- Bold ASCII art header (terminal) or Tkinter GUI with packet size chart.
- Text-based line chart of packet sizes.
- Colorized anomaly distribution (green for normal, red for anomalies).
- Traffic details table (10 rows terminal, 20 rows GUI).
- Anomalies list with automatic IP blocking (unique IPs only).
- Stores data in SQLite (`logs/traffic.db`).
- Supports `IsolationForest` (default, contamination=0.05) and optional LSTM (requires PyTorch).

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/J4yd33n/sentinelx.git
   cd sentinelx
