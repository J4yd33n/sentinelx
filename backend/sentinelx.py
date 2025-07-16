import json
import sys
import sqlite3
import numpy as np
from termcolor import colored
from traffic_analyzer import TrafficAnalyzer
from anomaly_detector import AnomalyDetector, TORCH_AVAILABLE
from countermeasures import Countermeasures
import time
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def print_ascii_header():
    """Print a large ASCII art header for SentinelX."""
    print(r"""
    ____            _       _          __  __
   / ___|  ___ _ __| |_ ___| |__   ___|  \/  |
   \___ \ / __| '__| __/ __| '_ \ / __| |\/| |
    ___) | (__| |  | || (__| | | | (__| |  | |
   |____/ \___|_|   \__|\___|_| |_| \___|_|  |_|

   === SentinelX Terminal Dashboard ===
    """)

def print_line_chart(packet_sizes, max_height=10, width=50):
    """Print a simple ASCII line chart for packet sizes."""
    if not packet_sizes:
        print("No packet sizes to display.")
        return
    max_size = max(packet_sizes, default=1)
    min_size = min(packet_sizes, default=0)
    if max_size == min_size:
        max_size += 1
    normalized = [(size - min_size) / (max_size - min_size) * max_height for size in packet_sizes]
    
    print("\nNetwork Traffic (Packet Sizes)")
    for h in range(max_height, -1, -1):
        line = f"{int(min_size + (h/max_height)*(max_size-min_size)):>5} | "
        for val in normalized[:width]:
            line += "*" if val >= h else " "
        print(line)
    print("      +" + "-" * min(len(packet_sizes), width))
    print("      " + " ".join(str(i+1) for i in range(min(len(packet_sizes), width))))

def print_pie_chart(normal_count, anomaly_count):
    """Print a text-based pie chart for anomaly distribution."""
    total = normal_count + anomaly_count
    if total == 0:
        print("\nAnomaly Distribution\nNo data to display.")
        return
    normal_pct = (normal_count / total) * 100 if total > 0 else 0
    anomaly_pct = (anomaly_count / total) * 100 if total > 0 else 0
    print("\nAnomaly Distribution")
    print(colored(f"Normal Packets: {normal_pct:.1f}% [{normal_count} packets]", "green"))
    print(colored(f"Anomalies:      {anomaly_pct:.1f}% [{anomaly_count} packets]", "red"))

def print_traffic_table(traffic_data):
    """Print a table of traffic details."""
    if not traffic_data:
        print("\nTraffic Details\nNo traffic data to display.")
        return
    print("\nTraffic Details")
    headers = ["Source IP", "Destination IP", "Src Port", "Dst Port", "Size", "TLS"]
    print(f"{headers[0]:<16} | {headers[1]:<16} | {headers[2]:<8} | {headers[3]:<8} | {headers[4]:<6} | {headers[5]}")
    print("-" * 16 + "|" + "-" * 17 + "|" + "-" * 9 + "|" + "-" * 9 + "|" + "-" * 7 + "|" + "-" * 5)
    for pkt in traffic_data[:10]:
        tls = "Yes" if pkt.get("tls_handshake", False) else "No"
        print(f"{pkt['src_ip']:<16} | {pkt['dst_ip']:<16} | {pkt['src_port']:<8} | {pkt['dst_port']:<8} | {pkt['packet_size']:<6} | {tls}")

def print_anomalies(anomalies):
    """Print a list of anomalies."""
    print("\nAnomalies")
    anomalies_found = False
    for anomaly in anomalies:
        if anomaly["anomaly"]:
            anomalies_found = True
            print(colored(f"- {anomaly['packet']['src_ip']} - {anomaly['packet']['timestamp']}", "red"))
    if not anomalies_found:
        print(colored("No anomalies detected.", "green"))

def block_anomalous_ips(anomalies):
    """Block IPs of anomalous packets."""
    defense = Countermeasures()
    blocked_ips = set()
    for anomaly in anomalies:
        if anomaly["anomaly"]:
            ip = anomaly["packet"]["src_ip"]
            if ip not in blocked_ips:
                defense.block_ip(ip)
                blocked_ips.add(ip)

def save_to_db(traffic_data):
    """Save traffic data to SQLite database."""
    try:
        conn = sqlite3.connect('logs/traffic.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS traffic
                     (timestamp REAL, src_ip TEXT, dst_ip TEXT, src_port INT, dst_port INT, size INT, tls TEXT)''')
        for pkt in traffic_data:
            c.execute("INSERT INTO traffic VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (pkt['timestamp'], pkt['src_ip'], pkt['dst_ip'], pkt['src_port'], pkt['dst_port'], pkt['packet_size'], 'Yes' if pkt.get('tls_handshake') else 'No'))
        conn.commit()
        print(f"Saved {len(traffic_data)} packets to logs/traffic.db")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

def show_gui(traffic_data, anomalies, refresh_callback):
    """Show a Tkinter GUI dashboard with a chart."""
    root = tk.Tk()
    root.title("SentinelX Dashboard")
    root.geometry("1000x800")
    tk.Label(root, text="SentinelX Dashboard", font=("Arial", 16, "bold")).pack(pady=10)
    
    # Traffic Table
    tree = ttk.Treeview(root, columns=("Source IP", "Dest IP", "Src Port", "Dst Port", "Size", "TLS", "Anomaly"), show="headings")
    for col in tree["columns"]:
        tree.heading(col, text=col)
        tree.column(col, width=100)
    for i, pkt in enumerate(traffic_data[:20]):
        anomaly = next((a["anomaly"] for a in anomalies if a["packet"] == pkt), False)
        tree.insert("", "end", values=(
            pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], pkt["dst_port"],
            pkt["packet_size"], "Yes" if pkt.get("tls_handshake") else "No", "Yes" if anomaly else "No"
        ))
    tree.pack(pady=10, fill="both", expand=True)
    
    # Packet Size Chart
    fig, ax = plt.subplots(figsize=(6, 3))
    packet_sizes = [pkt["packet_size"] for pkt in traffic_data[:50]]
    ax.plot(range(len(packet_sizes)), packet_sizes, marker='o', color='blue')
    ax.set_title("Packet Sizes Over Time")
    ax.set_xlabel("Packet Index")
    ax.set_ylabel("Size (bytes)")
    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.draw()
    canvas.get_tk_widget().pack(pady=10)
    
    # Buttons
    tk.Button(root, text="Refresh", command=refresh_callback).pack(pady=5)
    tk.Button(root, text="Exit", command=sys.exit).pack(pady=5)
    return root

def main(use_json=True, use_gui=False, refresh_interval=None):
    """Main function to display the terminal or GUI dashboard."""
    def refresh():
        if use_gui:
            root.destroy()
        main(use_json, use_gui, refresh_interval)

    while True:
        # Load or capture traffic data
        if use_json:
            try:
                with open("logs/traffic_analysis.json", "r") as f:
                    traffic_data = json.load(f)
                print(f"Loaded {len(traffic_data)} packets from logs/traffic_analysis.json")
            except Exception as e:
                print(f"Error reading traffic data: {e}")
                analyzer = TrafficAnalyzer(interface="eth0")
                analyzer.capture_traffic(duration=30)
                traffic_data = analyzer.analyze_traffic()
                print(f"Captured {len(traffic_data)} packets")
        else:
            analyzer = TrafficAnalyzer(interface="eth0")
            analyzer.capture_traffic(duration=30)
            traffic_data = analyzer.analyze_traffic()
            print(f"Captured {len(traffic_data)} packets")

        # Save to database
        if traffic_data:
            save_to_db(traffic_data)
        else:
            print("No traffic data available. Exiting...")
            break

        # Analyze anomalies
        detector = AnomalyDetector(use_lstm=TORCH_AVAILABLE)
        if not use_gui:
            detector.get_target()
        detector.train(traffic_data)
        anomalies = detector.predict(traffic_data)

        # Extract packet sizes and anomaly counts
        packet_sizes = [pkt["packet_size"] for pkt in traffic_data]
        anomaly_count = sum(1 for anomaly in anomalies if anomaly["anomaly"])
        normal_count = len(traffic_data) - anomaly_count

        # Display dashboard
        if use_gui:
            root = show_gui(traffic_data, anomalies, refresh)
            root.mainloop()
            break
        else:
            print_ascii_header()
            print_line_chart(packet_sizes)
            print_pie_chart(normal_count, anomaly_count)
            print_traffic_table(traffic_data)
            print_anomalies(anomalies)
            block_anomalous_ips(anomalies)
        
        if refresh_interval:
            print(f"Refreshing in {refresh_interval} seconds...")
            time.sleep(refresh_interval)
        else:
            try:
                input("Press Enter to refresh or Ctrl+C to exit...")
            except KeyboardInterrupt:
                print("\nExiting SentinelX...")
                break

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SentinelX Network Monitoring")
    parser.add_argument("--gui", action="store_true", help="Run with GUI")
    parser.add_argument("--refresh", type=int, help="Auto-refresh interval in seconds")
    args = parser.parse_args()
    main(use_json=True, use_gui=args.gui, refresh_interval=args.refresh)
