import scapy.all as scapy
import json
import time
import subprocess

class TrafficAnalyzer:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packets = []

    def check_interface(self):
        """Verify the network interface is valid."""
        try:
            result = subprocess.run(["ip", "link", "show", self.interface], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"Interface {self.interface} is valid.")
            else:
                print(f"Error: Interface {self.interface} not found. Available interfaces:")
                subprocess.run(["ip", "link"])
        except Exception as e:
            print(f"Error checking interface: {e}")

    def capture_traffic(self, duration=10):
        """Capture packets for a specified duration (in seconds)."""
        self.check_interface()
        print(f"Starting packet capture on {self.interface} for {duration} seconds...")
        try:
            self.packets = scapy.sniff(iface=self.interface, timeout=duration, filter="tcp port 443")
            print(f"Captured {len(self.packets)} packets.")
            self.save_pcap("logs/captured_traffic.pcap")
        except Exception as e:
            print(f"Error capturing packets: {e}")
            self.packets = []

    def save_pcap(self, filename):
        """Save captured packets to a .pcap file for Wireshark."""
        if self.packets:
            scapy.wrpcap(filename, self.packets)
            print(f"Packets saved to {filename}")
        else:
            print("No packets to save.")

    def analyze_traffic(self):
        """Analyze packet metadata and detect TLS handshakes."""
        traffic_data = []
        for pkt in self.packets:
            if pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.TCP):
                ip_layer = pkt[scapy.IP]
                tcp_layer = pkt[scapy.TCP]
                packet_info = {
                    "timestamp": pkt.time,
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "src_port": tcp_layer.sport,
                    "dst_port": tcp_layer.dport,
                    "packet_size": len(pkt),
                    "protocol": "TLS/HTTPS" if (tcp_layer.dport == 443 or tcp_layer.sport == 443) else "Other",
                    "tls_handshake": False
                }
                if pkt.haslayer(scapy.Raw):
                    payload = pkt[scapy.Raw].load
                    packet_info["tls_handshake"] = len(payload) > 0 and payload[0] == 0x16
                traffic_data.append(packet_info)
        return traffic_data

    def save_analysis(self, data, filename="logs/traffic_analysis.json"):
        """Save analysis to a JSON file."""
        try:
            with open(filename, "w") as f:
                json.dump(data, f, indent=4)
            print(f"Analysis saved to {filename}")
        except Exception as e:
            print(f"Error saving analysis: {e}")

if __name__ == "__main__":
    analyzer = TrafficAnalyzer(interface="eth0")
    analyzer.capture_traffic(duration=10)
    traffic_data = analyzer.analyze_traffic()
    analyzer.save_analysis(traffic_data)
