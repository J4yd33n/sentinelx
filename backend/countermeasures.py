import subprocess

class Countermeasures:
    def block_ip(self, ip_address):
        """Block an IP address using iptables."""
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            print(f"Blocked IP: {ip_address}")
        except subprocess.CalledProcessError:
            print(f"Failed to block IP: {ip_address}")

    def unblock_ip(self, ip_address):
        """Unblock an IP address."""
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            print(f"Unblocked IP: {ip_address}")
        except subprocess.CalledProcessError:
            print(f"Failed to unblock IP: {ip_address}")
