import nmap

class EthicalHacker:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_network(self, target="192.168.72.131/24"):
        """Scan the network to find devices."""
        self.nm.scan(target, arguments="-sP")
        return self.nm.all_hosts()

if __name__ == "__main__":
    hacker = EthicalHacker()
    hosts = hacker.scan_network()
    print(f"Discovered hosts: {hosts}")
