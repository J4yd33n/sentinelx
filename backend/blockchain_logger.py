import hashlib
import time
import json

class BlockchainLogger:
    def __init__(self):
        self.chain = []
        self.create_block(proof=1, previous_hash='0')

    def create_block(self, proof, previous_hash):
        """Create a new block in the chain."""
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'proof': proof,
            'previous_hash': previous_hash,
            'data': []
        }
        self.chain.append(block)
        return block

    def log_action(self, action):
        """Add an action to the blockchain."""
        block = self.chain[-1]
        block['data'].append(action)
        with open("logs/blockchain.json", "w") as f:
            json.dump(self.chain, f, indent=4)

if __name__ == "__main__":
    logger = BlockchainLogger()
    logger.log_action("Suspicious IP blocked: 192.168.1.100")
    print("Logged to blockchain.")
