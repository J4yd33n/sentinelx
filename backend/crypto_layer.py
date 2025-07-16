from oqs import KeyEncapsulation
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class CryptoLayer:
    def __init__(self):
        self.kyber = KeyEncapsulation("Kyber512")
        self.private_key = None

    def generate_keypair(self):
        """Generate a public/private key pair for Kyber."""
        self.private_key = self.kyber.generate_keypair()
        return self.private_key

    def encrypt_log(self, data, public_key):
        """Encrypt data using Kyber and AES-GCM."""
        ciphertext, shared_secret = self.kyber.encap_secret(public_key)
        nonce = get_random_bytes(12)
        cipher = AES.new(shared_secret[:16], AES.MODE_GCM, nonce=nonce)
        ciphertext_aes, tag = cipher.encrypt_and_digest(data.encode())
        # Combine nonce, tag, ciphertext, and Kyber ciphertext
        combined = nonce + tag + ciphertext_aes
        return base64.b64encode(combined).decode(), ciphertext

    def decrypt_log(self, encrypted_data, ciphertext):
        """Decrypt data using Kyber and AES-GCM."""
        shared_secret = self.kyber.decap_secret(ciphertext)
        encrypted_data = base64.b64decode(encrypted_data)
        nonce, tag, ciphertext_aes = encrypted_data[:12], encrypted_data[12:28], encrypted_data[28:]
        cipher = AES.new(shared_secret[:16], AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext_aes, tag).decode()

if __name__ == "__main__":
    crypto = CryptoLayer()
    public_key = crypto.generate_keypair()
    log_data = "Sample log: Suspicious IP detected."
    encrypted, ciphertext = crypto.encrypt_log(log_data, public_key)
    print(f"Encrypted: {encrypted}")
    decrypted = crypto.decrypt_log(encrypted, ciphertext)
    print(f"Decrypted: {decrypted}")
