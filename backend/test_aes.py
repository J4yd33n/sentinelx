from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = bytes.fromhex("12d2ddbed647c7b16489ef30dd184f812f6a493333e3a52e09758b2b54deb62e")  # From your output
nonce = bytes.fromhex("32fe6873f70996329eb7ca42")  # From your output
data = "Test log".encode()
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
cipher.update(b"")  # Explicitly set empty AAD
ciphertext_aes, tag = cipher.encrypt_and_digest(data)
print(f"Nonce: {nonce.hex()}, Tag: {tag.hex()}, Ciphertext_AES: {ciphertext_aes.hex()}")

# Decrypt
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
cipher.update(b"")  # Explicitly set empty AAD
decrypted = cipher.decrypt_and_verify(ciphertext_aes, tag).decode()
print(f"Decrypted: {decrypted}")
