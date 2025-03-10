import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Load AES key from file
AES_KEY_FILE = "backend/aes_key.txt"

def load_aes_key():
    """Load the AES key from the file and ensure it's in bytes format."""
    with open(AES_KEY_FILE, "rb") as key_file:  # Read in binary mode
        key = key_file.read().strip()  

    # Ensure the key is 16, 24, or 32 bytes long
    if len(key) in [16, 24, 32]:  
        return key
    else:
        raise ValueError(f"Invalid AES Key: Must be 16, 24, or 32 bytes long, got {len(key)} bytes")

AES_KEY = load_aes_key()
print(f"AES_KEY length: {len(AES_KEY)} bytes")  # Debugging


def encrypt_message(message,AES_KEY):
    """Encrypt a message using AES CBC mode."""
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(padded_message) + encryptor.finalize()

    encrypted_b64 = base64.b64encode(iv + encrypted_bytes).decode()
    return encrypted_b64

def decrypt_message(encrypted_b64,key):
    """Decrypt a message using AES CBC mode."""
    encrypted_bytes = base64.b64decode(encrypted_b64)
    iv = encrypted_bytes[:16]
    encrypted_data = encrypted_bytes[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted_message.decode()
