import os

# File paths for key storage
AES_KEY_FILE = "backend/aes_key.txt"

def generate_aes_key():
    """Generate a 16-byte AES key and save it to a file if it doesn't exist."""
    if not os.path.exists(AES_KEY_FILE):
        key = os.urandom(16)  # AES key (128-bit)
        with open(AES_KEY_FILE, "wb") as key_file:
            key_file.write(key)

def load_aes_key():
    """Load the AES key from the file."""
    if not os.path.exists(AES_KEY_FILE):
        generate_aes_key()
    with open(AES_KEY_FILE, "rb") as key_file:
        return key_file.read()

# Ensure key is generated before use
generate_aes_key()
AES_KEY = load_aes_key()
