import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def validate_key(user_key):
    """Ensure the key is exactly 8 characters long."""
    if len(user_key) != 8:
        raise ValueError("Encryption key must be exactly 8 characters long.")
    return user_key.encode().ljust(16, b'\0')  # Convert to 16 bytes

def encrypt_message(message, user_key):
    """Encrypt message using AES-CBC with user-provided key."""
    key = validate_key(user_key)  # Validate and format key
    iv = os.urandom(16)  # Generate a random IV
    
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(padded_message) + encryptor.finalize()
    
    encrypted_b64 = base64.b64encode(iv + encrypted_bytes).decode()
    return encrypted_b64

def decrypt_message(encrypted_b64, user_key):
     #Decrypt message using AES-CBC with user-provided key.#
    try:
        key = user_key.encode().ljust(16, b'\0')  # Convert to 16 bytes
        encrypted_bytes = base64.b64decode(encrypted_b64)
        iv = encrypted_bytes[:16]
        encrypted_data = encrypted_bytes[16:]
    
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_message = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted_message.decode()

    except (ValueError, Exception):  # Catch all decryption errors
            raise ValueError("Invalid decryption key")