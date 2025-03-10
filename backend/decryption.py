
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import cv2
import pyzbar.pyzbar as pyzbar
def decrypt_message(encrypted_b64, key):
    # Decode Base64
    encrypted_bytes = base64.b64decode(encrypted_b64)
    # Extract IV and encrypted data
    iv = encrypted_bytes[:16]
    encrypted_data = encrypted_bytes[16:]
    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Decrypt message
    decrypted_bytes = decryptor.update(encrypted_data) + decryptor.finalize()
    # Remove padding (trailing spaces)
    decrypted_message = decrypted_bytes.decode().rstrip()
    return decrypted_message
def scan_qr_and_decrypt(image_path, key):
    img = cv2.imread(image_path)
    detected_qrcodes = pyzbar.decode(img)
    if not detected_qrcodes:
        return "No QR code found!"
    encrypted_text = detected_qrcodes[0].data.decode("utf-8")
    
    try:
        decrypted_message = decrypt_message(encrypted_text, key)
        return decrypted_message
    except Exception as e:
        return f"Decryption failed: {str(e)}"
if __name__ == "__main__":
    # Load AES key from file
    with open("backend/aes_key.txt", "rb") as key_file:
        aes_key = key_file.read()
    # Ask user for QR code image path
    image_path = input("Enter the path of the QR code image: ")
    # Scan QR and decrypt
    decrypted_message = scan_qr_and_decrypt(image_path, aes_key)
    print("Decrypted Message:", decrypted_message)
