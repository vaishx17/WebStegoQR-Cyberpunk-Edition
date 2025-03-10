
import os
import base64
import qrcode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
with open("backend/aes_key.txt", "rb") as key_file:
    aes_key = key_file.read()

def encrypt_message(message, key):
    # Apply PKCS7 padding to make the message a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    # Generate a random 16-byte IV (Initialization Vector)
    iv = os.urandom(16)
    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt message
    encrypted_bytes = encryptor.update(padded_message) + encryptor.finalize()
    # Encode IV + encrypted message in Base64 for safe storage
    encrypted_b64 = base64.b64encode(iv + encrypted_bytes).decode()
    
    return encrypted_b64
def generate_qr(encrypted_data, filename="static/qr_codes/encrypted_qr.png"):
    # Ensure the directory exists
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4
    )
    
    qr.add_data(encrypted_data)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    img.save(filename)
    
    print(f"✅ QR Code saved at: {filename}")
    return filename  # Return the path to the saved QR code
if __name__ == "__main__":
    test_message = "Hello, this is a test message!"
    encrypted_text = encrypt_message(test_message, aes_key)
    print("🔒 Encrypted Message:", encrypted_text)
    
    qr_path = generate_qr(encrypted_text)
    print("✅ QR Code generated:", qr_path)
