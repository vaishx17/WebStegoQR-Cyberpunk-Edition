
from flask import Flask, render_template, request, send_file, jsonify
import qrcode
import base64
from io import BytesIO
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
app = Flask(__name__)
# Encryption function
def encrypt_data(data, key):
    if len(key) != 8:
        return None, "Encryption key must be exactly 8 characters long."
    key = key.encode('utf-8').ljust(16, b'\0')  # Pad to 16 bytes
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])  # IV must be 16 bytes
    encrypted_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    encrypted_text = base64.b64encode(encrypted_bytes).decode()
    return encrypted_text, None
# Decryption function
def decrypt_data(encrypted_data, key):
    if len(key) != 8:
        return None, "Decryption key must be exactly 8 characters long."
    try:
        key = key.encode('utf-8').ljust(16, b'\0')  # Pad to 16 bytes
        cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])  # IV must be 16 bytes
        decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size)
        return decrypted_bytes.decode(), None
    except Exception:
        return None, "Invalid decryption key"
@app.route('/')
def index():
    return render_template('indexqr.html')
# 🔹 Fix: `/encrypt` now correctly gets `key` from the frontend
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.form['data']
    encryption_key = request.form['key']  # Changed from `encryption_key`
    encrypted_data, error = encrypt_data(data, encryption_key)
    if error:
        return jsonify({"error": error}), 400
    # Generate QR Code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(encrypted_data)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img_io = BytesIO()
    img.save(img_io, format="PNG")
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')
# 🔹 Fix: Renamed `/decrypt` to `/decrypt_qr`
@app.route('/decrypt_qr', methods=['POST'])
def decrypt_qr():
    encrypted_data = request.form['encrypted_data']  # Received from frontend
    decryption_key = request.form['key']  # Changed to match frontend
    decrypted_text, error = decrypt_data(encrypted_data, decryption_key)
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"decrypted_text": decrypted_text})
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000, debug=True)
