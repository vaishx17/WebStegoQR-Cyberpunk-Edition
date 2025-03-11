from flask import Flask, render_template, request, send_file, jsonify
import qrcode
from io import BytesIO
from backend.crypto_utils import encrypt_message, decrypt_message  # Import updated functions

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('indexqr.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.form['data']
    user_key = request.form['key']  # Get user-provided key

    try:
        encrypted_data = encrypt_message(data, user_key)  # Pass user key
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

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

@app.route('/decrypt_qr', methods=['POST'])
def decrypt_qr():
    encrypted_data = request.form['encrypted_data']  # Data from frontend
    user_key = request.form['key']  # User-provided key

    try:
        decrypted_text = decrypt_message(encrypted_data, user_key)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "Invalid decryption key"}), 400

    return jsonify({"decrypted_text": decrypted_text})

if __name__ == '__main__':
    app.run(debug=True)
