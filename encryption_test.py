from backend.encryption import encrypt_data
from backend.decryption import decrypt_data

key = "my_secure_key_16"
plaintext = "Hello, Cyberpunk!"

encrypted_text = encrypt_data(plaintext, key)
print("Encrypted:", encrypted_text)

decrypted_text = decrypt_data(encrypted_text, key)
print("Decrypted:", decrypted_text)
