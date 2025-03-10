import base64

with open("backend/secret.key", "rb") as f:
    key = f.read()

print("Base64 Key:", base64.b64encode(key).decode())
