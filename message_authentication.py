import hmac
import hashlib
import os

def generate_symmetric_key(key_length):
    return os.urandom(key_length // 8)  

def generate_hmac(key, message):
    hmac_digest = hmac.new(key, message, hashlib.sha256).digest()
    return hmac_digest

K2 = generate_symmetric_key(256)

text_message = b"Hi! Ipek, Enes and Gorkem worked on this project!"

hmac_digest = generate_hmac(K2, text_message)

print("Symmetric Key (K2, 256-bit):", K2.hex())
print("Text Message:", text_message.decode())
print("HMAC-SHA256:", hmac_digest.hex())
