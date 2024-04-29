from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from PIL import Image
import os

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def calculate_image_hash(image_file):
    with open(image_file, 'rb') as f:
        image_data = f.read()
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(image_data)
    image_hash = hasher.finalize()
    return image_hash

def sign_data(private_key, data):
    signature = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return signature

def verify_signature(public_key, signature, data):
    try:
        public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except:
        return False

image_file = "logo.jpg"  
image_hash = calculate_image_hash(image_file)

private_key, public_key = generate_rsa_key_pair()

signature = sign_data(private_key, image_hash)

verification_result = verify_signature(public_key, signature, image_hash)

print("Image Hash (H(m)): ", image_hash.hex())
print("Digital Signature: ", signature.hex())
print("Verification Result: ", verification_result)
