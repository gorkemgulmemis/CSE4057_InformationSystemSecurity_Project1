from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

# RSA Key Generation
def generate_rsa_keys(key_size=1024):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Save keys to files
def save_keys_to_file(private_key, public_key, private_file_name, public_file_name):
    with open(private_file_name, 'wb') as priv_file:
        priv_file.write(private_key)
    with open(public_file_name, 'wb') as pub_file:
        pub_file.write(public_key)

# ECDH Key Generation
def generate_ecdh_keys(curve='P-384'):
    private_key = ECC.generate(curve=curve)
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt and decrypt functions using RSA
def encrypt_with_rsa(public_key, message):
    rsa_public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_public_key)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message

def decrypt_with_rsa(private_key, encrypted_message):
    rsa_private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message

# Main execution
if __name__ == '__main__':
    # RSA Key Pair Generation
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    save_keys_to_file(rsa_private_key, rsa_public_key, 'rsa_private.pem', 'rsa_public.pem')
    
    # ECDH Key Pair Generation
    ecdh_private_key1, ecdh_public_key1 = generate_ecdh_keys()
    ecdh_private_key2, ecdh_public_key2 = generate_ecdh_keys()
    
    # Symmetric Key Generation
    symmetric_key1 = get_random_bytes(16)  # 128 bit
    symmetric_key2 = get_random_bytes(32)  # 256 bit
    
    # Encrypt and Decrypt Symmetric Keys with RSA
    encrypted_key1 = encrypt_with_rsa(rsa_public_key, symmetric_key1)
    decrypted_key1 = decrypt_with_rsa(rsa_private_key, encrypted_key1)
    
    encrypted_key2 = encrypt_with_rsa(rsa_public_key, symmetric_key2)
    decrypted_key2 = decrypt_with_rsa(rsa_private_key, encrypted_key2)
    
    # Print the results
    print(f'Encrypted Key 1: {encrypted_key1}')
    print('******************************************')
    print(f'Decrypted Key 1: {decrypted_key1}')
    print('******************************************')
    print(f'Encrypted Key 2: {encrypted_key2}')
    print('******************************************')
    print(f'Decrypted Key 2: {decrypted_key2}')
    print('******************************************')
