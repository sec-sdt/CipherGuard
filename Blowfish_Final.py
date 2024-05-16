from Crypto.Cipher import Blowfish
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import random
import string

def generate_key(length):
    """
    Generates a random key of given length.
    """
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def derive_key_and_iv(passphrase, salt):
    # Derive a key and IV from the passphrase using PBKDF2
    key_iv = PBKDF2(passphrase, salt, dkLen=16, count=1000, hmac_hash_module=SHA256)
    key = key_iv[:8]
    iv = key_iv[8:]
    return key, iv

def encrypt_blowfish_cbc(plaintext, passphrase):
    salt = get_random_bytes(16)  # Generate a random salt
    key, iv = derive_key_and_iv(passphrase.encode(), salt)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    ciphertext = salt + cipher.encrypt(plaintext)
    return ciphertext

def decrypt_blowfish_cbc(ciphertext, passphrase):
    salt = ciphertext[:16]  # Extract the salt from the ciphertext
    ciphertext = ciphertext[16:]
    key, iv = derive_key_and_iv(passphrase.encode(), salt)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    return decrypted_text.decode()

"""

# Example usage
user_passphrase = input("Enter a passphrase: ")
plaintext = input("Enter the plaintext: ")

# Pad the plaintext if needed
plaintext = pad(plaintext.encode(), Blowfish.block_size)

# Encrypt using CBC mode
encrypted_text = encrypt_blowfish_cbc(plaintext, user_passphrase)

# Decrypt using CBC mode
decrypted_text = decrypt_blowfish_cbc(encrypted_text, user_passphrase)

# Print results
print("Plaintext:", plaintext.decode())
print("Encrypted Text (CBC):", encrypted_text.hex())
print("Decrypted Text (CBC):", decrypted_text)

"""
