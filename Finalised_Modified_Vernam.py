import random
import string
import hashlib
#generating random key
def generate_key(length):
    return  ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

#getting a key from the user

def get_key_from_user(length, passphrase):
        temp_hash=hashlib.sha256(passphrase.encode())
        Key_hash=temp_hash.hexdigest()
        key_matrix = [Key_hash[i:i+length] for i in range(0, len(Key_hash), 8)]
        transposed_key = ''.join([''.join(row) for row in zip(*key_matrix)])
        # Appending the string to make up to the  required length
        while len(transposed_key) < length:
            transposed_key += transposed_key
            transposed_key[:length]
        if len(transposed_key)>length:
             transposed_key[:length]
        
        return transposed_key

def vernam_encrypt(plaintext, key):
     ciphertext = ''
     for i in range(len(plaintext)):
        char = plaintext[i]
        key_char = key[i]
        if char.isalpha():  # Encrypt only alphabetic characters
            shift = ord('A') if char.isupper() else ord('a')
            ciphertext += chr((ord(char) - shift + ord(key_char) - shift) % 26 + shift)
        else:
            ciphertext += char

     return ciphertext
def vernam_decrypt(ciphertext, key):
    plaintext = ''
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        key_char = key[i]
        if char.isalpha():  # Decrypt only alphabetic characters
            shift = ord('A') if char.isupper() else ord('a')
            plaintext += chr((ord(char) - shift - (ord(key_char) - shift) + 26) % 26 + shift)
        else:
            plaintext += char

    return plaintext

"""
passphrase=input("Enter your Passphrase to Generate :")
plaintext=input("Enter the plaintext to be encrypted: ")
Encrypted_Text=vernam_encrypt(plaintext,passphrase)
print("Your Encrypted text is :\n",Encrypted_Text)
ciphertext=input("Enter the Cipher text to be decrypted: ")
Decrypted_Text=vernam_decrypt(ciphertext,passphrase)
print("Your Decrypted Text is: \n",Decrypted_Text)
"""