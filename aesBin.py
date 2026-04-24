import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
import hashlib

def AESencrypt(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, key

def writeResultToFiles(key, ciphertext):
    # Write the cipher text to cipher.bin
    with open("cipher.bin", "wb") as cipher_file:
        cipher_file.write(ciphertext)
    
    # Write the key to key.bin
    with open("key.bin", "wb") as key_file:
        key_file.write(key)

try:
    with open(sys.argv[1], "rb") as file:
        content = file.read()
    KEY = urandom(16)
    ciphertext, key = AESencrypt(content, KEY)
    writeResultToFiles(KEY, ciphertext)
    print("Encryption successful. Files 'cipher.bin' and 'key.bin' have been created.")
except Exception as e:
    print("Error:", e)
    sys.exit()
