from flags import flag8 as flag
from Crypto.Cipher import AES
from time import time
import os
from hashlib import md5

class CFB8:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        IV = urandom(16)
        cipher = AES.new(self.key, AES.MODE_ECB)
        ct = b''
        state = IV
        for i in range(len(plaintext)):
            b = cipher.encrypt(state)[0]
            c = b ^ plaintext[i]
            ct += bytes([c])
            state = state[1:] + bytes([c])
        return IV + ct

    def decrypt(self, ciphertext):
        IV = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_ECB)
        pt = b''
        state = IV
        for i in range(len(ct)):
            b = cipher.encrypt(state)[0]
            c = b ^ ct[i]
            pt += bytes([c])
            state = state[1:] + bytes([ct[i]])
        return pt

print("Welcome to the MeowcroSoft login portal 🐾")
admin_password = os.urandom(16)

while True:
    cur_time = str(time())
    print(f"Current TimeStamp: {cur_time}")
    client_challenge = bytes.fromhex(input("Challenge: "))
    if len(client_challenge) != 32:
        print("Error: incorrect client challenge length")
        continue
    
    cipher = CFB8(md5(cur_time.encode() + admin_password).digest())
    client_token = cipher.decrypt(client_challenge)
    input_token = bytes.fromhex(input("Token: "))
    if client_token == input_token:
        print(f"Welcome, admin\n{flag}")
    else:
        print("Login Failed QwQ")
