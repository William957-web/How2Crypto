import os
import hashlib
from Crypto.Cipher import ChaCha20_Poly1305
from flags import flag5 as flag

key = os.urandom(32)
nonce = os.urandom(12)

def encrypt(message):
   cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
   ciphertext, tag = cipher.encrypt_and_digest(message)
   return ciphertext + tag + nonce

def decrypt(message_enc):
   ciphertext = message_enc[:-28]
   tag = message_enc[-28:-12]
   nonce = message_enc[-12:]
   cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
   plaintext = cipher.decrypt_and_verify(ciphertext, tag)
   return plaintext

menu = [b"Mixtured curry with rice - 120 TWD", 
b"\"Automated\" Cafe Mocha - 45 TWD",
b"Secret FLAG :>"]

print('=' * 20, ' W3lcome 2 ENC Restaurant ', '='*20)
print('=' * 30, ' M3NU ', '=' * 30)

for i in range(2):
    print('> ', encrypt(menu[i]).hex())

print('=' * 24, ' 3RR: menu broken ', '=' * 24)

patch = input('> ')
if menu[2] in decrypt(bytes.fromhex(patch)):
    print(flag)

else:
    print('=' * 24, 'Recovery Failed :<', '=' * 24)
