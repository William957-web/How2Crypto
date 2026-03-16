from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
from flags import flag6 as flag
import os

IV = os.urandom(8)


def xor(a, b):
    return bytes(x ^ y for x,y in zip(a, b * (1 + len(a) // len(b))))


def encrypt(key, plaintext):
    try:
        plaintext = xor(plaintext, IV)
        
        cipher = DES3.new(key, DES3.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = xor(ciphertext, IV)
        
        return ciphertext.hex()
    except:
        return 'Error'

print('You are the key man <3')
key = bytes.fromhex(input('> '))
print(encrypt(key, pad(flag, 8)))
print('Give u a gift')

while True:
    key = bytes.fromhex(input('(key)> '))
    plaintext = bytes.fromhex(input('(ctx)> '))
    print(encrypt(key, plaintext))
