from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import *
from hashlib import sha256
import os, random
from flags import flag1

def encrypt(key, msg):
    key = sha256(str(key).encode()).digest()[:16]
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(msg, 16)), iv

p = getPrime(512)
g = 2
A = random.getrandbits(512)
pA = pow(g, A, p)
print(f"{p=}\n{g=}\n{pA=}")

pB = int(input("pB: "))
enc, IV = encrypt(pow(pB, A, p), flag1)
enc, IV = enc.hex(), IV.hex()
print(f"enc: {enc}\niv: {IV}")
