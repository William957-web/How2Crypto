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

p = 539886463685170284852407443970056803194248989742398797294074913090310265582980509535654551509645984788215337814031007413437004302678083874517375765338325720828816975723039
g = 2
A = random.getrandbits(512)
pA = pow(g, A, p)
print(f"{p=}\n{g=}\n{pA=}")

B = random.getrandbits(512)
pB = pow(g, B, p)
print(f"{pB=}")
enc, IV = encrypt(pow(pB, A, p), flag2)
enc, IV = enc.hex(), IV.hex()
print(f"enc: {enc}\niv: {IV}")
