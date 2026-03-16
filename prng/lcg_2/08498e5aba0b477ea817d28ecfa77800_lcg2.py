import os
from flags import flag2 as flag
from Crypto.Util.number import getPrime

p = getPrime(256)
a, b = 0x120, 0x1337

def lcg(x):
    return (a*x + b) % p

seed = int.from_bytes(os.urandom(32), 'little')
cur = lcg(seed)

while input("> ") == 'next':
    print("now:", cur)
    cur = lcg(cur)

if int(input("ans: ")) == cur:
    print(flag)

else:
    print("failed qwq")
