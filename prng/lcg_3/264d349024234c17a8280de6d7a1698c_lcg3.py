import os
from flags import flag5 as flag
from Crypto.Util.number import getPrime

p = 2**255 - 19
a, b = 0x120, 0x1337

def lcg(x):
    return (a*x + b) % p

seed = int.from_bytes(os.urandom(32), 'little')
cur = lcg(seed)

while input("> ") == 'next':
    print("now:", cur>>32)
    cur = lcg(cur)

if int(input("ans: ")) == cur:
    print(flag)

else:
    print("failed qwq")
