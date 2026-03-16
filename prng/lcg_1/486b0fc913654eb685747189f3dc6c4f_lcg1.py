import os
from flags import flag1 as flag

p = 2**255 - 19
a, b = 0x120, 0x1337

def lcg(x):
    return (a*x + b) % p

seed = int.from_bytes(os.urandom(32), 'little')
cur = lcg(seed)
print("now:", cur)
cur = lcg(cur)

if int(input("ans: ")) == cur:
    print(flag)

else:
    print("failed qwq")
