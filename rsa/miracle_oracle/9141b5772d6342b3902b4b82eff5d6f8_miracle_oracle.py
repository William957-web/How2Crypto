from Crypto.Util.number import *
from flags import flag2 as flag

p, q = getPrime(1024), getPrime(1024)
N = p*q
e = 0x10001
d = inverse(e, (p-1) * (q-1))
c = pow(bytes_to_long(flag), e, N)
print(f"{N=}\n{c=}")

while True:
    new_c = int(input("> "))
    print(f"< {pow(new_c, d, N) & 1}")
