from Crypto.Util.number import *
p, q=getPrime(1024), getPrime(1024)
n=p*q
e=65537
flag=b"ICED{REDACTED}"
m=bytes_to_long(flag)
c=pow(m, e, n)
p0=p-(p%2**128)
print(f"{c=}\n{e=}\n{n=}\n{p0=}")