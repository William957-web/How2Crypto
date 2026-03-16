from Crypto.Util.number import *
flag=b'SECRET{SECRET_SECRET_SECRET}'
a=1004
b=120
m1=bytes_to_long(flag)
m2=a*m1+b
p, q=getPrime(1024), getPrime(1024)
e=7
n=p*q
c1=pow(m1, e, n)
c2=pow(m2, e, n)
print(f"{e=}\n{n=}\n{a=}\n{b=}\n{c1=}\n{c2=}")