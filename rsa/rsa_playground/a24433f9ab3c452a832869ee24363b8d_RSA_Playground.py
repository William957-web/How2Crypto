from Crypto.Util.number import *
flag1=b'REMOVED FLAG'
flag2=b'REMOVED FLAG'
flag3=b'REMOVED FLAG'
flag=flag1+flag2+flag3
print(flag)
c1=bytes_to_long(flag1)
c2=bytes_to_long(flag2)
c3=bytes_to_long(flag3)

def stage1(c):
    p, q=getPrime(512), getPrime(512)
    n=p*q
    e=3
    c=pow(c, e, n)
    print('----------------------------stage1------------------------------')
    print(f'n:{n}')
    print(f'c:{c}')
    print(f'e:{e}')

def stage2(c):
    p=getPrime(128)
    q=p+1
    while isPrime(q)==False:
        q=q+1 #q will be the next prime number after p
    n=p*q
    e=65537
    c=pow(c, e, n)
    print('----------------------------stage2------------------------------')
    print(f'n:{n}')
    print(f'c:{c}')
    print(f'e:{e}')

def stage3(c):
    p, q=getPrime(512), getPrime(512)
    n=p*q
    d=getPrime(200)
    e=inverse(d, (p-1)*(q-1))
    c=pow(c, e, n)
    print('----------------------------stage3------------------------------')
    print(f'n:{n}')
    print(f'c:{c}')
    print(f'e:{e}')

stage1(c1)
stage2(c2)
stage3(c3)