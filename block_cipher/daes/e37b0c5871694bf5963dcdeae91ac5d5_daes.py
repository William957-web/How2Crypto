from Crypto.Cipher import AES
import random
import os
import signal
from flags import flag7 as flag

TIMEOUT = 900

def timeout_handler(signum, frame):
    print("\nTime's up! No flag for u...")
    exit()

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(TIMEOUT)

target = os.urandom(16)

keys = [b'whalekey:' + str(random.randrange(1000000, 1999999)).encode() for _ in range(2)]

def enc(key, msg):
    ecb = AES.new(key, AES.MODE_ECB)
    return ecb.encrypt(msg)

def daes(msg):
    tmp = enc(keys[0], msg)
    return enc(keys[1], tmp)

test = b'you are my fire~'
print(daes(test).hex())
print(daes(target).hex())

ans = input("Ans:")

if ans == target.hex():
    print(flag)
else:
    print("Nah, no flag for u...")

signal.alarm(0)
