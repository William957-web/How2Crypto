import os
from flags import flag

def xor(enc, keystream):
    return bytes([b1 ^ b2 for b1, b2 in zip(enc, keystream)])

key = os.urandom(16)
msg = b'cat eat subway!!'


print(xor(msg, key).hex())
print(xor(flag, key).hex())

'''
Output:
d282a15fb7ae1ac91f95f4ee33cf2233
f7af9438a9b7019b3398f9eb0d8b336f
'''
