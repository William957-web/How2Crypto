from hashlib import md5
import os
from flags import flag3 as flag

print("U have 1 min, gogo!")

for i in range(20):
    key = os.urandom(16)
    print(key.hex())
    msg1 = input('1> ')
    msg1 = bytes.fromhex(msg1)
    msg2 = input('2> ')
    msg2 = bytes.fromhex(msg2)
    if key in msg1 and key in msg2 and msg1!=msg2 and md5(msg1).hexdigest() == md5(msg2).hexdigest():
        print('AC')
    else:
        print('WA')
        exit()

print(flag.decode())
