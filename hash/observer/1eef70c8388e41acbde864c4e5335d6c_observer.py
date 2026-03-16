from itertools import cycle
from hashlib import md5
from flags import flag2 as flag

# Make sure you nc first, flag length and leakage matters!

print("Yep, I know supporting my self with my secret is a bad idea ...")
print("Though, I showed you my secert, didn'y u get it? That's not that hard babe")
print("Just ... nvm, it's too hard to say that for me ... now ... will I regret?")
print("I'll give you a piece of gift!")
print(flag.decode()[:7], len(flag))

def xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

while True:
    msg = input("> ")
    msg = bytes.fromhex(msg)
    msg = msg.ljust(len(flag))
    print('<', md5(xor(msg, cycle(flag))).hexdigest())
