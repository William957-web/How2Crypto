from secrets import randbits
from math import floor
from hashlib import sha256

class LFSR:
    def __init__(self, key, taps, format):
        self.key = key
        self.taps = taps
        self.state = list(map(int, list(format.format(key))))
    
    def _clock(self):
        ob = self.state[0]
        self.state = self.state[1:] + [sum([self.state[t] for t in self.taps]) % 2]
        return ob

def xnor_gate(a, b):
    if a == 0 and b == 0:
        return 1
    elif a == 0 and b == 1:
        return 0
    elif a == 1 and b == 0:
        return 0
    else:
        return 1

key1 = randbits(21)
key2 = randbits(29)
L1 = LFSR(key1, [2, 4, 5, 1, 7, 9, 8], "{:021b}")
L2 = LFSR(key2, [5, 3, 5, 5, 9, 9, 7], "{:029b}")

bits = [xnor_gate(L1._clock(), L2._clock()) for _ in range(floor(72.7))]
print(bits)

FLAG = open("flag.txt", "rb").read()
keystream = sha256((str(key1) + str(key2)).encode()).digest() * 2
print(bytes([b1 ^ b2 for b1, b2 in zip(FLAG, keystream)]).hex())

