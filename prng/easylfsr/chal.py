import os
from itertools import cycle

class LFSR:
    def __init__(self, taps, mod=1283):
        self.mod = mod
        self.state = [int.from_bytes(os.urandom(2), 'big') % mod for _ in range(32)]
        self.taps = [t % mod for t in taps]

    def step(self):
        new_val = sum(s * t for s, t in zip(self.state, self.taps)) % self.mod
        self.state = self.state[1:] + [new_val]
        return new_val

    def generate(self, n):
        return [self.step() for _ in range(n)]

    def generate_key(self, n):
        return [self.step()&0xff for _ in range(n)]

def xor(b1: bytes, b2: bytes):
    return bytes([x ^ y for x, y in zip(b1, cycle(b2))])

taps = [19, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 7, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]
l = LFSR(taps)
flag = b'TEST_FLAG' # without AIS3{.*} for this flag

assert len(flag) == 45

with open('out.txt', 'wb') as f:
    f.write(xor(l.generate_key(1000000), flag))
