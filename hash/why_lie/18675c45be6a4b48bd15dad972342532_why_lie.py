from hashlib import md5
from flags import flag1 as flag
import os

salt = os.urandom(16)

banner = """================== WHALE MSG SYSTEM v0.5 ==================
QUOTE: year by year ... 3 years ... 6 years ... it doesn't matter but you have to sign to prove this time

COMMANDS:
- SIGN
- SEND
"""

print(banner)

while True:
    cmd = input("CMD > ")
    if cmd == 'SIGN':
        content = input("MSG > ")
        content = bytes.fromhex(content)
        if b'meet me next wednesday' not in content:
            print(md5(salt + content).hexdigest())
        else:
            print("ERROR, BAD HACKER")
    
    elif cmd == 'SEND':
        content = input("MSG > ")
        content = bytes.fromhex(content)
        signature = input("SIG > ")
        if signature == md5(salt + content).hexdigest():
            print("GOOD, I've READ IT")
            if b'meet me next wednesday' in content:
                print(flag.decode())
        else:
            print("SORRY ... I can't believe u")
