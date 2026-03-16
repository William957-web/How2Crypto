from random import getrandbits
from flags import flag3 as flag

while input("> ") == "next":
    print("next:", getrandbits(128))

if int(input("ans: ")) == getrandbits(128):
    print(flag)
