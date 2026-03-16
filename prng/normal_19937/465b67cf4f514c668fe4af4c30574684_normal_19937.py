from random import getrandbits
from flags import flag4 as flag

while input("> ") == "next":
    print("next:", getrandbits(1337))

if int(input("ans: ")) == getrandbits(1337):
    print(flag)
