# Padding Oracle Attack
import os
from Crypto.Cipher import AES
from flags import flag4

# Initial datas
key=os.urandom(16)

def encrypt(IV, data):
    aes=AES.new(key, AES.MODE_CBC, IV)
    return aes.encrypt(data)

def decrypt(IV, data):
    aes=AES.new(key, AES.MODE_CBC, IV)
    return aes.decrypt(data)

# PKCS #7
def pad(data):
    padlen=16-len(data)%16
    return data+bytes([padlen]*padlen)

def unpad(data):
    padlen=int(data[-1])
    if not (bytes([data[-1]])*padlen==data[-padlen:]):
        raise ValueError
    else:
        return data[:-padlen]

if __name__=='__main__':
    print("=== Psychic Message ===")
    print("I would like to listen to you ... if you break my flag ...")
    cur_iv=os.urandom(16)
    print(f"Encrypted Flag:{cur_iv.hex()+encrypt(cur_iv, pad(flag4)).hex()}")
    while True:
        msg=input("Your Message (hex) >")
        msg=bytes.fromhex(msg)
        try:
            unpad(decrypt(msg[:16], msg[16:]))
            print('I got that message!')
        except ValueError:
            print('What were you talking about?')