# Bit Flipping Attack
import os
from Crypto.Cipher import AES
from flags import flag3

# Initial datas
key, iv=os.urandom(16), os.urandom(16)

def encrypt(data):
    aes=AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(data)

def decrypt(data):
    aes=AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(data)

# Main Function
if __name__=='__main__':
    print('=== One Shot ===')
    print('Change the first block into wha13.github.io/')
    chal=os.urandom(32)
    print(f'Original Message:{chal.hex()}')
    print(f'Encrypted:{encrypt(chal).hex()}')
    shot=input('One Shot >')
    result=decrypt(bytes.fromhex(shot))
    if b'wha13.github.io/' in result:
        print(flag3)
    else:
        print('Failed...')