# Prepend Oracle Attack
import os
from Crypto.Cipher import AES
from flags import flag2

# Initial datas
key=os.urandom(16)
aes=AES.new(key, AES.MODE_ECB)

# PKCS #7
def pad(data):
    return data+bytes([-len(data)%16]*(-len(data)%16))

# Main Function
if __name__=='__main__':
    print('=== Super Signer ===')
    while True:
        data=input('Input you message (hex) >')
        signed=aes.encrypt(pad(bytes.fromhex(data)+flag2))
        print(f"Signed:{signed.hex()}")