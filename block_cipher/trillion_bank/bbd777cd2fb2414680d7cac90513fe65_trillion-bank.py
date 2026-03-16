# Cut & Paste Attack
import os
from Crypto.Cipher import AES
from flags import flag1

# Initial datas
trillion=1000000000000000000
key=os.urandom(16)
aes=AES.new(key, AES.MODE_ECB)
funclist="""1. Create an acount
2. Login with session
"""

# PKCS #7
def pad(data):
    return data+bytes([-len(data)%16]*(-len(data)%16))

def unpad(data):
    padlen=int(data[-1])
    if padlen<=15 and bytes([data[-1]])*padlen==data[-padlen:]:
        return data[:-padlen]
    else:
        return data

# Parser
def parse(data):
    parts=data.split(';')
    if len(parts) != 2:
        print('[!] Parsing Error')
        exit()
    
    else:
        name=parts[0].split(':')[1]
        amount=parts[1].split(':')[1]
        return {'user':name, 'amount':int(amount)}

# Main Function
if __name__=='__main__':
    print('=== Welcom to Trillion Bank ===')
    while True:
        print('How can I help you today?')
        print(funclist)
        option=input("Your option (1/2): ")
        if option != '1' and option != '2':
            print('Bye bye~')
            exit()
        elif option == '1':
            name=input('Your name:')
            data='user:'+name+';amount:10'
            print(aes.encrypt(pad(data.encode())).hex())
        else:
            session=input('Session:')
            session=bytes.fromhex(session)
            data=parse(unpad(aes.decrypt(session)).decode())
            print(f"Your account info: {data}")
            if data['amount']>trillion:
                print(flag1)
            else:
                print("I don't have anything for you!")