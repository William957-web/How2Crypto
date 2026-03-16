from random import randint
from hashlib import sha256
FLAG=b'NCKUCTF{FAKE!!!}'
def xor(b1: bytes, b2: bytes):
    return bytes([x ^^ y for x, y in zip(b1, b2)])

p = 2557088666494490131660800000000000001
a = 1323879184140127113148715489137793
b = 1413453335371254304533447979395016
E = EllipticCurve(GF(p), [a, b])
G = E.gens()[0]
kirby_secret, system_secret = randint(1, E.order()-1), randint(1, E.order()-1)
kirby_public, system_public = G*kirby_secret, G*system_secret
print(f">> System: {G.xy()}")
print(f">> Kirby: {kirby_public.xy()}")
print(f">> System: {system_public.xy()}")
key = system_secret*kirby_public.xy()[0]
key = sha256(str(key).encode()).digest()
print(f">> Kirby: {xor(key, FLAG).hex()}")

'''
>> System: (641747663469961782999122163178770355, 1089889755501076444972858180314593563)
>> Kirby: (758959419335830375195380373138541878, 1519088632765340280491220856568511255)
>> System: (2092611384277986804207595009723692543, 1074363320747067198658898006283242194)
>> Kirby: 262b810a9674462059433c94274c0196e2c97b9ce6b1495461dacff50d786e76
'''
