from jwtlib import JWTError, encode_token, hs256_sign, parse_token, rs256_verify
from secrets import FLAG4


FLAG = FLAG4
PRIVATE_KEY_FILE = "keys/level4_private.pem"
PUBLIC_KEY_FILE = "keys/level4_public.pem"


def issue_guest_token():
    return encode_token({"user": "guest"}, PRIVATE_KEY_FILE, alg="RS256")


def public_key_text():
    with open(PUBLIC_KEY_FILE, "r", encoding="utf-8") as handle:
        return handle.read()


def verify(token):
    header, payload, signing_input, signature = parse_token(token)
    alg = header.get("alg")
    pem_data = open(PUBLIC_KEY_FILE, "rb").read()

    if alg == "HS256":
        expected = hs256_sign(signing_input, pem_data)
        if signature != expected:
            raise JWTError("bad signature")
        return payload

    if alg == "RS256":
        if not rs256_verify(signing_input, signature, PUBLIC_KEY_FILE):
            raise JWTError("bad signature")
        return payload

    raise JWTError("unsupported algorithm")


def source_for_display():
    with open(__file__, "r", encoding="utf-8") as handle:
        return handle.read()
