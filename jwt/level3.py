from jwtlib import JWTError, encode_token, hs256_sign, parse_token
from secrets import FLAG3


FLAG = FLAG3
DEFAULT_KEYFILE = "keys/level3_secret.txt"


def issue_guest_token():
    return encode_token({"user": "guest"}, read_secret(DEFAULT_KEYFILE), alg="HS256", headers={"kid": DEFAULT_KEYFILE})


def read_secret(key_file):
    with open(key_file, "rb") as handle:
        return handle.read()


def verify(token):
    header, payload, signing_input, signature = parse_token(token)
    if header.get("alg") != "HS256":
        raise JWTError("only HS256 is accepted")

    key_file = header.get("kid", DEFAULT_KEYFILE)
    secret = read_secret(key_file)
    expected = hs256_sign(signing_input, secret)
    if signature != expected:
        raise JWTError("bad signature")
    return payload


def source_for_display():
    with open(__file__, "r", encoding="utf-8") as handle:
        return handle.read()
