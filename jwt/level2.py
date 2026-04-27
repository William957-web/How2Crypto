from jwtlib import JWTError, encode_token, hs256_sign, parse_token
from secrets import FLAG2


FLAG = FLAG2
SECRET = "1001"


def issue_guest_token():
    return encode_token({"user": "guest"}, SECRET, alg="HS256")


def verify(token):
    header, payload, signing_input, signature = parse_token(token)
    if header.get("alg") != "HS256":
        raise JWTError("only HS256 is accepted")

    expected = hs256_sign(signing_input, SECRET)
    if signature != expected:
        raise JWTError("bad signature")
    return payload


def source_for_display():
    with open(__file__, "r", encoding="utf-8") as handle:
        source = handle.read()
    return source.replace('SECRET = "1001"', 'SECRET = "REDACTED"')
