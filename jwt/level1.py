from jwtlib import JWTError, encode_token, hs256_sign, parse_token
from secrets import FLAG1


FLAG = FLAG1
SECRET = "level1-development-secret"


def issue_guest_token():
    return encode_token({"user": "guest"}, SECRET, alg="HS256")


def verify(token):
    header, payload, signing_input, signature = parse_token(token)
    alg = header.get("alg", "HS256")

    if alg == "none":
        return payload

    if alg != "HS256":
        raise JWTError("unsupported algorithm")

    expected = hs256_sign(signing_input, SECRET)
    if signature != expected:
        raise JWTError("bad signature")
    return payload


def source_for_display():
    with open(__file__, "r", encoding="utf-8") as handle:
        return handle.read()
