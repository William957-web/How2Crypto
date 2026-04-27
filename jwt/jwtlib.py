import base64
import hashlib
import hmac
import json
import os
import subprocess
import tempfile


class JWTError(Exception):
    pass


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data):
    if isinstance(data, str):
        data = data.encode("ascii")
    padding = b"=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + padding)
    except Exception as exc:
        raise JWTError("invalid base64") from exc


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def json_loads(raw):
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise JWTError("invalid json") from exc


def parse_token(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTError("token must have 3 segments")
    header_raw, payload_raw, signature_raw = parts
    header = json_loads(b64url_decode(header_raw))
    payload = json_loads(b64url_decode(payload_raw))
    signing_input = f"{header_raw}.{payload_raw}".encode("ascii")
    signature = b64url_decode(signature_raw)
    return header, payload, signing_input, signature


def hs256_sign(message, secret):
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).digest()


def rs256_sign(message, private_key_path):
    return _openssl_sign(message, ["openssl", "dgst", "-sha256", "-sign", private_key_path])


def rs256_verify(message, signature, public_key_path):
    with tempfile.NamedTemporaryFile(delete=False) as data_file, tempfile.NamedTemporaryFile(delete=False) as sig_file:
        data_file.write(message)
        sig_file.write(signature)
        data_path = data_file.name
        sig_path = sig_file.name
    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", public_key_path, "-signature", sig_path, data_path],
            capture_output=True,
            check=False,
            text=True,
        )
        return result.returncode == 0 and "Verified OK" in result.stdout
    finally:
        os.unlink(data_path)
        os.unlink(sig_path)


def _openssl_sign(message, command):
    with tempfile.NamedTemporaryFile(delete=False) as data_file:
        data_file.write(message)
        data_path = data_file.name
    try:
        result = subprocess.run(command + [data_path], capture_output=True, check=False)
        if result.returncode != 0:
            raise JWTError(result.stderr.decode("utf-8", errors="ignore") or "openssl sign failed")
        return result.stdout
    finally:
        os.unlink(data_path)


def encode_token(payload, key, alg="HS256", headers=None):
    header = {"typ": "JWT", "alg": alg}
    if headers:
        header.update(headers)
    header_raw = b64url_encode(json_bytes(header))
    payload_raw = b64url_encode(json_bytes(payload))
    signing_input = f"{header_raw}.{payload_raw}".encode("ascii")

    if alg == "none":
        signature = b""
    elif alg == "HS256":
        signature = hs256_sign(signing_input, key)
    elif alg == "RS256":
        signature = rs256_sign(signing_input, key)
    else:
        raise JWTError(f"unsupported alg: {alg}")

    return f"{header_raw}.{payload_raw}.{b64url_encode(signature)}"
