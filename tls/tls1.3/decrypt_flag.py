#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256, SHA384
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from scapy.all import IP, TCP, PcapReader

PCAP_PATH = "___FILL_ME___"
CLIENT_RANDOM = "___FILL_ME___"
SERVER_TRAFFIC_SECRET_0 = "___FILL_ME___"
SERVER_PORT = 443

CIPHER_SUITES = {
    0x1301: {"hash": SHA256, "key_len": 16, "aead": AESGCM},
    0x1302: {"hash": SHA384, "key_len": 32, "aead": AESGCM},
    0x1303: {"hash": SHA256, "key_len": 32, "aead": ChaCha20Poly1305},
}


def iter_tls_records(stream: bytes):
    offset = 0
    while offset + 5 <= len(stream):
        content_type = stream[offset]
        version = stream[offset + 1 : offset + 3]
        length = int.from_bytes(stream[offset + 3 : offset + 5], "big")
        start = offset + 5
        end = start + length
        if end > len(stream):
            raise SystemExit("Encountered a truncated TLS record.")
        yield content_type, version, stream[start:end]
        offset = end

    if offset != len(stream):
        raise SystemExit("Encountered trailing bytes after the TLS stream.")


def iter_handshake_messages(fragment: bytes):
    offset = 0
    while offset + 4 <= len(fragment):
        msg_type = fragment[offset]
        msg_len = int.from_bytes(fragment[offset + 1 : offset + 4], "big")
        start = offset + 4
        end = start + msg_len
        if end > len(fragment):
            raise SystemExit("Encountered a truncated handshake message.")
        yield msg_type, fragment[start:end]
        offset = end


def read_streams(pcap_path: Path) -> tuple[bytes, bytes]:
    client_chunks: list[bytes] = []
    server_chunks: list[bytes] = []

    with PcapReader(str(pcap_path)) as packets:
        for packet in packets:
            if IP not in packet or TCP not in packet:
                continue

            tcp = packet[TCP]
            payload = bytes(tcp.payload)
            if not payload:
                continue

            if tcp.dport == SERVER_PORT:
                client_chunks.append(payload)
            elif tcp.sport == SERVER_PORT:
                server_chunks.append(payload)

    if not client_chunks or not server_chunks:
        raise SystemExit("Could not find a TLS stream on the expected server port.")

    return b"".join(client_chunks), b"".join(server_chunks)


def extract_client_random(client_stream: bytes) -> str:
    for content_type, _, fragment in iter_tls_records(client_stream):
        if content_type != 22:
            continue
        for msg_type, body in iter_handshake_messages(fragment):
            if msg_type == 1:
                return body[2:34].hex()
    raise SystemExit("Could not find the ClientHello random in the pcap.")


def extract_cipher_suite(server_stream: bytes) -> int:
    for content_type, _, fragment in iter_tls_records(server_stream):
        if content_type != 22:
            continue
        for msg_type, body in iter_handshake_messages(fragment):
            if msg_type == 2:
                session_id_len = body[34]
                cipher_offset = 35 + session_id_len
                return int.from_bytes(body[cipher_offset : cipher_offset + 2], "big")
    raise SystemExit("Could not find the ServerHello cipher suite in the pcap.")


def read_embedded_secret() -> tuple[str, bytes]:
    return CLIENT_RANDOM.lower(), bytes.fromhex(SERVER_TRAFFIC_SECRET_0)


def hkdf_expand_label(secret: bytes, label: bytes, length: int, hash_cls) -> bytes:
    full_label = b"tls13 " + label
    info = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + b"\x00"
    )
    return HKDFExpand(algorithm=hash_cls(), length=length, info=info).derive(secret)


def xor_nonce(iv: bytes, sequence_number: int) -> bytes:
    seq_bytes = sequence_number.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, seq_bytes))


def split_inner_plaintext(data: bytes) -> tuple[int, bytes]:
    index = len(data) - 1
    while index >= 0 and data[index] == 0:
        index -= 1
    if index < 0:
        raise SystemExit("Encountered an empty TLS inner plaintext.")
    return data[index], data[:index]


def decrypt_server_application_data(server_stream: bytes, suite: int, secret: bytes) -> bytes:
    params = CIPHER_SUITES.get(suite)
    if params is None:
        raise SystemExit(f"Unsupported TLS 1.3 cipher suite: 0x{suite:04x}")

    key = hkdf_expand_label(secret, b"key", params["key_len"], params["hash"])
    iv = hkdf_expand_label(secret, b"iv", 12, params["hash"])
    aead = params["aead"](key)

    plaintext_chunks: list[bytes] = []
    sequence_number = 0
    started = False

    for content_type, version, fragment in iter_tls_records(server_stream):
        if content_type != 23:
            continue

        header = bytes([content_type]) + version + len(fragment).to_bytes(2, "big")
        nonce = xor_nonce(iv, sequence_number)

        try:
            inner = aead.decrypt(nonce, fragment, header)
        except Exception:
            if started:
                raise SystemExit("Failed to decrypt a TLS 1.3 application record.")
            continue

        started = True
        sequence_number += 1
        inner_type, content = split_inner_plaintext(inner)
        if inner_type == 23:
            plaintext_chunks.append(content)

    if not plaintext_chunks:
        raise SystemExit("Did not recover any decrypted application data.")

    return b"".join(plaintext_chunks)


def main() -> None:
    if "___FILL_ME___" in (PCAP_PATH, CLIENT_RANDOM, SERVER_TRAFFIC_SECRET_0):
        raise SystemExit("Fill in PCAP_PATH, CLIENT_RANDOM, and SERVER_TRAFFIC_SECRET_0 first.")

    client_stream, server_stream = read_streams(Path(PCAP_PATH))
    expected_client_random, secret = read_embedded_secret()
    client_random = extract_client_random(client_stream)
    if client_random.lower() != expected_client_random:
        raise SystemExit("The embedded CLIENT_RANDOM does not match the TLS session in the pcap.")
    cipher_suite = extract_cipher_suite(server_stream)
    plaintext = decrypt_server_application_data(server_stream, cipher_suite, secret)

    match = re.search(rb"FLAG\{[^}]+\}", plaintext)
    if not match:
        raise SystemExit("Could not find a flag in the decrypted plaintext.")
    print(match.group(0).decode("ascii"))


if __name__ == "__main__":
    main()
