#!/usr/bin/env python3

from __future__ import annotations

import select
import socket
import ssl
import subprocess
import threading
from pathlib import Path

from scapy.all import Ether, IP, PcapWriter, Raw, TCP


ROOT = Path(__file__).resolve().parent.parent
LOOPBACK = "127.0.0.1"

TLS12_DIR = ROOT / "tls1.2"
TLS13_DIR = ROOT / "tls1.3"

TLS12_PROXY_PORT = 44120
TLS13_PROXY_PORT = 44130
TLS12_BACKEND_PORT = 45120
TLS13_BACKEND_PORT = 45130

TLS12_FLAG = "FLAG{one_key_can_rule_them_all}"
TLS13_FLAG = "FLAG{key_logger_but_not_with_usb_lol}"

CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
SERVER_PORT = 443
TLS12_CLIENT_PORT = 51012
TLS13_CLIENT_PORT = 51013

CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"


TLS13_SOLVER = """#!/usr/bin/env python3
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
        + b"\\x00"
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

    match = re.search(rb"FLAG\\{[^}]+\\}", plaintext)
    if not match:
        raise SystemExit("Could not find a flag in the decrypted plaintext.")
    print(match.group(0).decode("ascii"))


if __name__ == "__main__":
    main()
"""


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def make_cert(out_dir: Path) -> tuple[Path, Path]:
    key_path = out_dir / "server.key"
    cert_path = out_dir / "server.crt"
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-days",
            "3650",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ]
    )
    return cert_path, key_path


def write_tls13_solver(out_dir: Path) -> None:
    solver_path = out_dir / "decrypt_flag.py"
    solver_path.write_text(TLS13_SOLVER, encoding="ascii")
    solver_path.chmod(0o755)


def make_packet(
    *,
    src_ip: str,
    dst_ip: str,
    src_mac: str,
    dst_mac: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: str,
    payload: bytes = b"",
    ts: float,
):
    pkt = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=64240)
    )
    if payload:
        pkt /= Raw(load=payload)
    pkt.time = ts
    return pkt


def write_pcap(records: list[tuple[str, bytes]], *, pcap_path: Path, client_port: int) -> None:
    writer = PcapWriter(str(pcap_path), sync=True)
    current_time = 1_700_000_000.0
    client_seq = 1000
    server_seq = 9000

    def emit(packet) -> None:
        nonlocal current_time
        writer.write(packet)
        current_time += 0.001

    emit(
        make_packet(
            src_ip=CLIENT_IP,
            dst_ip=SERVER_IP,
            src_mac=CLIENT_MAC,
            dst_mac=SERVER_MAC,
            sport=client_port,
            dport=SERVER_PORT,
            seq=client_seq,
            ack=0,
            flags="S",
            ts=current_time,
        )
    )
    emit(
        make_packet(
            src_ip=SERVER_IP,
            dst_ip=CLIENT_IP,
            src_mac=SERVER_MAC,
            dst_mac=CLIENT_MAC,
            sport=SERVER_PORT,
            dport=client_port,
            seq=server_seq,
            ack=client_seq + 1,
            flags="SA",
            ts=current_time,
        )
    )
    client_seq += 1
    server_seq += 1
    emit(
        make_packet(
            src_ip=CLIENT_IP,
            dst_ip=SERVER_IP,
            src_mac=CLIENT_MAC,
            dst_mac=SERVER_MAC,
            sport=client_port,
            dport=SERVER_PORT,
            seq=client_seq,
            ack=server_seq,
            flags="A",
            ts=current_time,
        )
    )

    for direction, payload in records:
        if direction == "c2s":
            emit(
                make_packet(
                    src_ip=CLIENT_IP,
                    dst_ip=SERVER_IP,
                    src_mac=CLIENT_MAC,
                    dst_mac=SERVER_MAC,
                    sport=client_port,
                    dport=SERVER_PORT,
                    seq=client_seq,
                    ack=server_seq,
                    flags="PA",
                    payload=payload,
                    ts=current_time,
                )
            )
            client_seq += len(payload)
            emit(
                make_packet(
                    src_ip=SERVER_IP,
                    dst_ip=CLIENT_IP,
                    src_mac=SERVER_MAC,
                    dst_mac=CLIENT_MAC,
                    sport=SERVER_PORT,
                    dport=client_port,
                    seq=server_seq,
                    ack=client_seq,
                    flags="A",
                    ts=current_time,
                )
            )
        else:
            emit(
                make_packet(
                    src_ip=SERVER_IP,
                    dst_ip=CLIENT_IP,
                    src_mac=SERVER_MAC,
                    dst_mac=CLIENT_MAC,
                    sport=SERVER_PORT,
                    dport=client_port,
                    seq=server_seq,
                    ack=client_seq,
                    flags="PA",
                    payload=payload,
                    ts=current_time,
                )
            )
            server_seq += len(payload)
            emit(
                make_packet(
                    src_ip=CLIENT_IP,
                    dst_ip=SERVER_IP,
                    src_mac=CLIENT_MAC,
                    dst_mac=SERVER_MAC,
                    sport=client_port,
                    dport=SERVER_PORT,
                    seq=client_seq,
                    ack=server_seq,
                    flags="A",
                    ts=current_time,
                )
            )

    emit(
        make_packet(
            src_ip=SERVER_IP,
            dst_ip=CLIENT_IP,
            src_mac=SERVER_MAC,
            dst_mac=CLIENT_MAC,
            sport=SERVER_PORT,
            dport=client_port,
            seq=server_seq,
            ack=client_seq,
            flags="FA",
            ts=current_time,
        )
    )
    server_seq += 1
    emit(
        make_packet(
            src_ip=CLIENT_IP,
            dst_ip=SERVER_IP,
            src_mac=CLIENT_MAC,
            dst_mac=SERVER_MAC,
            sport=client_port,
            dport=SERVER_PORT,
            seq=client_seq,
            ack=server_seq,
            flags="A",
            ts=current_time,
        )
    )
    emit(
        make_packet(
            src_ip=CLIENT_IP,
            dst_ip=SERVER_IP,
            src_mac=CLIENT_MAC,
            dst_mac=SERVER_MAC,
            sport=client_port,
            dport=SERVER_PORT,
            seq=client_seq,
            ack=server_seq,
            flags="FA",
            ts=current_time,
        )
    )
    client_seq += 1
    emit(
        make_packet(
            src_ip=SERVER_IP,
            dst_ip=CLIENT_IP,
            src_mac=SERVER_MAC,
            dst_mac=CLIENT_MAC,
            sport=SERVER_PORT,
            dport=client_port,
            seq=server_seq,
            ack=client_seq,
            flags="A",
            ts=current_time,
        )
    )
    writer.close()


def http_exchange(
    *,
    tls_min: ssl.TLSVersion,
    tls_max: ssl.TLSVersion,
    flag: str,
    backend_port: int,
    proxy_port: int,
    cert_path: Path,
    key_path: Path,
    keylog_path: Path | None = None,
    cipher: str | None = None,
) -> list[tuple[str, bytes]]:
    response_body = flag.encode("ascii")
    response = (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Length: {len(response_body)}\r\n".encode("ascii")
        + b"Content-Type: text/plain\r\n"
        + b"Connection: close\r\n"
        + b"\r\n"
        + response_body
    )
    request = (
        b"GET /flag HTTP/1.1\r\n"
        + b"Host: localhost\r\n"
        + b"Connection: close\r\n"
        + b"\r\n"
    )

    server_ready = threading.Event()
    server_done = threading.Event()
    proxy_ready = threading.Event()
    proxy_done = threading.Event()
    server_error: list[BaseException] = []
    proxy_error: list[BaseException] = []
    records: list[tuple[str, bytes]] = []

    def server() -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((LOOPBACK, backend_port))
                sock.listen(1)
                server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_ctx.minimum_version = tls_min
                server_ctx.maximum_version = tls_max
                if cipher:
                    server_ctx.set_ciphers(cipher)
                if hasattr(server_ctx, "num_tickets"):
                    server_ctx.num_tickets = 0
                server_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
                server_ready.set()
                conn, _ = sock.accept()
                with conn:
                    with server_ctx.wrap_socket(conn, server_side=True) as tls_conn:
                        tls_conn.recv(4096)
                        tls_conn.sendall(response)
        except BaseException as exc:  # pragma: no cover
            server_error.append(exc)
        finally:
            server_done.set()

    def proxy() -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((LOOPBACK, proxy_port))
                listener.listen(1)
                proxy_ready.set()
                client_conn, _ = listener.accept()
                with client_conn:
                    with socket.create_connection((LOOPBACK, backend_port), timeout=5) as server_conn:
                        client_open = True
                        server_open = True
                        while client_open or server_open:
                            readable, _, _ = select.select(
                                [sock for sock, open_ in ((client_conn, client_open), (server_conn, server_open)) if open_],
                                [],
                                [],
                                5,
                            )
                            if not readable:
                                continue
                            for src in readable:
                                data = src.recv(16384)
                                if src is client_conn:
                                    dst = server_conn
                                    direction = "c2s"
                                else:
                                    dst = client_conn
                                    direction = "s2c"
                                if data:
                                    records.append((direction, data))
                                    dst.sendall(data)
                                else:
                                    try:
                                        dst.shutdown(socket.SHUT_WR)
                                    except OSError:
                                        pass
                                    if src is client_conn:
                                        client_open = False
                                    else:
                                        server_open = False
        except BaseException as exc:  # pragma: no cover
            proxy_error.append(exc)
        finally:
            proxy_done.set()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()

    if not server_ready.wait(timeout=5):
        raise RuntimeError("Server failed to start.")

    proxy_thread = threading.Thread(target=proxy, daemon=True)
    proxy_thread.start()

    if not proxy_ready.wait(timeout=5):
        raise RuntimeError("Proxy failed to start.")

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.minimum_version = tls_min
    client_ctx.maximum_version = tls_max
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    if cipher:
        client_ctx.set_ciphers(cipher)
    if keylog_path is not None:
        client_ctx.keylog_filename = str(keylog_path)

    with socket.create_connection((LOOPBACK, proxy_port), timeout=5) as sock:
        with client_ctx.wrap_socket(sock, server_hostname="localhost") as tls_sock:
            tls_sock.sendall(request)
            received = bytearray()
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                received.extend(chunk)

    if flag.encode("ascii") not in received:
        raise RuntimeError("Did not receive the expected flag from the TLS service.")

    if not server_done.wait(timeout=5):
        raise RuntimeError("Server did not finish cleanly.")

    if not proxy_done.wait(timeout=5):
        raise RuntimeError("Proxy did not finish cleanly.")

    if server_error:
        raise RuntimeError("TLS server failed.") from server_error[0]

    if proxy_error:
        raise RuntimeError("TLS proxy failed.") from proxy_error[0]

    return records


def build_tls12() -> None:
    TLS12_DIR.mkdir(exist_ok=True)
    cert_path, key_path = make_cert(TLS12_DIR)
    pcap_path = TLS12_DIR / "traffic.pcap"

    records = http_exchange(
        tls_min=ssl.TLSVersion.TLSv1_2,
        tls_max=ssl.TLSVersion.TLSv1_2,
        flag=TLS12_FLAG,
        backend_port=TLS12_BACKEND_PORT,
        proxy_port=TLS12_PROXY_PORT,
        cert_path=cert_path,
        key_path=key_path,
        cipher="AES128-SHA:@SECLEVEL=0",
    )
    write_pcap(records, pcap_path=pcap_path, client_port=TLS12_CLIENT_PORT)
    cert_path.unlink(missing_ok=True)


def build_tls13() -> None:
    TLS13_DIR.mkdir(exist_ok=True)
    cert_path, key_path = make_cert(TLS13_DIR)
    pcap_path = TLS13_DIR / "traffic.pcap"
    keylog_path = TLS13_DIR / "session.keys"

    if keylog_path.exists():
        keylog_path.unlink()

    records = http_exchange(
        tls_min=ssl.TLSVersion.TLSv1_3,
        tls_max=ssl.TLSVersion.TLSv1_3,
        flag=TLS13_FLAG,
        backend_port=TLS13_BACKEND_PORT,
        proxy_port=TLS13_PROXY_PORT,
        cert_path=cert_path,
        key_path=key_path,
        keylog_path=keylog_path,
    )
    write_pcap(records, pcap_path=pcap_path, client_port=TLS13_CLIENT_PORT)
    cert_path.unlink(missing_ok=True)
    write_tls13_solver(TLS13_DIR)


def main() -> None:
    build_tls12()
    build_tls13()
    print("Generated tls1.2 and tls1.3 challenge artifacts.")


if __name__ == "__main__":
    main()
