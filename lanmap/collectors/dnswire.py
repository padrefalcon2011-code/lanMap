"""Разбор и сборка DNS-пакетов (mDNS, PTR-запросы) без сторонних библиотек."""
from __future__ import annotations

import socket
import struct

TYPE_A, TYPE_PTR, TYPE_TXT, TYPE_AAAA, TYPE_SRV, TYPE_CNAME = 1, 12, 16, 28, 33, 5


def read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 20:
        raise ValueError("слишком глубокая цепочка сжатия DNS")
    parts: list[str] = []
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset]
            offset += 1
            parts.append(read_name(data, ptr, depth + 1)[0])
            break
        parts.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(p for p in parts if p), offset


def parse_records(data: bytes) -> list[dict]:
    """Все записи ответа (answer + authority + additional)."""
    counts = struct.unpack("!6H", data[:12])
    offset = 12
    for _ in range(counts[2]):
        _, offset = read_name(data, offset)
        offset += 4
    records = []
    for _ in range(sum(counts[3:])):
        name, offset = read_name(data, offset)
        rtype, _cls, ttl, size = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        raw = data[offset:offset + size]
        value = None
        if rtype == TYPE_A and size == 4:
            value = socket.inet_ntoa(raw)
        elif rtype in (TYPE_PTR, TYPE_CNAME):
            value = read_name(data, offset)[0]
        elif rtype == TYPE_SRV and size >= 6:
            _prio, _weight, port = struct.unpack("!HHH", raw[:6])
            value = {"port": port, "target": read_name(data, offset + 6)[0]}
        elif rtype == TYPE_TXT:
            value, n = [], 0
            while n < len(raw):
                length = raw[n]
                n += 1
                value.append(raw[n:n + length].decode("utf-8", "replace"))
                n += length
        elif rtype == TYPE_AAAA and size == 16:
            value = socket.inet_ntop(socket.AF_INET6, raw)
        if value is not None:
            records.append({"name": name, "type": rtype, "ttl": ttl, "value": value})
        offset += size
    return records


def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0"


def build_query(name: str, qtype: int, unicast_response: bool = False, qid: int = 0, rd: bool = False) -> bytes:
    qclass = 0x8001 if unicast_response else 0x0001
    flags = 0x0100 if rd else 0
    return struct.pack("!6H", qid, flags, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, qclass)


def ptr_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
