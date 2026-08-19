"""
Discord DNS v3.6 — Packet Surgery Toolkit
Pure, side-effect-free parsing and rebuilding of IPv4/IPv6 + TCP packets, TLS
ClientHello (SNI) and HTTP request headers.

Everything here is plain byte manipulation with no driver involved, so it is
unit-testable without Administrator rights (see tests/test_dpi_engine.py).
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

# ─── Protocol constants ──────────────────────────────────────────────────────────

PROTO_TCP = 6
PROTO_UDP = 17

TLS_RECORD_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_EXT_SERVER_NAME = 0x0000

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


# ─── Parsed view ─────────────────────────────────────────────────────────────────

@dataclass
class TcpPacket:
    """Offsets and header fields of a diverted IPv4/IPv6 TCP packet."""

    raw: bytes
    version: int          # 4 or 6
    ip_hlen: int          # IP header length in bytes
    tcp_off: int          # offset of the TCP header
    tcp_hlen: int         # TCP header length in bytes (incl. options)
    payload_off: int      # offset of the TCP payload
    payload: bytes
    seq: int
    flags: int
    src_port: int
    dst_port: int
    ttl: int              # IPv4 TTL / IPv6 hop limit
    ip_id: int            # IPv4 identification (0 for IPv6)
    src_ip: bytes         # raw source address (4 or 16 bytes)
    dst_ip: bytes         # raw destination address

    @property
    def payload_len(self) -> int:
        return len(self.payload)

    @property
    def is_tls_handshake(self) -> bool:
        return len(self.payload) > 5 and self.payload[0] == TLS_RECORD_HANDSHAKE

    @property
    def is_http_request(self) -> bool:
        return self.payload.startswith(HTTP_METHODS)


def parse_tcp_packet(packet: bytes) -> Optional[TcpPacket]:
    """Parse an IPv4/IPv6 TCP packet. Returns None when it is not usable."""
    if len(packet) < 20:
        return None

    version = packet[0] >> 4

    if version == 4:
        ip_hlen = (packet[0] & 0x0F) * 4
        if ip_hlen < 20 or len(packet) < ip_hlen + 20:
            return None
        if packet[9] != PROTO_TCP:
            return None
        src_ip = bytes(packet[12:16])
        dst_ip = bytes(packet[16:20])
        total_len = struct.unpack_from("!H", packet, 2)[0]
        ip_id = struct.unpack_from("!H", packet, 4)[0]
        ttl = packet[8]
        # Never touch a fragmented datagram — offsets would be meaningless
        frag_off = struct.unpack_from("!H", packet, 6)[0] & 0x1FFF
        if frag_off:
            return None
        end = min(len(packet), total_len) if total_len else len(packet)
    elif version == 6:
        if len(packet) < 40 + 20:
            return None
        if packet[6] != PROTO_TCP:      # no extension-header walking on purpose
            return None
        ip_hlen = 40
        ip_id = 0
        src_ip = bytes(packet[8:24])
        dst_ip = bytes(packet[24:40])
        ttl = packet[7]
        payload_len = struct.unpack_from("!H", packet, 4)[0]
        end = min(len(packet), ip_hlen + payload_len) if payload_len else len(packet)
    else:
        return None

    tcp_off = ip_hlen
    tcp_hlen = ((packet[tcp_off + 12] >> 4) & 0x0F) * 4
    if tcp_hlen < 20 or tcp_off + tcp_hlen > end:
        return None

    src_port, dst_port = struct.unpack_from("!HH", packet, tcp_off)
    seq = struct.unpack_from("!I", packet, tcp_off + 4)[0]
    flags = packet[tcp_off + 13]
    payload_off = tcp_off + tcp_hlen

    return TcpPacket(
        raw=bytes(packet),
        version=version,
        ip_hlen=ip_hlen,
        tcp_off=tcp_off,
        tcp_hlen=tcp_hlen,
        payload_off=payload_off,
        payload=bytes(packet[payload_off:end]),
        seq=seq,
        flags=flags,
        src_port=src_port,
        dst_port=dst_port,
        ttl=ttl,
        ip_id=ip_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
    )


def infer_hop_count(observed_ttl: int) -> Optional[int]:
    """
    How many routers a reply crossed on its way here.

    Stacks start their packets at one of a few well-known TTLs, so the distance
    is simply that starting value minus what arrived. Used by auto-TTL to age a
    decoy packet so it dies *after* the ISP's DPI box but *before* the server.
    """
    for initial in (64, 128, 255):
        if 0 < observed_ttl <= initial:
            hops = initial - observed_ttl
            return hops if 0 <= hops < 40 else None
    return None


# ─── TLS ClientHello / SNI ───────────────────────────────────────────────────────

def extract_sni(payload: bytes) -> Optional[Tuple[str, int, int]]:
    """
    Extract the SNI host from a TLS ClientHello.
    Returns (hostname, offset_of_hostname_in_payload, hostname_length) or None.
    Fully bounds-checked: malformed records simply yield None.
    """
    try:
        if len(payload) < 45 or payload[0] != TLS_RECORD_HANDSHAKE:
            return None
        if payload[5] != TLS_HANDSHAKE_CLIENT_HELLO:
            return None

        record_len = struct.unpack_from("!H", payload, 3)[0]
        limit = min(len(payload), 5 + record_len)

        pos = 5 + 4          # handshake header
        pos += 2 + 32        # client version + random
        if pos >= limit:
            return None

        session_id_len = payload[pos]
        pos += 1 + session_id_len

        if pos + 2 > limit:
            return None
        cipher_len = struct.unpack_from("!H", payload, pos)[0]
        pos += 2 + cipher_len

        if pos + 1 > limit:
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len

        if pos + 2 > limit:
            return None
        ext_total = struct.unpack_from("!H", payload, pos)[0]
        pos += 2
        ext_end = min(limit, pos + ext_total)

        while pos + 4 <= ext_end:
            ext_type, ext_len = struct.unpack_from("!HH", payload, pos)
            body = pos + 4
            if body + ext_len > ext_end:
                return None
            if ext_type == TLS_EXT_SERVER_NAME:
                # server_name_list length (2) | name_type (1) | name length (2)
                if ext_len < 5:
                    return None
                name_type = payload[body + 2]
                name_len = struct.unpack_from("!H", payload, body + 3)[0]
                host_off = body + 5
                if name_type != 0 or host_off + name_len > ext_end:
                    return None
                host = payload[host_off:host_off + name_len].decode("ascii", errors="replace")
                return host, host_off, name_len
            pos = body + ext_len
        return None
    except Exception:
        return None


def extract_http_host(payload: bytes) -> Optional[Tuple[str, int, int]]:
    """
    Extract the Host header from a plain HTTP request.
    Returns (host, offset_of_header_name, header_name_length) or None.
    """
    try:
        head = payload[:2048]
        lowered = head.lower()
        idx = lowered.find(b"\r\nhost:")
        if idx < 0:
            return None
        name_off = idx + 2
        value_start = name_off + 5
        while value_start < len(head) and head[value_start:value_start + 1] in (b" ", b"\t", b":"):
            value_start += 1
        line_end = head.find(b"\r\n", value_start)
        if line_end < 0:
            return None
        host = head[value_start:line_end].decode("ascii", errors="replace").strip()
        return host, name_off, 4
    except Exception:
        return None


def describe_target(payload: bytes) -> Tuple[str, Optional[str], Optional[Tuple[int, int]]]:
    """
    Identify what a first-data packet carries.
    Returns (kind, hostname, (host_offset, host_len)) with kind in
    {"tls", "http", "other"}.
    """
    sni = extract_sni(payload)
    if sni:
        host, off, length = sni
        return "tls", host, (off, length)
    http = extract_http_host(payload)
    if http:
        host, off, length = http
        return "http", host, (off, length)
    return "other", None, None


# ─── Split position selection ────────────────────────────────────────────────────

def choose_split_positions(payload: bytes, base_split: int = 2,
                           split_at_sni: bool = True) -> List[int]:
    """
    Decide where to cut the payload into TCP segments.

    Two cuts are used by default:
      • an early cut (base_split) that breaks the TLS record header itself, and
      • a cut in the middle of the SNI hostname, which defeats DPI engines that
        only reassemble the first segment.
    """
    positions: List[int] = []
    n = len(payload)
    if n < 2:
        return []

    if 0 < base_split < n:
        positions.append(base_split)

    if split_at_sni:
        found = describe_target(payload)
        span = found[2]
        if span:
            host_off, host_len = span
            mid = host_off + max(1, host_len // 2)
            if 0 < mid < n:
                positions.append(mid)

    return sorted(set(positions))


def split_payload(payload: bytes, positions: List[int]) -> List[Tuple[int, bytes]]:
    """Cut payload at the given positions → [(relative_seq_offset, chunk), ...]."""
    chunks: List[Tuple[int, bytes]] = []
    prev = 0
    for pos in positions:
        if pos <= prev or pos >= len(payload):
            continue
        chunks.append((prev, payload[prev:pos]))
        prev = pos
    chunks.append((prev, payload[prev:]))
    return [c for c in chunks if c[1]]


# ─── Packet rebuilding ───────────────────────────────────────────────────────────

def ipv4_checksum(header: bytes) -> int:
    """Standard one's-complement checksum over an IPv4 header."""
    if len(header) % 2:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += struct.unpack_from("!H", header, i)[0]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_segment(pkt: TcpPacket, payload: bytes, seq: int,
                  ttl: Optional[int] = None,
                  ip_id: Optional[int] = None,
                  flags: Optional[int] = None) -> bytearray:
    """
    Rebuild a TCP packet reusing the original IP/TCP headers with a new payload,
    sequence number and (optionally) TTL / IP id / TCP flags.
    Checksums are left for WinDivertHelperCalcChecksums unless finalize_badsum()
    is called afterwards.
    """
    header = bytearray(pkt.raw[:pkt.payload_off])
    out = header + bytearray(payload)

    total_len = len(out)
    if pkt.version == 4:
        struct.pack_into("!H", out, 2, total_len)
        if ip_id is not None:
            struct.pack_into("!H", out, 4, ip_id & 0xFFFF)
        if ttl is not None:
            out[8] = max(1, min(255, ttl))
        struct.pack_into("!H", out, 10, 0)          # zero checksum → recalculated
    else:
        struct.pack_into("!H", out, 4, total_len - pkt.ip_hlen)
        if ttl is not None:
            out[7] = max(1, min(255, ttl))

    struct.pack_into("!I", out, pkt.tcp_off + 4, seq & 0xFFFFFFFF)
    if flags is not None:
        out[pkt.tcp_off + 13] = flags & 0xFF
    struct.pack_into("!H", out, pkt.tcp_off + 16, 0)  # zero TCP checksum

    return out


def finalize_badsum(packet: bytearray, pkt: TcpPacket) -> bytearray:
    """
    Make a decoy packet that DPI accepts but the destination host discards:
    a valid IP header checksum with a deliberately wrong TCP checksum.
    """
    if pkt.version == 4:
        struct.pack_into("!H", packet, 10, 0)
        chk = ipv4_checksum(bytes(packet[:pkt.ip_hlen]))
        struct.pack_into("!H", packet, 10, chk)
    struct.pack_into("!H", packet, pkt.tcp_off + 16, 0xB4D5)  # intentionally invalid
    return packet


# ─── Decoy payloads ──────────────────────────────────────────────────────────────

DECOY_HOSTS = (b"www.microsoft.com", b"www.bing.com", b"www.wikipedia.org", b"outlook.office.com")


def make_decoy_payload(payload: bytes, host_span: Optional[Tuple[int, int]] = None) -> bytes:
    """
    Build a same-length decoy of the real first packet.

    For TLS the record stays structurally valid and only the SNI hostname bytes
    are replaced with a benign domain, so DPI happily records the decoy while the
    real (fragmented) ClientHello slips past. For anything else a random blob
    behind a valid TLS record header is used.
    """
    if host_span:
        off, length = host_span
        if 0 < length and off + length <= len(payload):
            filler = DECOY_HOSTS[os.urandom(1)[0] % len(DECOY_HOSTS)]
            replacement = (filler * (length // len(filler) + 1))[:length]
            return bytes(payload[:off]) + replacement + bytes(payload[off + length:])

    body = os.urandom(max(0, len(payload) - 5))
    return bytes([TLS_RECORD_HANDSHAKE, 0x03, 0x01]) + struct.pack("!H", len(body)) + body


def mangle_http_host_header(payload: bytes, name_off: int) -> bytes:
    """
    Rewrite `Host:` as `hOsT:` — case-insensitive for every HTTP server, but
    enough to miss the byte-exact `Host:` pattern many cheap DPI boxes match on.
    """
    if name_off + 4 > len(payload):
        return payload
    return payload[:name_off] + b"hOsT" + payload[name_off + 4:]
