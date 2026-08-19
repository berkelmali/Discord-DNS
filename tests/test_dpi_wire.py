"""
Discord DNS v3.6 — Wire Proof (no Administrator needed)
Answers one question: what *actually* leaves this machine when the engine
touches a connection?

It does not simulate the engine. It takes a genuine ClientHello produced by
OpenSSL (the same bytes Chrome or Discord would send), feeds it through the real
NativeDpiEngine._handle_packet() with a recording stand-in for the driver, and
prints every byte the engine would hand to WinDivert.

Run: python -m tests.test_dpi_wire
"""

import os
import ssl
import struct
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import dpi_engine
import dpi_packets as dp
import windivert as wd

HOST = "gateway.discord.gg"


# ─── A real ClientHello, straight out of OpenSSL ─────────────────────────────────

def real_client_hello(hostname: str = HOST) -> bytes:
    """Drive a memory-BIO TLS handshake just far enough to capture the ClientHello."""
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=hostname)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass                     # expected: the server never replies
    return outgoing.read()


# ─── Recording stand-in for the WinDivert handle ─────────────────────────────────

class RecordingHandle:
    """Same interface the engine uses, but it keeps the packets instead of sending."""

    def __init__(self):
        self.sent = []           # (kind, packet_bytes)

    def send(self, packet, addr, recalc_checksums=True):
        self.sent.append(("normal", bytes(packet)))
        return len(packet)

    def send_precomputed(self, packet, addr):
        self.sent.append(("badsum", bytes(packet)))
        return len(packet)


def build_outbound_packet(payload: bytes, seq: int = 3_000_000) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 52345, 443, seq, 99, (5 << 4), 0x18, 64240, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0xABCD,
                     0x4000, 128, dp.PROTO_TCP, 0,
                     bytes([192, 168, 1, 50]), bytes([162, 159, 128, 233]))
    return ip + tcp + payload


def hexdump(data: bytes, limit: int = 48) -> str:
    shown = data[:limit]
    return " ".join(f"{b:02x}" for b in shown) + (" …" if len(data) > limit else "")


def printable(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def main() -> int:
    print("=" * 72)
    print("  TEL ÜZERİNDE NE GİDİYOR? — GERÇEK PAKET KANITI")
    print("=" * 72)

    hello = real_client_hello()
    kind, host, span = dp.describe_target(hello)
    print(f"\nOpenSSL'in ürettiği gerçek ClientHello : {len(hello)} bayt")
    print(f"Motorun okuduğu SNI                    : {host}  (tip: {kind})")
    print(f"Ham baytlar                            : {hexdump(hello)}")
    if host != HOST:
        print("  !! SNI okunamadı — kanıt geçersiz")
        return 1

    original = build_outbound_packet(hello)
    engine = dpi_engine.NativeDpiEngine(dpi_engine.PRESETS["superonline"])
    handle = RecordingHandle()
    addr = wd.WinDivertAddress()
    addr.outbound = True

    engine._handle_packet(handle, bytearray(original), addr)

    print(f"\nTek ClientHello girdi, telden {len(handle.sent)} paket çıktı:\n")

    base_seq = dp.parse_tcp_packet(original).seq
    reassembly = {}
    failures = 0

    for index, (mode, raw) in enumerate(handle.sent, start=1):
        pkt = dp.parse_tcp_packet(raw)
        rel = (pkt.seq - base_seq) & 0xFFFFFFFF
        rel_signed = rel - (1 << 32) if rel > (1 << 31) else rel
        checksum = struct.unpack_from("!H", raw, pkt.tcp_off + 16)[0]

        if rel_signed < 0:
            role = "SAHTE (decoy)"
        else:
            role = f"gerçek parça @ofset {rel_signed}"
            reassembly[rel_signed] = pkt.payload

        leaks = HOST.encode() in pkt.payload
        if leaks:
            failures += 1

        print(f"  {index}. paket — {role}")
        print(f"     seq farkı      : {rel_signed:+d}")
        print(f"     yük uzunluğu   : {pkt.payload_len} bayt")
        print(f"     TCP sağlaması  : 0x{checksum:04x}{'  (kasten bozuk)' if mode == 'badsum' else ''}")
        print(f"     içerik         : {printable(pkt.payload[:56])}")
        print(f"     '{HOST}' görünüyor mu: {'EVET — SIZINTI!' if leaks else 'hayır'}")
        print()

    # 1) DPI ne görürse görsün, hiçbir segmentte tam alan adı yok
    print("-" * 72)
    print(f"[1] Hiçbir pakette tam alan adı yok            : {'EVET' if failures == 0 else 'HAYIR'}")

    # 2) Sunucu tarafında birleşince orijinalin aynısı mı?
    merged = b"".join(reassembly[key] for key in sorted(reassembly))
    identical = merged == hello
    print(f"[2] Parçalar birleşince orijinalin aynısı      : {'EVET' if identical else 'HAYIR'}")
    if not identical:
        failures += 1

    # 3) Sahte paket sunucuya zarar veremez mi?
    decoys = [dp.parse_tcp_packet(raw) for mode, raw in handle.sent
              if ((dp.parse_tcp_packet(raw).seq - base_seq) & 0xFFFFFFFF) > (1 << 31)]
    safe_decoy = all((base_seq - d.seq) & 0xFFFFFFFF > 65535 for d in decoys)
    print(f"[3] Sahte paket pencere dışında (sunucu atar)  : {'EVET' if safe_decoy else 'HAYIR'}")
    if decoys and not safe_decoy:
        failures += 1

    # 4) Sahte paket gerçekten zararsız bir alan adı taşıyor mu?
    decoy_hosts = [dp.extract_sni(d.payload) for d in decoys]
    decoy_ok = all(h is not None and HOST not in h[0] for h in decoy_hosts)
    print(f"[4] Sahte paketteki SNI zararsız               : "
          f"{'EVET → ' + str([h[0] for h in decoy_hosts if h]) if decoy_ok else 'HAYIR'}")

    print("-" * 72)
    print("SONUÇ:", "KANIT GEÇERLİ — motor telde gerçekten böyle davranıyor"
          if failures == 0 else f"{failures} SORUN VAR")
    print("=" * 72)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
