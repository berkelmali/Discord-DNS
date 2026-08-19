"""
Discord DNS v3.6 — Self-Diagnostics
Builds a single, shareable report answering "is this actually working on my
machine, and if not, why?".

Written to be pasted into a GitHub issue: the public IP is masked and no
account, hostname or MAC information is collected. What it does collect is what
a maintainer needs — driver state, engine counters, and whether the ISP is
hijacking DNS.
"""

from __future__ import annotations

import platform
import socket
import ssl
import struct
import sys
import time
from typing import Callable, List, Optional, Sequence, Tuple

import dns_manager
import doh_proxy
import dpi_bypass
import dpi_engine
import dpi_packets as dp

TEST_HOSTS: Tuple[str, ...] = ("discord.com", "gateway.discord.gg", "cloudflare.com")


def mask_ip(address: str) -> str:
    """95.70.152.158 → 95.70.x.x — enough to identify the ISP, not the user."""
    parts = (address or "").split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    if ":" in (address or ""):
        return address.split(":")[0] + ":…"
    return "gizlendi"


# ─── Individual checks ───────────────────────────────────────────────────────────

def _dns_query(server: str, name: str, timeout: float = 4.0) -> List[str]:
    """Minimal A-record lookup against a specific server."""
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    query = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, 53))
        answer, _ = sock.recvfrom(4096)
    except Exception:
        return []
    finally:
        sock.close()

    try:
        pos = 12
        while answer[pos]:
            pos += 1 + answer[pos]
        pos += 5
        found = []
        for _ in range(struct.unpack_from("!H", answer, 6)[0]):
            if answer[pos] & 0xC0:
                pos += 2
            else:
                while answer[pos]:
                    pos += 1 + answer[pos]
                pos += 1
            rtype = struct.unpack_from("!H", answer, pos)[0]
            rdlen = struct.unpack_from("!H", answer, pos + 8)[0]
            if rtype == 1 and rdlen == 4:
                found.append(socket.inet_ntoa(answer[pos + 10:pos + 14]))
            pos += 10 + rdlen
        return found
    except Exception:
        return []


def check_dns_hijack(host: str = "discord.com") -> Tuple[bool, str]:
    """
    Compare what the configured resolver says against a known-good one.
    Different answers with a failing certificate is the signature of a hijack.
    """
    adapters = dns_manager.get_network_adapters()
    system_servers: List[str] = []
    for adapter in adapters:
        system_servers = dns_manager.get_current_dns(adapter).get("ipv4") or []
        if system_servers:
            break
    if not system_servers:
        return False, "Sistem DNS sunucusu okunamadı (DHCP)."

    # 127.0.0.1 is our own resolver. Testing it proves nothing about the ISP —
    # and if the app is not running it is simply dead, so fall through to the
    # next configured server (the safety net) instead of reporting a failure.
    loopback = {dns_manager.LOCAL_RESOLVER_IPV4, "::1"}
    usable = [s for s in system_servers if s not in loopback]
    if not usable:
        if doh_proxy.is_running():
            return False, "Sistem DNS'i yerel şifreli çözümleyiciye bakıyor — kaçırma mümkün değil."
        return False, ("Sistem DNS'i 127.0.0.1'e bakıyor ama çözümleyici kapalı; "
                       "yedek sunucu devrede. Uygulamayı açıp Kanal 2'yi etkinleştirin.")

    server = usable[0]
    local = _dns_query(server, host)
    reference = _dns_query("1.1.1.1", host)

    if not local:
        return False, f"Sistem DNS ({server}) yanıt vermedi."
    if not reference:
        return False, "Karşılaştırma için 1.1.1.1'e ulaşılamadı."

    if set(local) & set(reference):
        return False, f"DNS temiz — {server} ile 1.1.1.1 aynı adresleri veriyor."

    verdict = f"⚠ DNS KAÇIRMA: sistem DNS'i {local[0]} diyor, gerçek adres {reference[0]}."
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((local[0], 443), 4) as raw:
            ctx.wrap_socket(raw, server_hostname=host)
        verdict += " (Yine de sertifika doğrulandı — CDN farkı olabilir.)"
        return True, verdict
    except ssl.SSLError:
        return True, verdict + " Sahte sertifika doğrulandı — kesin engel."
    except Exception:
        return True, verdict


def tls_probe(host: str, timeout: float = 6.0) -> Tuple[bool, float, str]:
    ctx = ssl.create_default_context()
    started = time.time()
    try:
        with socket.create_connection((host, 443), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                return True, (time.time() - started) * 1000, tls.version() or "TLS"
    except Exception as e:
        return False, (time.time() - started) * 1000, f"{type(e).__name__}: {e}"[:70]


def wire_proof() -> Tuple[bool, str]:
    """
    Run a real ClientHello through the engine's own code path (no driver needed)
    and confirm the hostname is genuinely split across segments.
    """
    try:
        import windivert as wd

        ctx = ssl.create_default_context()
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ctx.wrap_bio(incoming, outgoing, server_hostname="gateway.discord.gg")
        try:
            tls.do_handshake()
        except ssl.SSLWantReadError:
            pass
        hello = outgoing.read()

        tcp = struct.pack("!HHIIBBHHH", 52345, 443, 3_000_000, 99, (5 << 4), 0x18, 64240, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(hello), 0xABCD,
                         0x4000, 128, dp.PROTO_TCP, 0,
                         bytes([192, 168, 1, 50]), bytes([162, 159, 128, 233]))

        captured: List[bytes] = []

        class _Recorder:
            def send(self, packet, addr, recalc_checksums=True):
                captured.append(bytes(packet))
                return len(packet)

            def send_precomputed(self, packet, addr):
                captured.append(bytes(packet))
                return len(packet)

        engine = dpi_engine.NativeDpiEngine(dpi_engine.PRESETS["superonline"])
        address = wd.WinDivertAddress()
        address.outbound = True
        engine._handle_packet(_Recorder(), bytearray(ip + tcp + hello), address)

        leaked = any(b"gateway.discord.gg" in dp.parse_tcp_packet(p).payload for p in captured)
        return (not leaked,
                f"{len(captured)} paket üretildi, alan adı hiçbirinde "
                f"{'GÖRÜNÜYOR (!)' if leaked else 'görünmüyor'}.")
    except Exception as e:
        return False, f"Kanıt testi çalıştırılamadı: {e}"


# ─── Report ──────────────────────────────────────────────────────────────────────

def collect_report(on_progress: Optional[Callable[[str], None]] = None,
                   hosts: Sequence[str] = TEST_HOSTS) -> str:
    """Assemble the full diagnostic report as shareable Turkish text."""
    say = on_progress or (lambda text: None)
    lines: List[str] = []

    def section(title: str) -> None:
        lines.append("")
        lines.append(title)
        lines.append("─" * len(title))

    lines.append("DISCORD DNS v3.6 — TANILAMA RAPORU")
    lines.append("=" * 42)
    lines.append(f"Tarih      : {time.strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"Sistem     : {platform.system()} {platform.release()} ({platform.machine()})")
    lines.append(f"Python     : {sys.version.split()[0]}")

    section("1. Sürücü ve yetki")
    say("Sürücü kontrol ediliyor…")
    import admin_utils
    is_admin = admin_utils.is_admin()
    lines.append(f"Yönetici    : {'EVET' if is_admin else 'HAYIR — motor çalışamaz'}")
    ok, message = dpi_bypass.self_test()
    lines.append(f"WinDivert   : {'OK' if ok else 'BAŞARISIZ'} — {message}")

    section("2. Motor durumu")
    engine_name = dpi_bypass.active_engine()
    lines.append(f"Aktif motor : {engine_name or 'kapalı'}")
    stats = dpi_bypass.engine_stats()
    if stats:
        lines.append(f"Paket       : görülen {stats.get('packets_seen')}, "
                     f"yeniden yazılan {stats.get('packets_rewritten')}, "
                     f"parça {stats.get('segments_sent')}, sahte {stats.get('decoys_sent')}")
        lines.append(f"Ek koruma   : engellenen RST {stats.get('rst_blocked', 0)}, "
                     f"öğrenilen mesafe {stats.get('hops_learned', 0)}")
        lines.append(f"Hata        : {stats.get('errors')}")
    lines.append(f"DoH         : {'çalışıyor' if doh_proxy.is_running() else 'kapalı'}")
    if doh_proxy.is_running():
        doh_stats = doh_proxy.stats()
        lines.append(f"              {doh_stats.get('queries')} sorgu, "
                     f"{doh_stats.get('cache_hits')} önbellek, "
                     f"sağlayıcı {doh_stats.get('active_upstream')}")

    section("3. İSS ve DNS")
    say("İSS ve DNS kontrol ediliyor…")
    isp = dpi_bypass.detect_isp()
    lines.append(f"İSS         : {isp.get('isp')}")
    lines.append(f"Genel IP    : {mask_ip(isp.get('ip', ''))}  (maskelendi)")
    lines.append(f"Öneri       : {isp.get('recommended_channel')}")
    hijacked, verdict = check_dns_hijack()
    lines.append(f"DNS testi   : {verdict}")

    section("4. Gerçek bağlantı testi")
    for host in hosts:
        say(f"{host} deneniyor…")
        good, ms, detail = tls_probe(host)
        lines.append(f"{host:24s} {'OK  ' if good else 'FAIL'} {ms:6.0f} ms  {detail}")

    section("5. Paket kanıtı (sürücüsüz)")
    say("Paket kanıtı üretiliyor…")
    proof_ok, proof_msg = wire_proof()
    lines.append(f"{'OK' if proof_ok else 'SORUN'} — {proof_msg}")

    section("6. Sonuç")
    if not is_admin:
        lines.append("Uygulamayı yönetici olarak çalıştırın — motor aksi hâlde açılamaz.")
    elif hijacked:
        lines.append("İSS'niz DNS yanıtlarını değiştiriyor → Kanal 2 (şifreli DNS) kullanın.")
    elif not ok:
        lines.append("WinDivert sürücüsü açılamıyor → Kanal 3 kullanılamaz, Kanal 1/2 çalışır.")
    else:
        lines.append("Sistem sağlıklı görünüyor.")

    lines.append("")
    lines.append("Bu rapor paylaşılabilir: genel IP maskelenmiştir, kişisel veri içermez.")
    say("Tanılama tamamlandı.")
    return "\n".join(lines)
