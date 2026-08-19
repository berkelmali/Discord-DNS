"""
Discord DNS v3.6 — Live Engine Diagnostic (REQUIRES ADMINISTRATOR)
Starts the native DPI engine and the local DoH resolver against real traffic,
proves they actually rewrite packets / answer queries, then shuts everything
down and verifies nothing is left behind.

Run in an elevated terminal:
    python -m tests.test_dpi_live
"""

import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import admin_utils
import dns_manager
import doh_proxy
import dpi_bypass
import dpi_engine
import windivert

TEST_HOSTS = ("discord.com", "gateway.discord.gg", "cloudflare.com")
DOH_TEST_PORT = 15353


def tls_handshake(host: str, timeout: float = 6.0) -> tuple[bool, float, str]:
    """Open a real TLS connection so the engine sees a genuine ClientHello."""
    ctx = ssl.create_default_context()
    start = time.time()
    try:
        with socket.create_connection((host, 443), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                version = tls.version() or "?"
        return True, (time.time() - start) * 1000, version
    except Exception as e:
        return False, (time.time() - start) * 1000, str(e)[:60]


def section(title: str) -> None:
    print("\n" + title)
    print("-" * len(title))


def main() -> int:
    print("=" * 64)
    print("  DISCORD DNS v3.6 -- LIVE ENGINE DIAGNOSTIC")
    print("=" * 64)

    failures = 0

    section("[1/6] Administrator & driver")
    is_admin = admin_utils.is_admin()
    print(f"  Yönetici yetkisi : {'EVET' if is_admin else 'HAYIR'}")
    if not is_admin:
        print("\n  !! Bu testi yönetici olarak açılmış bir terminalde çalıştırın.")
        return 1

    print(f"  WinDivert klasörü: {windivert.DRIVER_DIR}")
    ok, msg = dpi_bypass.self_test()
    print(f"  Sürücü testi     : {'OK' if ok else 'BAŞARISIZ'} — {msg}")
    if not ok:
        failures += 1
        print("  Sürücü açılamadığı için motor testleri atlanıyor.")
        return 1

    section("[2/6] Baseline (motor kapalıyken TLS)")
    baseline = {}
    hijack_suspects = []
    for host in TEST_HOSTS:
        good, ms, info = tls_handshake(host)
        baseline[host] = good
        print(f"  {host:22s} {'OK ' if good else 'FAIL'} {ms:7.0f} ms  {info}")
        if not good and "CERTIFICATE_VERIFY_FAILED" in info:
            hijack_suspects.append(host)

    if hijack_suspects:
        print("\n  ! Sertifika doğrulaması başarısız: " + ", ".join(hijack_suspects))
        print("    Bu, motorun değil İSS'nin sorunudur — DNS yanıtı sahte bir IP'ye")
        print("    yönlendiriliyor (DNS hijacking). Çözümü Kanal 2 (yerel DoH).")

    section("[3/6] Yerel DPI motoru")
    mode = dpi_bypass.resolve_mode(dpi_bypass.detect_isp())
    print(f"  Seçilen strateji : {mode} ({dpi_engine.PRESETS[mode].name})")
    ok, msg = dpi_bypass.start_dpi_bypass(mode=mode)
    print(f"  Başlatma         : {'OK' if ok else 'BAŞARISIZ'} — {msg}")
    if not ok:
        failures += 1
    else:
        print(f"  Aktif motor      : {dpi_bypass.active_engine()}")
        time.sleep(0.5)
        for host in TEST_HOSTS:
            good, ms, info = tls_handshake(host)
            flag = "OK " if good else "FAIL"
            regressed = " (motor açıkken bozuldu!)" if baseline.get(host) and not good else ""
            print(f"  {host:22s} {flag} {ms:7.0f} ms  {info}{regressed}")
            if baseline.get(host) and not good:
                failures += 1

        stats = dpi_bypass.engine_stats()
        print(f"\n  Görülen paket    : {stats.get('packets_seen')}")
        print(f"  Yeniden yazılan  : {stats.get('packets_rewritten')}")
        print(f"  Gönderilen parça : {stats.get('segments_sent')}")
        print(f"  Sahte paket      : {stats.get('decoys_sent')}")
        print(f"  Hata             : {stats.get('errors')}")
        print(f"  Son alan adları  : {', '.join(stats.get('last_hosts', [])[-6:]) or '—'}")

        if not stats.get("packets_rewritten"):
            failures += 1
            print("  !! Hiç paket yeniden yazılmadı — filtre veya sürücü sorunu.")

    section("[4/6] Motoru durdurma")
    ok, msg = dpi_bypass.stop_dpi_bypass()
    print(f"  Durdurma         : {'OK' if ok else 'BAŞARISIZ'} — {msg}")
    still = dpi_bypass.is_dpi_bypass_running()
    print(f"  Kalan süreç      : {'VAR (!)' if still else 'yok'}")
    if still:
        failures += 1
    good, ms, info = tls_handshake("discord.com")
    print(f"  Motorsuz TLS     : {'OK' if good else 'FAIL'} {ms:.0f} ms {info}")

    section("[5/6] Yerel DoH çözümleyici")
    proxy = doh_proxy.LocalDohProxy(port=DOH_TEST_PORT)
    ok, msg = proxy.start()
    print(f"  Başlatma         : {'OK' if ok else 'BAŞARISIZ'} — {msg}")
    if not ok:
        failures += 1
    else:
        import struct
        for host in TEST_HOSTS:
            labels = b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\x00"
            query = struct.pack("!HHHHHH", 0x2024, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(6)
            t0 = time.time()
            try:
                sock.sendto(query, ("127.0.0.1", DOH_TEST_PORT))
                answer, _ = sock.recvfrom(4096)
                ancount = struct.unpack_from("!H", answer, 6)[0]
                print(f"  {host:22s} {ancount} kayıt  {(time.time() - t0) * 1000:6.0f} ms")
                if not ancount:
                    failures += 1
            except Exception as e:
                failures += 1
                print(f"  {host:22s} HATA: {e}")
            finally:
                sock.close()
        print(f"  İstatistik       : {proxy.stats.snapshot()}")
        ok, msg = proxy.stop()
        print(f"  Durdurma         : {'OK' if ok else 'BAŞARISIZ'} — {msg}")

    section("[6/6] DNS durumu (değiştirilmedi)")
    adapters = dns_manager.get_network_adapters()
    for adapter in adapters[:3]:
        state = dns_manager.get_current_dns(adapter)
        print(f"  {adapter:22s} {state['preset_name']:12s} v4={state['ipv4']} v6={state['ipv6']}")

    print("\n" + "=" * 64)
    print("  SONUÇ: " + ("TÜM TESTLER GEÇTİ" if failures == 0 else f"{failures} SORUN BULUNDU"))
    print("=" * 64)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
