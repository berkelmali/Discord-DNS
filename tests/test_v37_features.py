"""
Discord DNS v3.7 — Feature Test Suite
Covers what v3.7 added: the sequence-overlap strategy, voice (UDP) decoys,
the extended Discord domain list, user options over presets, network memory,
the DNS leak test / browser secure-DNS parsing and the update checker.

Needs no Administrator rights and touches no traffic — packets are fed to the
engine directly and "sent" into a list.

Run: python -m tests.test_v37_features
"""

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import dns_manager
import dpi_engine
import dpi_packets as dp
import leak_test
import network_memory
import updater
import version
import windivert as wd
from tests.test_dpi_engine import build_client_hello, build_ipv4_tcp

PASSED = 0
FAILED = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  [PASS] {label}")
    else:
        FAILED += 1
        print(f"  [FAIL] {label}  {detail}")


class FakeHandle:
    """Collects what the engine would have put on the wire."""

    def __init__(self):
        self.sent = []

    def send(self, packet, addr, recalc_checksums=True):
        self.sent.append(bytes(packet))
        return True

    def send_precomputed(self, packet, addr):
        self.sent.append(bytes(packet))
        return True


def outbound_addr() -> wd.WinDivertAddress:
    addr = wd.WinDivertAddress()
    addr.outbound = 1
    return addr


def build_ipv4_udp(payload: bytes, dst_port: int = 50003, src_port: int = 61000,
                   dst=(66, 22, 196, 10)) -> bytes:
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    total = 20 + len(udp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1111, 0, 128, 17, 0,
                     bytes([192, 168, 1, 50]), bytes(dst))
    return ip + udp + payload


# ─── Engine: sequence overlap ────────────────────────────────────────────────────

def test_seqovl():
    print("\n[1] Sıra örtüşmesi (seqovl)")
    config = dpi_engine.PRESETS["seqovl"]
    check("'seqovl' profili tanımlı ve taramada", "seqovl" in dpi_engine.AGGRESSION_LADDER)
    check("örtüşme 568 bayt", config.seqovl == 568)

    pattern = dp.seqovl_pattern(568)
    check("desen tam istenen uzunlukta", len(pattern) == 568)
    found = dp.extract_sni(pattern)
    check("desen sahte bir SNI taşıyor", bool(found) and found[0] == "www.google.com",
          str(found))

    engine = dpi_engine.NativeDpiEngine(config)
    handle = FakeHandle()
    hello = build_client_hello("gateway.discord.gg")
    seq = 0x10000000
    engine._handle_packet(handle, bytearray(build_ipv4_tcp(hello, seq=seq)), outbound_addr())

    segs = [dp.parse_tcp_packet(p) for p in handle.sent]
    segs = [s for s in segs if s is not None and s.payload]
    check("en az iki parça gönderildi", len(segs) >= 2, str(len(segs)))
    if len(segs) >= 2:
        first = segs[0]
        check("ilk parça 568 bayt geriden başlıyor",
              first.seq == (seq - 568) & 0xFFFFFFFF, hex(first.seq))
        check("ilk parçanın başı sahte el sıkışma", first.payload[:568] == pattern)
        # What the server keeps: bytes from the real sequence start onward
        stream = {}
        for s in segs:
            for i, b in enumerate(s.payload):
                stream.setdefault((s.seq + i) & 0xFFFFFFFF, b)
        rebuilt = bytes(stream[(seq + i) & 0xFFFFFFFF] for i in range(len(hello)))
        check("sunucunun birleştirdiği akış özgün ClientHello", rebuilt == hello)
        dpi_view = dp.extract_sni(first.payload)
        check("DPI'nın ilk okuduğu SNI sahte", bool(dpi_view) and dpi_view[0] == "www.google.com")
    check("istatistik sayıldı", engine.stats.seqovl_sent == 1)


# ─── Engine: voice (UDP) decoys ──────────────────────────────────────────────────

def test_udp_voice():
    print("\n[2] Sesli sohbet (UDP) koruması")
    config = dpi_engine.replace(dpi_engine.PRESETS["general"], udp_voice=True)
    engine = dpi_engine.NativeDpiEngine(config)
    handle = FakeHandle()
    payload = os.urandom(74)
    packet = build_ipv4_udp(payload)

    for _ in range(4):
        engine._handle_udp(handle, bytearray(packet), outbound_addr())

    reals = [p for p in handle.sent if p == packet]
    decoys = [p for p in handle.sent if p != packet]
    expected = config.udp_fake_repeats * config.udp_cutoff
    check("gerçek paketler değişmeden geçti", len(reals) == 4, str(len(reals)))
    check(f"yalnızca ilk {config.udp_cutoff} pakete sahte eklendi",
          len(decoys) == expected, f"{len(decoys)} != {expected}")
    if decoys:
        d = dp.parse_udp_packet(decoys[0])
        check("sahte paket aynı hedefe gidiyor",
              d is not None and d.dst_port == 50003 and d.dst_ip == bytes([66, 22, 196, 10]))
        check("UDP uzunluk alanı doğru",
              struct.unpack_from("!H", decoys[0], 24)[0] == 8 + len(payload))
        check("IP toplam uzunluk doğru",
              struct.unpack_from("!H", decoys[0], 2)[0] == len(decoys[0]))
        check("sahte içerik gerçekten farklı", d is not None and d.payload != payload)

    engine._handle_udp(handle, bytearray(build_ipv4_udp(payload, src_port=61001)), outbound_addr())
    check("yeni akış yeniden korunuyor", engine.stats.udp_flows == 2)

    impostor = outbound_addr()
    impostor.impostor = 1
    before = len(handle.sent)
    engine._handle_udp(handle, bytearray(packet), impostor)
    check("kendi enjekte ettiğimiz pakete dokunulmuyor", len(handle.sent) == before + 1)

    check("filtre ses port aralıklarını kapsıyor",
          "50000" in dpi_engine.UDP_VOICE_FILTER and "19294" in dpi_engine.UDP_VOICE_FILTER)
    check("ses koruması varsayılan olarak kapalı",
          not any(p.udp_voice for p in dpi_engine.PRESETS.values()))


# ─── Engine: domain list & user options ──────────────────────────────────────────

def test_domains_and_options():
    print("\n[3] Alan adı listesi ve kullanıcı seçenekleri")
    check("21 Discord alan adı", len(dpi_engine.DISCORD_DOMAINS) == 21)
    only = dpi_engine.PRESETS["discord_only"]
    for host in ("discord.gg", "cdn.discordapp.com", "media.discordapp.net",
                 "discord-attachments-uploads-prd.storage.googleapis.com", "dis.gd"):
        check(f"discord_only → {host}", only.matches_host(host))
    check("discord_only google.com'a dokunmuyor", not only.matches_host("www.google.com"))
    check("discord_only benzer adlara kanmıyor", not only.matches_host("notdiscord.com"))

    saved = dpi_engine.user_options()
    try:
        dpi_engine.set_user_options(udp_voice=True, bogus=True)
        check("bilinmeyen seçenek yok sayılıyor", "bogus" not in dpi_engine.user_options())
        check("seçenek profile ekleniyor", dpi_engine.configured("ttnet").udp_voice)
        check("profilin kendisi değişmiyor", not dpi_engine.PRESETS["ttnet"].udp_voice)
        check("profilin diğer alanları korunuyor",
              dpi_engine.configured("ttnet").name == dpi_engine.PRESETS["ttnet"].name)
        check("bilinmeyen profil 'general'e düşüyor",
              dpi_engine.configured("yok").name == dpi_engine.PRESETS["general"].name)
    finally:
        dpi_engine.set_user_options(**saved)


# ─── Network memory ──────────────────────────────────────────────────────────────

def test_network_memory():
    print("\n[4] Ağ hafızası")
    netsh = ("    Name                   : Wi-Fi\n"
             "    SSID                   : EvAgi 5G\n"
             "    BSSID                  : aa:bb:cc:dd:ee:ff\n")
    check("SSID okunuyor (BSSID karışmıyor)", network_memory.parse_ssid(netsh) == "EvAgi 5G")
    check("SSID yoksa boş", network_memory.parse_ssid("Kablosuz arabirim yok") == "")
    check("AS numarası ayrıştırılıyor",
          network_memory.parse_asn({"as": "AS12735 TurkNet Iletisim"}) == "AS12735")
    check("AS yoksa İSS adı", network_memory.parse_asn({"isp": "Superonline"}) == "Superonline")

    a = network_memory.fingerprint("AS1", "Ev", "Wi-Fi", "192.168.1.1")
    b = network_memory.fingerprint("AS1", "Is", "Wi-Fi", "192.168.1.1")
    check("farklı ağ → farklı parmak izi", a != b)
    check("parmak izi kararlı ve kısa",
          a == network_memory.fingerprint("as1", "ev", "Wi-Fi", "192.168.1.1") and len(a) == 16)
    check("parmak izi ham bilgiyi içermiyor", "192.168" not in a)

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "networks.json")
        check("bilinmeyen ağ → None", network_memory.recall(a, path) is None)
        network_memory.remember(a, "Test · Ev", "⚡ Kanal 3: DPI Bypass", "seqovl", "Cloudflare", path)
        network_memory.remember(a, "Test · Ev", "⚡ Kanal 3: DPI Bypass", "seqovl", "Cloudflare", path)
        got = network_memory.recall(a, path)
        check("kaydedilen ayar geri okunuyor",
              got is not None and got["dpi_profile"] == "seqovl" and "Kanal 3" in got["channel"])
        check("başarı sayacı artıyor", got is not None and got["successes"] == 2)

        network_memory.remember(b, "Test · İş", "🟢 Kanal 1: Standart", None, "Google", path)
        got_b = network_memory.recall(b, path)
        check("profilsiz kanal → profil None", got_b is not None and got_b["dpi_profile"] is None)

        with open(path, "w", encoding="utf-8") as f:
            f.write('{"x": {"channel": 5}, "y": "bozuk"}')
        check("bozuk kayıt reddediliyor", network_memory.recall("x", path) is None)
        with open(path, "w", encoding="utf-8") as f:
            f.write("[1, 2")
        check("bozuk dosya çökertmiyor", network_memory.recall(a, path) is None)

        for i in range(network_memory.MAX_ENTRIES + 5):
            network_memory.remember(f"k{i}", "", "🟢 Kanal 1: Standart", None, "Cloudflare", path)
        check("kayıt sayısı sınırlı", network_memory.count(path) <= network_memory.MAX_ENTRIES)
        check("unutma çalışıyor", network_memory.forget(f"k{network_memory.MAX_ENTRIES + 4}", path))
        network_memory.forget_all(path)
        check("hepsini unutma", network_memory.count(path) == 0)


# ─── Leak test & browsers ────────────────────────────────────────────────────────

def test_leak_test():
    print("\n[5] DNS sızıntı testi ve tarayıcı şifreli DNS")
    check("Cloudflare çıkışı tanınıyor", leak_test.operator_for("104.23.182.137") == "Cloudflare")
    check("Cloudflare (172.70) tanınıyor", leak_test.operator_for("172.70.51.39") == "Cloudflare")
    check("Google tanınıyor", leak_test.operator_for("172.217.40.1") == "Google")
    check("Quad9 tanınıyor", leak_test.operator_for("9.9.9.9") == "Quad9")
    check("İSS adresi tanınmıyor", leak_test.operator_for("203.0.113.10") is None)
    check("bozuk adres güvenli", leak_test.operator_for("abc") is None)

    ok = leak_test.LeakResult("104.23.1.1", "Cloudflare", "Cloudflare")
    bad = leak_test.LeakResult("203.0.113.10", None, "Cloudflare")
    idle = leak_test.LeakResult("203.0.113.10", None, None)
    check("beklenen sağlayıcı → sızıntı yok", not ok.leaking and "Sızıntı yok" in ok.verdict)
    check("başka sunucu → sızıntı", bad.leaking and "sızıntı" in bad.verdict.lower())
    check("yönetilmeyen DNS sızıntı sayılmıyor", not idle.leaking)
    check("adres karardaki metinde yok", "203.0" not in bad.verdict)

    check("DoH açıkken beklenen = üst sunucu",
          leak_test.expected_operator(True, "Cloudflare (cloudflare-dns.com)", "", False) == "Cloudflare")
    check("DHCP → beklenen yok", leak_test.expected_operator(False, "", "Cloudflare", True) is None)
    check("elle yazılmış 8.8.8.8 → Google",
          leak_test.expected_operator(False, "", "Custom", False, ["8.8.8.8"]) == "Google")

    check("Chromium varsayılanı otomatik", leak_test.parse_chromium_state({}) == ("automatic", ""))
    check("Chromium güvenli + sağlayıcı",
          leak_test.parse_chromium_state({"dns_over_https": {
              "mode": "secure", "templates": "https://dns.google/dns-query{?dns}"}})
          == ("secure", "dns.google"))
    check("Opera kapalı", leak_test.parse_chromium_state(
        {"dns_over_https": {"mode": "off", "templates": ""}})[0] == "off")
    check("Firefox yalnız-TRR → secure", leak_test.parse_firefox_prefs(
        'user_pref("network.trr.mode", 3);\nuser_pref("network.trr.uri", '
        '"https://mozilla.cloudflare-dns.com/dns-query");') == ("secure", "mozilla.cloudflare-dns.com"))
    check("Firefox varsayılan → off", leak_test.parse_firefox_prefs("")[0] == "off")
    check("Firefox mode 5 → off",
          leak_test.parse_firefox_prefs('user_pref("network.trr.mode", 5);')[0] == "off")

    secure = leak_test.BrowserDns("Chrome", "secure", "dns.google")
    check("güvenli mod sistemi atlıyor", secure.bypasses_system and "AÇIK" in secure.summary)
    lines = leak_test.report_lines(bad, [secure])
    check("rapor tarayıcı notunu içeriyor", any("tarayıcı kendi şifreli" in l for l in lines))
    check("rapor IP'yi maskeliyor", any("203.0.x.x" in l for l in lines)
          and not any("203.0.113.10" in l for l in lines))


# ─── Update checker ──────────────────────────────────────────────────────────────

def test_updater():
    print("\n[6] Güncelleme denetleyicisi")
    check("sürüm ayrıştırma", version.parse_version("v3.10.1-beta") == (3, 10, 1))
    check("kısa sürüm", version.parse_version("3.7") == (3, 7, 0))
    check("3.10 > 3.9 (metin değil sayı)", updater.is_newer("v3.10.0", "3.9.0"))
    check("aynı sürüm yeni değil", not updater.is_newer("v3.7.0", "3.7.0"))
    check("eski sürüm yeni değil", not updater.is_newer("v3.6.0", "3.7.0"))
    check("anlamsız etiket yeni değil", not updater.is_newer("latest", "3.7.0"))

    info = updater.interpret({"tag_name": "v9.0.0",
                              "html_url": f"{version.REPO_URL}/releases/tag/v9.0.0"})
    check("yeni sürüm algılanıyor", info.available and info.latest == "v9.0.0")
    check("bağlantı proje sayfası", info.url.startswith(version.REPO_URL + "/releases"))
    evil = updater.interpret({"tag_name": "v9.0.0", "html_url": "https://example.com/x.exe"})
    check("yabancı bağlantı reddediliyor", evil.url == version.RELEASES_URL)
    check("taslak sürüm yok sayılıyor",
          not updater.interpret({"tag_name": "v9.0.0", "draft": True}).available)
    check("ön sürüm yok sayılıyor",
          not updater.interpret({"tag_name": "v9.0.0", "prerelease": True}).available)
    check("bozuk yanıt güvenli", not updater.interpret([]).available)
    check("istek kişisel veri taşımıyor",
          version.REPO_SLUG in updater.API_URL and "?" not in updater.API_URL)


# ─── Adapter ordering ────────────────────────────────────────────────────────────

def test_adapter_order():
    print("\n[7] Ağ kartı sıralaması")
    items = [
        {"Name": "Yerel Ağ Bağlantısı* 10", "Desc": "Microsoft Wi-Fi Direct Virtual Adapter #2",
         "HasRoute": False, "Metric": 99999},
        {"Name": "Ethernet 2", "Desc": "VirtualBox Host-Only Ethernet Adapter",
         "HasRoute": False, "Metric": 99999},
        {"Name": "Wi-Fi", "Desc": "Intel(R) Wi-Fi 6 AX201", "HasRoute": True, "Metric": 75},
        {"Name": "Ethernet", "Desc": "Realtek Gaming GbE", "HasRoute": True, "Metric": 25},
        {"Name": "Bluetooth Ağ Bağlantısı", "Desc": "Bluetooth Device (PAN)",
         "HasRoute": False, "Metric": 99999},
        "bozuk", {"Name": None}, {"Name": "Garip", "Metric": "x", "HasRoute": False},
    ]
    order = dns_manager.order_adapters(items)
    check("en iyi rotalı kart başta", order[:2] == ["Ethernet", "Wi-Fi"], str(order))
    check("Wi-Fi Direct sanal kartı elendi", not any("Ağ Bağlantısı*" in n for n in order))
    check("Bluetooth elendi", not any("Bluetooth" in n for n in order))
    check("rotasız sanal kart sona kaldı", order.index("Ethernet 2") > order.index("Wi-Fi"))
    check("bozuk girdiler çökertmiyor", "Garip" in order and len(order) == 4)
    check("boş liste güvenli", dns_manager.order_adapters([]) == [])


def run_tests():
    print("=" * 62)
    print(f"  {version.APP_TITLE.upper()} -- v3.7 FEATURE TEST SUITE")
    print("=" * 62)
    test_seqovl()
    test_udp_voice()
    test_domains_and_options()
    test_network_memory()
    test_leak_test()
    test_updater()
    test_adapter_order()
    print("\n" + "=" * 62)
    print(f"  {PASSED} passed, {FAILED} failed")
    print("=" * 62)
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
