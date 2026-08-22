"""
Discord DNS v3.6 — Native DPI Engine Test Suite
Validates the packet surgery (parsing, SNI extraction, splitting, rebuilding)
with synthetic packets. Needs no Administrator rights and touches no traffic.

Run: python -m tests.test_dpi_engine   (or python tests/test_dpi_engine.py)
"""

import os
import struct
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import dpi_packets as dp
import dpi_engine


# ─── Synthetic packet builders ───────────────────────────────────────────────────

def build_client_hello(hostname: str = "gateway.discord.gg") -> bytes:
    """A structurally valid TLS 1.2 ClientHello carrying one SNI extension."""
    host = hostname.encode()

    sni_body = b"\x00" + struct.pack("!H", len(host)) + host           # type + len + host
    sni_ext_data = struct.pack("!H", len(sni_body)) + sni_body          # server_name_list
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data

    extensions = sni_ext
    body = (
        b"\x03\x03"                       # client version TLS 1.2
        + bytes(range(32))                # random
        + b"\x00"                         # session id length
        + struct.pack("!H", 4) + b"\x13\x01\x13\x02"   # cipher suites
        + b"\x01\x00"                     # compression methods
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body       # 3-byte length
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def build_ipv4_tcp(payload: bytes, src_port: int = 51000, dst_port: int = 443,
                   seq: int = 1000, ttl: int = 128) -> bytes:
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, 0,
        (5 << 4), 0x18,                   # data offset 5 words, PSH+ACK
        64240, 0, 0,
    )
    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1234, 0x4000, ttl, dp.PROTO_TCP, 0,
        bytes([192, 168, 1, 50]), bytes([162, 159, 128, 233]),
    )
    return ip + tcp + payload


def build_ipv6_tcp(payload: bytes, seq: int = 2000) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 51000, 443, seq, 0, (5 << 4), 0x18, 64240, 0, 0)
    ip = (
        b"\x60\x00\x00\x00"
        + struct.pack("!H", len(tcp) + len(payload))
        + bytes([dp.PROTO_TCP, 64])
        + bytes(16)                        # src
        + bytes(15) + b"\x01"              # dst
    )
    return ip + tcp + payload


def build_http_request(host: str = "discord.com") -> bytes:
    return (f"GET /api/v9/gateway HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: Discord/1.0\r\nAccept: */*\r\n\r\n").encode()


# ─── Assertions ──────────────────────────────────────────────────────────────────

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


# ─── Tests ───────────────────────────────────────────────────────────────────────

def test_parsing():
    print("\n[1/6] IPv4 / IPv6 TCP parsing")
    hello = build_client_hello()
    packet = build_ipv4_tcp(hello)
    pkt = dp.parse_tcp_packet(packet)
    check("IPv4 packet parsed", pkt is not None)
    check("payload matches ClientHello", pkt.payload == hello)
    check("sequence number read", pkt.seq == 1000, f"got {pkt.seq}")
    check("ports read", (pkt.src_port, pkt.dst_port) == (51000, 443))
    check("TLS handshake detected", pkt.is_tls_handshake)

    pkt6 = dp.parse_tcp_packet(build_ipv6_tcp(hello))
    check("IPv6 packet parsed", pkt6 is not None and pkt6.version == 6)
    check("IPv6 payload matches", pkt6.payload == hello)

    check("garbage rejected", dp.parse_tcp_packet(b"\x00" * 8) is None)
    check("UDP rejected", dp.parse_tcp_packet(
        build_ipv4_tcp(hello)[:9] + bytes([dp.PROTO_UDP]) + build_ipv4_tcp(hello)[10:]) is None)


def test_sni():
    print("\n[2/6] TLS SNI extraction")
    for host in ("gateway.discord.gg", "discord.com", "a.io", "x" * 200 + ".com"):
        hello = build_client_hello(host)
        found = dp.extract_sni(hello)
        check(f"SNI '{host[:24]}' extracted", found is not None and found[0] == host,
              f"got {found[0] if found else None}")
        if found:
            _, off, length = found
            check(f"SNI span points at hostname ({host[:12]})",
                  hello[off:off + length].decode() == host)

    check("truncated ClientHello handled", dp.extract_sni(build_client_hello()[:30]) is None)
    check("non-TLS handled", dp.extract_sni(b"GET / HTTP/1.1\r\n\r\n") is None)
    check("empty handled", dp.extract_sni(b"") is None)


def test_http():
    print("\n[3/6] HTTP host handling")
    req = build_http_request("discord.com")
    kind, host, span = dp.describe_target(req)
    check("HTTP request classified", kind == "http", f"got {kind}")
    check("Host header value read", host == "discord.com", f"got {host}")

    mangled = dp.mangle_http_host_header(req, span[0])
    check("Host header case-mangled", b"hOsT:" in mangled)
    check("request length unchanged", len(mangled) == len(req))
    check("path untouched", mangled.startswith(b"GET /api/v9/gateway"))


def test_split():
    print("\n[4/6] Payload splitting")
    hello = build_client_hello("gateway.discord.gg")
    positions = dp.choose_split_positions(hello, base_split=2, split_at_sni=True)
    check("two cut positions chosen", len(positions) == 2, f"got {positions}")

    segments = dp.split_payload(hello, positions)
    check("three segments produced", len(segments) == 3, f"got {len(segments)}")
    check("segments reassemble to original",
          b"".join(chunk for _, chunk in segments) == hello)
    check("relative offsets are contiguous",
          all(segments[i][0] + len(segments[i][1]) == segments[i + 1][0]
              for i in range(len(segments) - 1)))

    # The point of the exercise: no single segment contains the whole hostname
    check("hostname never intact in one segment",
          not any(b"gateway.discord.gg" in chunk for _, chunk in segments))


def test_rebuild():
    print("\n[5/6] Segment rebuilding & checksums")
    hello = build_client_hello()
    pkt = dp.parse_tcp_packet(build_ipv4_tcp(hello, seq=5000))

    segments = dp.split_payload(hello, dp.choose_split_positions(hello))
    rebuilt = [dp.build_segment(pkt, chunk, pkt.seq + rel, ip_id=100 + i)
               for i, (rel, chunk) in enumerate(segments)]

    for i, seg in enumerate(rebuilt):
        view = dp.parse_tcp_packet(bytes(seg))
        check(f"segment {i} is a valid packet", view is not None)
        check(f"segment {i} IP total length correct",
              struct.unpack_from("!H", seg, 2)[0] == len(seg))
        check(f"segment {i} sequence number advanced",
              view.seq == 5000 + segments[i][0], f"got {view.seq}")
        check(f"segment {i} payload preserved", view.payload == segments[i][1])

    # IPv6 length field lives elsewhere
    pkt6 = dp.parse_tcp_packet(build_ipv6_tcp(hello))
    seg6 = dp.build_segment(pkt6, hello[:20], pkt6.seq)
    check("IPv6 payload length rewritten",
          struct.unpack_from("!H", seg6, 4)[0] == len(seg6) - 40)

    # badsum decoy: valid IP checksum, deliberately wrong TCP checksum
    decoy = dp.make_decoy_payload(hello, dp.extract_sni(hello)[1:])
    check("decoy keeps original length", len(decoy) == len(hello))
    check("decoy hides the real hostname", b"gateway.discord.gg" not in decoy)

    fake = dp.finalize_badsum(dp.build_segment(pkt, decoy, pkt.seq), pkt)
    check("decoy IPv4 header checksum valid",
          dp.ipv4_checksum(bytes(fake[:pkt.ip_hlen])) == 0)
    check("decoy TCP checksum intentionally wrong",
          struct.unpack_from("!H", fake, pkt.tcp_off + 16)[0] == 0xB4D5)

    # badseq is what keeps the decoy harmless when the NIC repairs checksums:
    # the server must drop it as out-of-window instead of answering its fake SNI
    cfg = dpi_engine.PRESETS["general"]
    badseq = (pkt.seq - cfg.decoy_seq_offset) & 0xFFFFFFFF
    decoy_pkt = dp.parse_tcp_packet(bytes(dp.build_segment(pkt, decoy, badseq)))
    check("decoy sequence is outside the receive window",
          (pkt.seq - decoy_pkt.seq) & 0xFFFFFFFF > 65535,
          f"offset {(pkt.seq - decoy_pkt.seq) & 0xFFFFFFFF}")
    check("badseq is the default fooling method", "badseq" in cfg.decoy_fooling)


def test_engine_config():
    print("\n[6/6] Engine configuration")
    check("presets defined", set(dpi_engine.PRESETS) >= {
        "superonline", "ttnet", "vodafone", "general", "discord_only"})

    discord_only = dpi_engine.PRESETS["discord_only"]
    check("discord preset matches subdomain", discord_only.matches_host("gateway.discord.gg"))
    check("discord preset matches apex", discord_only.matches_host("discord.com"))
    check("discord preset skips others", not discord_only.matches_host("example.com"))
    check("discord preset skips lookalikes", not discord_only.matches_host("notdiscord.com"))
    check("open preset matches everything", dpi_engine.PRESETS["general"].matches_host("example.com"))

    engine = dpi_engine.NativeDpiEngine(dpi_engine.PRESETS["general"])
    check("engine starts stopped", not engine.is_running)
    ok, _ = engine.stop()
    check("stopping an idle engine is safe", ok)
    check("stats snapshot shape", set(engine.stats.snapshot()) >= {
        "packets_seen", "packets_rewritten", "segments_sent", "decoys_sent"})

    valid, msg = True, ""
    try:
        import windivert
        valid, msg = windivert.check_filter(dpi_engine.TCP_FILTER)
    except OSError as e:
        msg = f"(WinDivert yüklenemedi: {e})"
    check("engine filter compiles", valid, msg)


def test_auto_ttl_and_rst():
    print("\n[7/8] Otomatik TTL & RST koruması")

    check("hop hesabı (Linux 64)", dp.infer_hop_count(57) == 7, f"got {dp.infer_hop_count(57)}")
    check("hop hesabı (Windows 128)", dp.infer_hop_count(120) == 8)
    check("hop hesabı (255 başlangıç)", dp.infer_hop_count(250) == 5)
    check("saçma TTL reddedilir", dp.infer_hop_count(0) is None)

    engine = dpi_engine.NativeDpiEngine(dpi_engine.PRESETS["hardened"])
    server = bytes([162, 159, 128, 233])

    check("mesafe bilinmeden otomatik TTL yok", engine._decoy_ttl(server) is None)
    engine._hops[server] = 9
    ttl = engine._decoy_ttl(server)
    check("mesafe öğrenilince TTL hesaplanır", ttl == 8, f"got {ttl}")
    check("TTL sunucuya ulaşmayacak kadar kısa", ttl is not None and ttl < 9)

    engine._hops[server] = 2          # too close to fake anything usefully
    check("çok yakın sunucuda TTL hilesi yapılmaz", engine._decoy_ttl(server) is None)

    # RST filtresi: sadece bizim dokunduğumuz akış ve sadece kısa süre
    hello = build_client_hello()
    pkt = dp.parse_tcp_packet(build_ipv4_tcp(hello))
    engine.config = dpi_engine.PRESETS["hardened"]
    engine._remember_flow(pkt)
    key = (pkt.dst_ip, pkt.dst_port, pkt.src_port)
    check("yeniden yazılan akış hatırlanır", key in engine._recent_flows)

    class Recorder:
        def __init__(self): self.forwarded = 0
        def send(self, packet, addr, recalc_checksums=True):
            self.forwarded += 1
            return len(packet)

    def inbound_rst(src_ip, src_port, dst_port):
        tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 500, 0, (5 << 4), 0x04, 0, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 57, dp.PROTO_TCP, 0,
                         src_ip, bytes([192, 168, 1, 50]))
        return bytearray(ip + tcp)

    import windivert as wd_mod
    addr = wd_mod.WinDivertAddress()

    engine._hops.clear()          # distance unknown → fall back to the flow window
    rec = Recorder()
    engine._handle_inbound(rec, inbound_rst(pkt.dst_ip, pkt.dst_port, pkt.src_port), addr)
    check("mesafe bilinmezken RST düşürülür", rec.forwarded == 0 and engine.stats.rst_blocked == 1)

    # Distance known: a reset from a middlebox arrives from noticeably closer
    # than the server, while the server's own reset matches its hop count.
    engine._remember_flow(pkt)
    engine._hops[pkt.dst_ip] = 14              # server is 14 hops away
    rec = Recorder()
    engine._handle_inbound(rec, inbound_rst(pkt.dst_ip, pkt.dst_port, pkt.src_port), addr)
    check("DPI kutusundan gelen (daha yakın) RST düşürülür",
          rec.forwarded == 0 and engine.stats.rst_blocked == 2)

    # Default: the TTL comparison is OFF. Measured on a TT mobile line, the
    # injected resets arrived with a TTL matching the server's distance, so the
    # check waved every one of them through and the strongest profiles blocked
    # nothing at all. Inside the window, a reset on a rewritten flow is hostile.
    engine._remember_flow(pkt)
    engine._hops[pkt.dst_ip] = 7               # matches the probe's TTL 57 → 7 hops
    rec = Recorder()
    engine._handle_inbound(rec, inbound_rst(pkt.dst_ip, pkt.dst_port, pkt.src_port), addr)
    check("varsayılan: mesafe uyuşsa bile RST düşürülür (TTL taklidine karşı)",
          rec.forwarded == 0 and engine.stats.rst_blocked == 3)

    # A DPI box firing several resets in a row must be blocked every time — the
    # flow entry deliberately survives the first block.
    rec = Recorder()
    engine._handle_inbound(rec, inbound_rst(pkt.dst_ip, pkt.dst_port, pkt.src_port), addr)
    check("art arda gelen ikinci RST de düşürülür",
          rec.forwarded == 0 and engine.stats.rst_blocked == 4)

    # Opt-in: networks where the check does help can still enable it
    engine.config = dpi_engine.DpiConfig(**{**dpi_engine.PRESETS["hardened"].__dict__,
                                            "rst_ttl_check": True})
    engine._remember_flow(pkt)
    rec = Recorder()
    engine._handle_inbound(rec, inbound_rst(pkt.dst_ip, pkt.dst_port, pkt.src_port), addr)
    check("rst_ttl_check açıkken mesafe uyuşan RST geçirilir",
          rec.forwarded == 1 and engine.stats.rst_blocked == 4)
    engine.config = dpi_engine.PRESETS["hardened"]

    engine._hops.clear()
    engine._remember_flow(pkt)

    rec = Recorder()
    engine._handle_inbound(rec, inbound_rst(bytes([9, 9, 9, 9]), 443, 40000), addr)
    check("ilgisiz akışın RST'si geçirilir", rec.forwarded == 1)

    engine._remember_flow(pkt)
    engine._recent_flows[key] = 0.0          # pretend it happened long ago
    rec = Recorder()
    engine._handle_inbound(rec, inbound_rst(pkt.dst_ip, pkt.dst_port, pkt.src_port), addr)
    check("zaman aşımına uğramış akışın RST'si geçirilir", rec.forwarded == 1)

    # SYN-ACK ile mesafe öğrenme
    def inbound_synack(src_ip, ttl):
        tcp = struct.pack("!HHIIBBHHH", 443, 52345, 1, 2, (5 << 4), 0x12, 0, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, ttl, dp.PROTO_TCP, 0,
                         src_ip, bytes([192, 168, 1, 50]))
        return bytearray(ip + tcp)

    engine._hops.clear()
    engine._handle_inbound(Recorder(), inbound_synack(bytes([1, 2, 3, 4]), 55), addr)
    check("SYN-ACK'ten mesafe öğrenilir", engine._hops.get(bytes([1, 2, 3, 4])) == 9,
          f"got {engine._hops}")
    check("istatistiğe yansır", engine.stats.hops_learned == 1)


def test_finder_and_diagnostics():
    print("\n[8/8] Strateji bulucu & tanılama")
    import diagnostics
    import strategy_finder as sf

    check("agresiflik merdiveni tanımlı", len(dpi_engine.AGGRESSION_LADDER) >= 5)

    # The strategy measured to work against a Turkish DPI box must be reached
    # early, not after eight failed attempts.
    ladder = dpi_engine.AGGRESSION_LADDER
    check("kanıtlanmış strateji merdivende erken geliyor",
          ladder.index("stateful") <= 2, f"index={ladder.index('stateful')}")
    for name in ("ttnet", "superonline", "stateful"):
        config = dpi_engine.PRESETS[name]
        check(f"{name}: sahte paket doğru sıra numarasında (durum takipli DPI için)",
              config.decoy_fooling == ("ttl",) and config.auto_ttl)
        check(f"{name}: mesafe bilinmezken güvenli yedek TTL var",
              0 < config.fake_ttl <= 8, f"fake_ttl={config.fake_ttl}")

    engine = dpi_engine.NativeDpiEngine(dpi_engine.PRESETS["ttnet"])
    server = bytes([1, 2, 3, 4])
    check("mesafe bilinmezken yedek TTL kullanılır", engine._decoy_ttl(server) == 5)
    engine._hops[server] = 12
    check("mesafe öğrenilince ondan hesaplanır", engine._decoy_ttl(server) == 11)
    engine._hops[server] = 2
    check("sunucu çok yakınsa sahte paket gönderilmez — el sıkışma bozulmasın",
          engine._decoy_ttl(server) is None)
    check("merdivendeki profillerin hepsi mevcut",
          all(name in dpi_engine.PRESETS for name in dpi_engine.AGGRESSION_LADDER))
    check("merdiven en hafiften başlar",
          not dpi_engine.PRESETS[dpi_engine.AGGRESSION_LADDER[0]].block_quic)
    check("merdiven en agresifle biter",
          dpi_engine.PRESETS[dpi_engine.AGGRESSION_LADDER[-1]].auto_ttl)

    hijack = sf.ProbeResult("discord.com", False, 50.0,
                            "SSLCertVerificationError: CERTIFICATE_VERIFY_FAILED")
    timeout = sf.ProbeResult("discord.com", False, 6000.0, "TimeoutError: timed out")
    check("sahte sertifika DNS kaçırma sayılır", hijack.dns_hijacked)
    check("zaman aşımı DNS kaçırma sayılmaz", not timeout.dns_hijacked)

    ok_probes = [sf.ProbeResult(h, True, 30.0, "TLSv1.3") for h in ("a", "b")]
    clean = sf.FinderReport(baseline=sf.StrategyResult("kapalı", "temel", ok_probes))
    clean.bypass_needed = False
    check("engelsiz hatta bypass önerilmez", "gerekmez" in clean.summary())

    blocked = sf.FinderReport(
        baseline=sf.StrategyResult("kapalı", "temel", [hijack]),
        best=sf.StrategyResult("ttnet", "Türk Telekom DPI Bypass", ok_probes),
    )
    blocked.dns_hijack_suspected = True
    summary = blocked.summary()
    check("çalışan profil özetlenir", "Türk Telekom" in summary)
    check("DNS kaçırma ayrıca uyarılır", "Kanal 2" in summary)

    check("skor doğru sayılır", blocked.best.score == 2 and blocked.best.perfect)
    check("genel IP maskelenir", diagnostics.mask_ip("95.70.152.158") == "95.70.x.x")
    check("boş IP güvenli", diagnostics.mask_ip("") == "gizlendi")


def test_native_fragmentation():
    print("\n[9/10] IP parçalama (native fragmentation)")
    hello = build_client_hello("gateway.discord.gg")
    packet = build_ipv4_tcp(hello, seq=7000)
    pkt = dp.parse_tcp_packet(packet)

    # Checksums must be final before the split: the second fragment has no TCP
    # header, so nothing downstream can compute them afterwards.
    sealed = dp.seal_checksums(bytearray(packet), pkt)
    check("IPv4 başlık sağlaması geçerli",
          dp.ipv4_checksum(bytes(sealed[:pkt.ip_hlen])) == 0)

    verify = dp.parse_tcp_packet(bytes(sealed))
    stored = struct.unpack_from("!H", sealed, pkt.tcp_off + 16)[0]
    check("TCP sağlaması pakete yazıldı", stored != 0)
    check("yeniden hesaplanan sağlama pakettekiyle aynı",
          dp.tcp_checksum(bytes(sealed), verify) == stored,
          f"hesaplanan 0x{dp.tcp_checksum(bytes(sealed), verify):04x} != yazılan 0x{stored:04x}")

    # Independent check: a receiver sums the segment *including* the checksum
    # field and must land on 0xFFFF.
    segment = bytes(sealed[pkt.tcp_off:])
    pseudo = (pkt.src_ip + pkt.dst_ip + bytes([0, dp.PROTO_TCP])
              + struct.pack("!H", len(segment)))
    total = dp._ones_complement_sum(pseudo) + dp._ones_complement_sum(segment)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    check("alıcı tarafında doğrulama 0xFFFF veriyor", total == 0xFFFF, f"got 0x{total:04x}")

    span = dp.extract_sni(hello)
    cut = pkt.tcp_hlen + span[1] + span[2] // 2
    fragments = dp.fragment_ipv4(bytes(sealed), cut)
    check("iki IP parçası üretildi", len(fragments) == 2, f"got {len(fragments)}")

    first, second = fragments
    flags_a = struct.unpack_from("!H", first, 6)[0]
    flags_b = struct.unpack_from("!H", second, 6)[0]
    check("ilk parçada MF biti açık", bool(flags_a & 0x2000))
    check("son parçada MF biti kapalı", not (flags_b & 0x2000))
    check("ikinci parçanın ofseti 8 baytın katı",
          (flags_b & 0x1FFF) * 8 == len(first) - 20,
          f"offset={(flags_b & 0x1FFF) * 8}, beklenen={len(first) - 20}")

    for index, fragment in enumerate(fragments):
        check(f"parça {index} IP sağlaması geçerli",
              dp.ipv4_checksum(bytes(fragment[:20])) == 0)
        check(f"parça {index} uzunluk alanı doğru",
              struct.unpack_from("!H", fragment, 2)[0] == len(fragment))

    reassembled = bytes(first[:20]) + bytes(first[20:]) + bytes(second[20:])
    check("parçalar birleşince orijinali verir", reassembled[20:] == bytes(sealed)[20:])
    check("hiçbir parçada alan adı bütün değil",
          not any(b"gateway.discord.gg" in bytes(f[20:]) for f in fragments))

    check("bölünemeyecek kadar küçük paket bölünmez",
          len(dp.fragment_ipv4(bytes(sealed), 0)) == 1)
    check("IPv6 paketi IP parçalamaya girmez",
          len(dp.fragment_ipv4(build_ipv6_tcp(hello), 40)) == 1)


def test_http_tricks_and_blacklist():
    print("\n[10/10] HTTP hileleri & kara liste")
    request = build_http_request("discord.com")

    mixed = dp.mix_host_case(request)
    check("Host değeri karışık büyük/küçük harf", b"Host: discord.com" not in mixed)
    check("karıştırma uzunluğu bozmuyor", len(mixed) == len(request))
    check("alan adı hâlâ aynı (harf duyarsız)",
          dp.extract_http_host(mixed)[0].lower() == "discord.com")

    swapped = dp.swap_http_spaces(request)
    check("Host: sonrası boşluk kaldırıldı", b"Host:discord.com" in swapped)
    check("metod sonrası fazladan boşluk eklendi", swapped.startswith(b"GET  /"))
    check("boşluk takası uzunluğu KORUYOR — akış bozulmaz",
          len(swapped) == len(request), f"{len(swapped)} != {len(request)}")

    combined = dp.apply_http_tricks(request, mangle_name=True, mix_case=True, swap_spaces=True)
    check("üç hile birlikte uzunluğu korur", len(combined) == len(request))
    check("üç hile birlikte Host'u gizler", b"Host: discord.com" not in combined)

    no_space = b"GET / HTTP/1.1\r\nHost:example.com\r\n\r\n"
    check("boşluksuz istekte takas güvenle atlanır",
          dp.swap_http_spaces(no_space) == no_space)

    # Decoy hostnames must look like real hostnames, not truncated repeats
    for length in (4, 11, 18, 30):
        name = dp.decoy_hostname(length)
        check(f"sahte alan adı {length} bayt ve geçerli biçimde",
              len(name) == length and b"." in name and not name.endswith(b"."),
              f"got {name!r}")

    hello = build_client_hello("gateway.discord.gg")
    decoy = dp.make_decoy_payload(hello, dp.extract_sni(hello)[1:])
    decoy_host = dp.extract_sni(decoy)
    check("sahte ClientHello ayrıştırılabilir kalıyor", decoy_host is not None)
    check("sahte alan adı gerçek olanı gizliyor",
          decoy_host and "discord" not in decoy_host[0])

    # Blacklist file support (GoodbyeDPI's --blacklist)
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
        handle.write("# yorum satırı\ndiscord.com\n.discord.gg\n\nexample.org # sonda yorum\n")
        list_path = handle.name
    try:
        loaded = dpi_engine.load_hostname_list(list_path)
        check("kara liste okundu", loaded == ("discord.com", "discord.gg", "example.org"),
              f"got {loaded}")
        config = dpi_engine.DpiConfig(hostnames=loaded)
        check("listedeki alan adı eşleşir", config.matches_host("gateway.discord.gg"))
        check("liste dışındaki alan adı atlanır", not config.matches_host("google.com"))
    finally:
        os.unlink(list_path)

    check("liste yoksa boş döner", dpi_engine.load_hostname_list("yok-boyle-bir-dosya.txt") == ())


def test_heartbeat_detection():
    print("\n[11/11] Kopma tespiti (hız ve doğruluk)")
    import heartbeat_guard as hg

    guard = hg.HeartbeatGuard()

    # Timing: idle stays cheap, protection is watched closely, a failed check is
    # confirmed within seconds instead of a whole cycle later.
    guard.is_dns_active = False
    guard.consecutive_failures = 0
    check("koruma kapalıyken seyrek kontrol", guard._next_delay() == hg.HEARTBEAT_INTERVAL_S,
          f"got {guard._next_delay()}")

    guard.is_dns_active = True
    check("koruma açıkken sık kontrol", guard._next_delay() == hg.ACTIVE_INTERVAL_S,
          f"got {guard._next_delay()}")

    guard.consecutive_failures = 1
    check("başarısızlıktan sonra hızlı doğrulama",
          guard._next_delay() == hg.CONFIRM_DELAY_S, f"got {guard._next_delay()}")

    budget = guard.get_status()["detection_budget_s"]
    check("tespit bütçesi 15 saniyenin altında", budget <= 15, f"got {budget}s")
    check("eski 50 saniyelik bütçeden belirgin iyileşme",
          budget < hg.HEARTBEAT_INTERVAL_S * hg.FAILURE_THRESHOLD,
          f"{budget}s vs {hg.HEARTBEAT_INTERVAL_S * hg.FAILURE_THRESHOLD}s")

    # Accuracy: the probe must reflect a real handshake, not a bare TCP connect.
    # Measured on live lines, the TCP check was wrong in both directions.
    import strategy_finder as sf

    original = sf.probe_host
    try:
        sf.probe_host = lambda host, timeout=6.0, resolve_over_doh=True: sf.ProbeResult(
            host, False, 120.0, "ConnectionResetError: reset by peer")
        result = guard.probe()
        check("SNI reseti kopma olarak görülüyor", result["ok"] is False)
        check("teşhis metni taşınıyor", "SNI" in result.get("diagnosis", ""),
              result.get("diagnosis"))

        sf.probe_host = lambda host, timeout=6.0, resolve_over_doh=True: sf.ProbeResult(
            host, True, 42.0, "TLSv1.3")
        result = guard.probe()
        check("gerçek el sıkışma başarılı sayılıyor", result["ok"] is True)
        check("gecikme ölçülüyor", result["ping_ms"] == 42, f"got {result['ping_ms']}")

        def explode(host, timeout=6.0, resolve_over_doh=True):
            raise RuntimeError("sonda kullanılamıyor")
        sf.probe_host = explode
        fallback = guard.probe()
        check("sonda çökerse TCP kontrolüne düşülüyor", "ok" in fallback)
    finally:
        sf.probe_host = original


def run_tests():
    print("=" * 62)
    print("  DISCORD DNS v3.6 -- NATIVE DPI ENGINE TEST SUITE")
    print("=" * 62)

    test_parsing()
    test_sni()
    test_http()
    test_split()
    test_rebuild()
    test_engine_config()
    test_auto_ttl_and_rst()
    test_finder_and_diagnostics()
    test_native_fragmentation()
    test_http_tricks_and_blacklist()
    test_heartbeat_detection()

    print("\n" + "=" * 62)
    print(f"  {PASSED} passed, {FAILED} failed")
    print("=" * 62)
    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
