"""
Discord DNS v3.7 — Native DPI Bypass Engine
Our own packet-level bypass, replacing the external goodbyedpi.exe process.

How it works
------------
WinDivert hands us only the packets that matter (the client's first TLS record
and plain HTTP requests), and for each one the engine:

  1. optionally injects a same-length *decoy* packet carrying a benign SNI,
     sent with a sequence number far outside the window (and a corrupt checksum
     on top) — the DPI box records the decoy, the destination server discards it
     without ever parsing it;
  2. cuts the real payload into several TCP segments, one cut inside the SNI
     hostname itself, so no single segment contains a matchable domain;
  3. optionally sends those segments out of order, which defeats DPI engines
     that only inspect the first segment of a stream.

Everything is reversible: stopping the engine closes the handles, and WinDivert
unloads its driver when the last handle is gone.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Deque, Dict, List, Optional, Tuple

import dpi_packets as dp
import windivert as wd

logger = logging.getLogger("DPIEngine")

# Only the packets we actually rewrite reach user space — everything else stays
# in the kernel fast path, which keeps the engine cheap enough for Python.
#
# `!impostor` is essential, not cosmetic: our own re-injected first segment also
# begins with 0x16 0x03, so without it the driver would hand our own output back
# to us and the engine would split the same ClientHello forever.
TCP_FILTER = (
    "outbound and !loopback and !impostor and tcp and ("
    "tcp.Payload16[0] == 0x1603 or "
    "(tcp.DstPort == 80 and tcp.PayloadLength > 16))"
)
QUIC_FILTER = "outbound and !loopback and !impostor and udp and udp.DstPort == 443"

# Discord voice and its STUN traffic. The port ranges are the ones the most
# widely used Discord bypass (zapret-discord-youtube, MIT) targets in its own
# strategy files: 50000-50100 for voice media, 19294-19344 for STUN/RTC.
UDP_VOICE_FILTER = (
    "outbound and !loopback and !impostor and udp and udp.PayloadLength > 0 and ("
    "(udp.DstPort >= 50000 and udp.DstPort <= 50100) or "
    "(udp.DstPort >= 19294 and udp.DstPort <= 19344))"
)

# Discord's own domains. Taken from the same project's host list, then each one
# checked here before inclusion: it must resolve, and the certificate it serves
# must name a Discord domain. Three entries on that list failed — two no longer
# resolve and one is not a real domain — and are left out. discordapp.net has no
# apex record but serves media.discordapp.net, so it stays (matching is by suffix).
DISCORD_DOMAINS: Tuple[str, ...] = (
    "discord.com", "discord.gg", "discord.media", "discordapp.com", "discordapp.net",
    "discordcdn.com", "discord.co", "discord.app", "discord.dev", "discord.new",
    "discord.gift", "discord.gifts", "discord.design", "discord.store", "dis.gd",
    "discordstatus.com", "discordsays.com", "discordsez.com", "discordactivities.com",
    "discordmerch.com", "discord-attachments-uploads-prd.storage.googleapis.com",
)

# Replies we want to look at: SYN-ACK teaches us how far away the server is
# (auto-TTL), RST is how a DPI box tears down a connection it disliked.
INBOUND_FILTER = (
    "inbound and !loopback and !impostor and tcp and "
    "(tcp.SrcPort == 443 or tcp.SrcPort == 80) and (tcp.Syn or tcp.Rst)"
)


# ─── Configuration ───────────────────────────────────────────────────────────────

@dataclass
class DpiConfig:
    """A bypass strategy. Presets below are tuned per Turkish ISP."""

    name: str = "Genel"
    description: str = ""

    split_position: int = 2        # early cut, breaks the TLS record header
    split_at_sni: bool = True      # second cut inside the SNI hostname
    reverse_order: bool = True     # send the last segment first (disorder)
    decoy: bool = True             # inject a benign-looking fake ClientHello first
    # How the decoy is made unusable for the real server. "badseq" is the default
    # and the only one that is safe on every adapter: a NIC with checksum offload
    # silently repairs a "badsum" decoy, and then the server answers the *decoy's*
    # fake SNI with a handshake_failure instead of talking to us.
    decoy_fooling: Tuple[str, ...] = ("badseq", "badsum")
    decoy_seq_offset: int = 0x30000  # how far outside the window the decoy sits
    fake_ttl: int = 0              # >0: fixed TTL for the decoy
    auto_ttl: bool = False         # learn the distance to each server and age the
                                   # decoy so it dies past the DPI, before the host
    auto_ttl_margin: int = 1       # how many hops short of the server to stop
    block_rst: bool = False        # drop the forged RST a DPI box sends to kill
                                   # a connection it could not classify
    rst_window_s: float = 4.0      # only for flows we just rewrote, and only briefly
    rst_ttl_check: bool = False    # let a reset through when its TTL matches the
                                   # server's distance (off: some DPI spoofs TTL)
    native_frag: bool = False      # split at the IP layer instead of the TCP one
    handle_http: bool = True       # also rewrite plain HTTP requests
    http_mangle: bool = True       # `Host:` → `hOsT:`
    http_mix_case: bool = False    # dIsCoRd.CoM in the Host value
    http_swap_spaces: bool = False # move a space from `Host:` to after the method
    block_quic: bool = False       # drop UDP/443 so browsers fall back to TCP TLS
    # Sequence overlap: the first segment starts this many bytes *before* the
    # real data, and the overlap is filled with a fake ClientHello for an
    # innocuous host. The server discards bytes that precede what it is waiting
    # for, so it only ever sees the real request; a DPI box that reassembles from
    # the earliest byte it saw reads the fake one first. 0 = off.
    seqovl: int = 0
    # Discord voice over UDP. Experimental: it cannot be verified without a live
    # voice session on a line that blocks voice, so it stays off by default.
    udp_voice: bool = False
    udp_fake_repeats: int = 6      # decoys sent ahead of each early voice packet
    udp_cutoff: int = 2            # only the first N packets of a flow are touched
    udp_fake_ttl: int = 0          # >0 ages the decoys so they die en route
    hostnames: Tuple[str, ...] = ()  # empty → every host; otherwise suffix match

    def matches_host(self, host: Optional[str]) -> bool:
        if not self.hostnames:
            return True
        if not host:
            return False
        h = host.lower()
        return any(h == d or h.endswith("." + d) for d in self.hostnames)


PRESETS: Dict[str, DpiConfig] = {
    # RST protection is on everywhere below. Turkish ISPs enforce SNI blocks by
    # injecting a forged RST the moment they see the hostname — measured on a TT
    # mobile line: TCP connects, then the handshake dies with ECONNRESET ~66 ms
    # in. Fragmentation alone is a bet that the DPI cannot reassemble; dropping
    # the forged reset is the safety net for when that bet loses.
    "superonline": DpiConfig(
        name="Superonline DPI Bypass",
        # Same technique as the verified TT profile, by analogy — Superonline's
        # box has not been measured here, so the ladder still tries the others.
        description="Doğru sıra numaralı TTL sahte paketi + erken bölme + ters sıra",
        split_position=2, split_at_sni=True, reverse_order=True,
        decoy=True, decoy_fooling=("ttl",), auto_ttl=True, auto_ttl_margin=1,
        fake_ttl=5, block_rst=True, block_quic=True,
    ),
    "ttnet": DpiConfig(
        name="Türk Telekom / Avea DPI Bypass",
        # Measured on a live TT mobile line: this is the only strategy that got
        # through. Splitting alone failed on every variant because the box
        # reassembles the stream; the decoy at the correct sequence number, aged
        # so it dies before the server, was never even answered with a reset.
        description="Ölçümle doğrulanmış: doğru sıra numaralı TTL sahte paketi + "
                    "SNI içi bölme + RST koruması",
        split_position=2, split_at_sni=True, reverse_order=True,
        decoy=True, decoy_fooling=("ttl",), auto_ttl=True, auto_ttl_margin=1,
        fake_ttl=5, block_rst=True, block_quic=True,
    ),
    "vodafone": DpiConfig(
        name="Vodafone / KabloNet Bypass",
        description="Hafif: SNI içi bölme + RST koruması, sahte paket yok",
        split_position=2, split_at_sni=True, reverse_order=False,
        decoy=False, block_rst=True, block_quic=False,
    ),
    "general": DpiConfig(
        name="Genel DPI Bypass",
        description="Dengeli varsayılan: bölme + sahte paket + RST koruması",
        split_position=2, split_at_sni=True, reverse_order=True,
        decoy=True, block_rst=True, block_quic=False,
    ),
    "discord_only": DpiConfig(
        name="Sadece Discord",
        description="Yalnızca Discord alan adlarına dokunur, diğer trafiği hiç değiştirmez",
        split_position=2, split_at_sni=True, reverse_order=True,
        decoy=True, block_quic=False,
        hostnames=DISCORD_DOMAINS,
    ),
    "hardened": DpiConfig(
        name="Sertleştirilmiş",
        description="SNI bölme + sahte paket + otomatik TTL + DPI kaynaklı RST engelleme",
        split_position=2, split_at_sni=True, reverse_order=True,
        decoy=True, auto_ttl=True, block_rst=True, block_quic=True,
    ),
    "maximum": DpiConfig(
        name="Maksimum",
        description="Her şey açık: erken bölme, ters sıra, otomatik TTL, RST koruması, QUIC kapalı",
        split_position=1, split_at_sni=True, reverse_order=True,
        decoy=True, decoy_fooling=("badseq", "badsum"), auto_ttl=True,
        auto_ttl_margin=2, block_rst=True, block_quic=True,
        http_mangle=True, http_mix_case=True, http_swap_spaces=True,
    ),
    "stateful": DpiConfig(
        name="Durum Takipli DPI",
        description="Doğru sıra numaralı, TTL ile ölen sahte ClientHello — akışı "
                    "yeniden birleştiren DPI kutuları için",
        split_position=2, split_at_sni=True, reverse_order=True,
        decoy=True, decoy_fooling=("ttl",), auto_ttl=True, auto_ttl_margin=1,
        fake_ttl=5, block_rst=True, block_quic=True,
    ),
    "stateful_fake_only": DpiConfig(
        name="Sadece Sahte Paket",
        description="Bölme yok: yalnızca TTL ile ölen sahte ClientHello gönderilir, "
                    "gerçek istek olduğu gibi gider",
        split_position=0, split_at_sni=False, reverse_order=False,
        decoy=True, decoy_fooling=("ttl",), auto_ttl=True, auto_ttl_margin=1,
        fake_ttl=5, block_rst=True, block_quic=True,
    ),
    "seqovl": DpiConfig(
        name="Sıra Örtüşmesi",
        # The primary TCP technique of zapret-discord-youtube (MIT), the most
        # widely used Discord bypass: split after the first byte, with the first
        # segment reaching 568 bytes back into a fake ClientHello. Implemented
        # here from the idea, not copied — the overlap pattern is generated at
        # runtime from this machine's own TLS stack.
        description="Sıra örtüşmesi: ilk parça sahte bir ClientHello'nun üstüne biner — "
                    "en yaygın Discord aracının ana tekniği",
        split_position=1, split_at_sni=False, reverse_order=False,
        decoy=False, seqovl=568, block_rst=True, block_quic=True,
    ),
    "native_frag": DpiConfig(
        name="IP Parçalama",
        description="TCP yerine IP katmanında parçalar — TCP akışını birleştiren ama "
                    "IP parçalarını birleştirmeyen DPI kutuları için",
        split_position=2, split_at_sni=True, reverse_order=False,
        native_frag=True, decoy=True, block_rst=True, auto_ttl=True, block_quic=True,
        http_mangle=True, http_mix_case=True, http_swap_spaces=True,
    ),
}

# Tried in this order by the strategy finder: cheapest and least invasive first,
# so a line that only needs a nudge never ends up on the heavy-handed profile.
AGGRESSION_LADDER: Tuple[str, ...] = (
    # "stateful" comes early because it is the one strategy measured to work
    # against a Turkish DPI box: a decoy at the correct sequence number, aged by
    # TTL so it never reaches the server. The purely fragmenting profiles stay in
    # the ladder for boxes that do not reassemble, but they are tried afterwards.
    "vodafone", "general", "stateful", "seqovl", "stateful_fake_only",
    "ttnet", "superonline", "hardened", "maximum", "native_frag",
)


_HOSTNAME_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-._")


def _is_hostname(entry: str) -> bool:
    """
    Whether a line from the domain list is actually a hostname.

    Without this, a file that picked up binary junk or a stray line turned into
    a "domain" the engine would then try to match — silently narrowing what it
    protects. A name has a length limit, a character set, and labels that do not
    start or end with a hyphen.
    """
    if not entry or len(entry) > 253 or ".." in entry:
        return False
    if not set(entry) <= _HOSTNAME_CHARS:
        return False
    labels = entry.split(".")
    return all(0 < len(label) <= 63 and not label.startswith("-")
               and not label.endswith("-") for label in labels)


def load_hostname_list(path: Optional[str] = None) -> Tuple[str, ...]:
    """
    Read a domain list (GoodbyeDPI's --blacklist) from
    %APPDATA%\\DiscordDNS\\blacklist.txt, one domain per line, # for comments.

    When the file exists, the engine only touches those domains and leaves the
    rest of the machine's traffic completely alone.
    """
    if path is None:
        appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
        path = os.path.join(appdata, "DiscordDNS", "blacklist.txt")

    try:
        if not os.path.isfile(path):
            return ()
        domains = []
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                entry = line.split("#", 1)[0].strip().lower().lstrip(".")
                if _is_hostname(entry):
                    domains.append(entry)
        return tuple(dict.fromkeys(domains))
    except Exception as e:
        logger.warning("Kara liste okunamadı (%s): %s", path, e)
        return ()


# ─── Statistics ──────────────────────────────────────────────────────────────────

@dataclass
class EngineStats:
    started_at: float = 0.0
    packets_seen: int = 0
    packets_rewritten: int = 0
    segments_sent: int = 0
    decoys_sent: int = 0
    passthrough: int = 0
    errors: int = 0
    rst_blocked: int = 0
    hops_learned: int = 0
    native_frags: int = 0
    seqovl_sent: int = 0
    udp_flows: int = 0
    udp_decoys_sent: int = 0
    process_us_total: float = 0.0
    last_hosts: Deque[str] = field(default_factory=lambda: deque(maxlen=25))

    def snapshot(self) -> dict:
        uptime = time.time() - self.started_at if self.started_at else 0.0
        return {
            "uptime_s": int(uptime),
            "packets_seen": self.packets_seen,
            "packets_rewritten": self.packets_rewritten,
            "segments_sent": self.segments_sent,
            "decoys_sent": self.decoys_sent,
            "passthrough": self.passthrough,
            "errors": self.errors,
            "rst_blocked": self.rst_blocked,
            "hops_learned": self.hops_learned,
            "native_frags": self.native_frags,
            "seqovl_sent": self.seqovl_sent,
            "udp_flows": self.udp_flows,
            "udp_decoys_sent": self.udp_decoys_sent,
            # Measured inside the live path, driver syscalls included — the
            # microbenchmark that excluded them was not a real cost figure.
            "avg_process_us": round(self.process_us_total / self.packets_rewritten, 1)
                              if self.packets_rewritten else 0.0,
            "last_hosts": list(self.last_hosts),
        }


# ─── Engine ──────────────────────────────────────────────────────────────────────

class NativeDpiEngine:
    """
    Owns the WinDivert handles and the worker threads.
    Start/stop is idempotent and safe to call from the GUI thread.
    """

    def __init__(self, config: Optional[DpiConfig] = None):
        self.config = config or PRESETS["general"]
        self.stats = EngineStats()

        self._tcp_handle: Optional[wd.WinDivertHandle] = None
        self._quic_handle: Optional[wd.WinDivertHandle] = None
        self._in_handle: Optional[wd.WinDivertHandle] = None
        self._udp_handle: Optional[wd.WinDivertHandle] = None
        self._udp_thread: Optional[threading.Thread] = None
        # Voice flows already handled: (dst ip, dst port, src port) → [count, last seen]
        self._udp_flows: Dict[Tuple[bytes, int, int], list] = {}
        self._thread: Optional[threading.Thread] = None
        self._in_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._ip_id = 0x4000
        self._running = False
        self.last_error: str = ""

        # Learned from inbound SYN-ACKs: raw server address → hop distance
        self._hops: Dict[bytes, int] = {}
        # Flows whose ClientHello we just rewrote → timestamp, for RST filtering
        self._recent_flows: Dict[Tuple[bytes, int, int], float] = {}

    # ── public API ──────────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    def start(self) -> Tuple[bool, str]:
        if self.is_running:
            return True, f"Yerel DPI motoru zaten çalışıyor ({self.config.name})."

        self._stop.clear()

        # A user-supplied domain list narrows the engine to those hosts only
        if not self.config.hostnames:
            listed = load_hostname_list()
            if listed:
                self.config = DpiConfig(**{**self.config.__dict__, "hostnames": listed})
                logger.info("Kara liste uygulandı: %d alan adı", len(listed))

        try:
            self._tcp_handle = wd.WinDivertHandle(TCP_FILTER, priority=-1000).open()
        except wd.WinDivertError as e:
            self.last_error = str(e)
            return False, f"Yerel motor başlatılamadı: {e}"
        except OSError as e:
            self.last_error = str(e)
            return False, f"WinDivert yüklenemedi: {e}"

        if self.config.block_quic:
            try:
                self._quic_handle = wd.WinDivertHandle(
                    QUIC_FILTER, priority=-1001,
                    flags=wd.FLAG_DROP | wd.FLAG_RECV_ONLY
                ).open()
            except Exception as e:      # QUIC blocking is a bonus, never fatal
                logger.warning("QUIC engelleme açılamadı: %s", e)
                self._quic_handle = None

        # A second, low-volume handle: only SYN-ACK and RST replies reach it
        if self.config.auto_ttl or self.config.block_rst:
            try:
                self._in_handle = wd.WinDivertHandle(INBOUND_FILTER, priority=-999).open()
            except Exception as e:      # both features are extras, never fatal
                logger.warning("Gelen paket kanalı açılamadı: %s", e)
                self._in_handle = None

        if self.config.udp_voice:
            try:
                self._udp_handle = wd.WinDivertHandle(UDP_VOICE_FILTER, priority=-998).open()
            except Exception as e:      # experimental extra, never fatal
                logger.warning("Ses (UDP) kanalı açılamadı: %s", e)
                self._udp_handle = None

        self.stats = EngineStats(started_at=time.time())
        self._running = True
        self._thread = threading.Thread(target=self._run, name="NativeDPI", daemon=True)
        self._thread.start()

        if self._in_handle is not None:
            self._in_thread = threading.Thread(target=self._run_inbound,
                                               name="NativeDPI-in", daemon=True)
            self._in_thread.start()

        if self._udp_handle is not None:
            self._udp_thread = threading.Thread(target=self._run_udp,
                                                name="NativeDPI-udp", daemon=True)
            self._udp_thread.start()

        extras = []
        if self._udp_handle:
            extras.append("ses (UDP) koruması")
        if self._quic_handle:
            extras.append("QUIC engelli")
        if self._in_handle and self.config.auto_ttl:
            extras.append("otomatik TTL")
        if self._in_handle and self.config.block_rst:
            extras.append("RST koruması")
        suffix = f" + {' + '.join(extras)}" if extras else ""
        return True, f"⚡ Yerel DPI motoru aktif — {self.config.name}{suffix}"

    def stop(self) -> Tuple[bool, str]:
        if (not self._running and self._tcp_handle is None and self._quic_handle is None
                and self._in_handle is None and self._udp_handle is None):
            return True, "Yerel DPI motoru zaten kapalı."

        self._stop.set()
        self._running = False

        # Unblock the workers parked in recv(), then let them close their handles
        for handle in (self._tcp_handle, self._in_handle, self._udp_handle):
            if handle is not None:
                try:
                    handle.shutdown(wd.SHUTDOWN_BOTH)
                except Exception:
                    pass

        for thread in (self._thread, self._in_thread, self._udp_thread):
            if thread is not None:
                thread.join(timeout=3)
        self._thread = self._in_thread = self._udp_thread = None

        for handle in (self._tcp_handle, self._quic_handle, self._in_handle, self._udp_handle):
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
        self._tcp_handle = None
        self._quic_handle = None
        self._in_handle = None
        self._udp_handle = None

        with self._lock:
            self._recent_flows.clear()
            self._udp_flows.clear()

        return True, "Yerel DPI motoru durduruldu ve sürücü serbest bırakıldı."

    def apply_config(self, config: DpiConfig) -> Tuple[bool, str]:
        """Switch strategy; restarts the handles only when QUIC blocking changes."""
        needs_restart = self.is_running and (config.block_quic != self.config.block_quic
                                             or config.udp_voice != self.config.udp_voice)
        self.config = config
        if needs_restart:
            self.stop()
            return self.start()
        return True, f"Strateji güncellendi: {config.name}"

    # ── worker ──────────────────────────────────────────────────────────────────

    def _run(self) -> None:
        handle = self._tcp_handle
        assert handle is not None
        logger.info("Native DPI worker started (%s)", self.config.name)

        while not self._stop.is_set():
            try:
                received = handle.recv()
            except wd.WinDivertError as e:
                if self._stop.is_set():
                    break
                self.stats.errors += 1
                self.last_error = str(e)
                logger.error("recv hatası: %s", e)
                break

            if received is None:
                break

            packet, addr = received
            self.stats.packets_seen += 1
            try:
                self._handle_packet(handle, packet, addr)
            except Exception as e:
                self.stats.errors += 1
                logger.debug("paket işlenemedi: %s", e)
                try:                       # never black-hole the user's traffic
                    handle.send(packet, addr)
                except Exception:
                    pass

        self._running = False
        logger.info("Native DPI worker stopped")

    def _run_inbound(self) -> None:
        """Watch replies: learn server distance, and swallow DPI-forged resets."""
        handle = self._in_handle
        if handle is None:
            return
        logger.info("Inbound worker started (auto_ttl=%s, block_rst=%s)",
                    self.config.auto_ttl, self.config.block_rst)

        while not self._stop.is_set():
            try:
                received = handle.recv()
            except wd.WinDivertError as e:
                if not self._stop.is_set():
                    logger.error("gelen paket hatası: %s", e)
                break
            if received is None:
                break

            packet, addr = received
            try:
                self._handle_inbound(handle, packet, addr)
            except Exception as e:
                logger.debug("gelen paket işlenemedi: %s", e)
                try:
                    handle.send(packet, addr)
                except Exception:
                    pass

        logger.info("Inbound worker stopped")

    def _handle_inbound(self, handle: wd.WinDivertHandle, packet: bytearray,
                        addr: wd.WinDivertAddress) -> None:
        pkt = dp.parse_tcp_packet(packet)
        if pkt is None:
            handle.send(packet, addr)
            return

        # SYN-ACK: the reply's TTL reveals how many hops away the server is
        if self.config.auto_ttl and (pkt.flags & dp.TCP_SYN) and (pkt.flags & dp.TCP_ACK):
            hops = dp.infer_hop_count(pkt.ttl)
            if hops and hops >= 3:
                with self._lock:
                    if len(self._hops) > 512:
                        self._hops.clear()
                    self._hops[pkt.src_ip] = hops
                self.stats.hops_learned = len(self._hops)

        # RST: a DPI box kills disliked connections by forging one. Drop it, but
        # only for a flow we just rewrote and only for a few seconds — a genuine
        # reset from the server (closed port, restart) must still get through.
        if self.config.block_rst and (pkt.flags & dp.TCP_RST):
            key = (pkt.src_ip, pkt.src_port, pkt.dst_port)
            with self._lock:
                seen_at = self._recent_flows.get(key)
                server_hops = self._hops.get(pkt.src_ip)

            if seen_at is not None and (time.time() - seen_at) <= self.config.rst_window_s:
                forged = True
                reason = "yeniden yazılan akış"

                # Optional sharper test: a middlebox sits closer than the server,
                # so its reset can arrive with a higher TTL. Measured on a TT
                # mobile line this backfired — the injected resets carried a TTL
                # matching the server's distance, so the check waved every one of
                # them through and the profiles that enabled it blocked nothing.
                # It stays available for networks where it helps, but off by
                # default: inside the window, a reset on a flow we just rewrote is
                # treated as hostile.
                if self.config.rst_ttl_check:
                    rst_hops = dp.infer_hop_count(pkt.ttl)
                    if server_hops is not None and rst_hops is not None:
                        if rst_hops >= server_hops - 1:
                            forged = False
                            reason = "sunucudan geliyor (mesafe uyuşuyor)"
                        else:
                            reason = f"DPI kutusu {server_hops - rst_hops} sekme daha yakın"

                if forged:
                    # The flow deliberately stays in the table: a DPI box usually
                    # fires several resets in a row, and popping the entry after
                    # the first one let every follow-up through — which is why
                    # blocking "worked" and the connection died anyway.
                    self.stats.rst_blocked += 1
                    logger.info("Sahte RST düşürüldü — %s", reason)
                    return                  # not re-injected → the reset never lands
                logger.debug("RST geçirildi — %s", reason)

        handle.send(packet, addr)

    def _run_udp(self) -> None:
        """Watch the first packets of each Discord voice flow."""
        handle = self._udp_handle
        if handle is None:
            return
        logger.info("UDP voice worker started")
        while not self._stop.is_set():
            try:
                received = handle.recv()
            except wd.WinDivertError as e:
                if not self._stop.is_set():
                    logger.error("UDP alma hatası: %s", e)
                break
            if received is None:
                break
            packet, addr = received
            try:
                self._handle_udp(handle, packet, addr)
            except Exception as e:
                self.stats.errors += 1
                logger.debug("UDP paketi işlenemedi: %s", e)
                try:                        # never black-hole a voice call
                    handle.send(packet, addr)
                except Exception:
                    pass
        logger.info("UDP voice worker stopped")

    def _handle_udp(self, handle: wd.WinDivertHandle, packet: bytearray,
                    addr: wd.WinDivertAddress) -> None:
        """
        Put decoys ahead of the opening packets of a voice flow.

        A DPI box classifies a UDP flow from its first few datagrams. Sending a
        burst of decoys before them — the approach zapret-discord-youtube uses
        for exactly these ports — gives the classifier something else to look
        at. Only the first `udp_cutoff` packets of a flow are touched, so an
        established call pays nothing. Decoys a voice server receives are just
        malformed datagrams it ignores; `udp_fake_ttl` can stop them earlier.
        """
        pkt = dp.parse_udp_packet(packet) if not addr.impostor else None
        if pkt is None or not pkt.payload:
            handle.send(packet, addr)
            return

        key = (pkt.dst_ip, pkt.dst_port, pkt.src_port)
        now = time.time()
        with self._lock:
            entry = self._udp_flows.get(key)
            if entry is None or now - entry[1] > 60:
                entry = [0, now]
                self.stats.udp_flows += 1
            seen = entry[0]
            entry[0] += 1
            entry[1] = now
            self._udp_flows[key] = entry
            if len(self._udp_flows) > 2048:
                for stale, value in list(self._udp_flows.items()):
                    if now - value[1] > 60:
                        self._udp_flows.pop(stale, None)

        if seen < self.config.udp_cutoff:
            ttl = self.config.udp_fake_ttl or None
            size = max(1, len(pkt.payload))
            for _ in range(self.config.udp_fake_repeats):
                decoy = dp.build_udp_datagram(pkt, os.urandom(size), ttl=ttl,
                                              ip_id=self._next_ip_id())
                if handle.send(decoy, addr.copy()):
                    self.stats.udp_decoys_sent += 1

        handle.send(packet, addr)

    def _decoy_ttl(self, dst_ip: bytes) -> Optional[int]:
        """
        TTL for the decoy: far enough to clear the ISP's DPI, short enough to
        expire before the destination.

        Getting this too low only wastes a packet. Getting it too high is the
        dangerous direction — the decoy would reach the server and corrupt the
        real handshake — so every path here errs downwards.
        """
        hops = None
        if self.config.auto_ttl:
            with self._lock:
                hops = self._hops.get(dst_ip)

        if hops:
            if hops <= self.config.auto_ttl_margin + 1:
                return None            # server too close to age a decoy safely
            return max(2, hops - self.config.auto_ttl_margin)

        if self.config.fake_ttl:
            # Distance unknown (first connection to this server). A low fixed
            # value still clears a nearby DPI box, and if it falls short the
            # decoy simply dies early and harmlessly; the retry gets the real
            # hop count once a SYN-ACK has been seen.
            return self.config.fake_ttl
        return None

    def _remember_flow(self, pkt: "dp.TcpPacket") -> None:
        if not self.config.block_rst:
            return
        now = time.time()
        with self._lock:
            self._recent_flows[(pkt.dst_ip, pkt.dst_port, pkt.src_port)] = now
            if len(self._recent_flows) > 4096:
                cutoff = now - self.config.rst_window_s
                for key, seen in list(self._recent_flows.items()):
                    if seen < cutoff:
                        self._recent_flows.pop(key, None)

    def _next_ip_id(self) -> int:
        with self._lock:
            self._ip_id = (self._ip_id + 1) & 0xFFFF
            return self._ip_id

    def _handle_packet(self, handle: wd.WinDivertHandle, packet: bytearray,
                       addr: wd.WinDivertAddress) -> None:
        started_at = time.perf_counter()

        # Second line of defence behind the `!impostor` filter: never re-split a
        # packet this engine itself injected.
        pkt = dp.parse_tcp_packet(packet) if not addr.impostor else None
        if pkt is None or not pkt.payload:
            handle.send(packet, addr)
            self.stats.passthrough += 1
            return

        kind, host, span = dp.describe_target(pkt.payload)

        # A ClientHello without SNI is still worth splitting; anything else is not
        if kind == "other":
            is_client_hello = (pkt.is_tls_handshake and len(pkt.payload) > 5
                               and pkt.payload[5] == dp.TLS_HANDSHAKE_CLIENT_HELLO)
            if not is_client_hello:
                handle.send(packet, addr)
                self.stats.passthrough += 1
                return
            kind = "tls"

        if kind == "http" and not self.config.handle_http:
            handle.send(packet, addr)
            self.stats.passthrough += 1
            return

        if not self.config.matches_host(host):
            handle.send(packet, addr)
            self.stats.passthrough += 1
            return

        payload = pkt.payload
        if kind == "http":
            payload = dp.apply_http_tricks(
                payload,
                mangle_name=self.config.http_mangle,
                mix_case=self.config.http_mix_case,
                swap_spaces=self.config.http_swap_spaces,
            )

        positions = dp.choose_split_positions(
            payload, self.config.split_position, self.config.split_at_sni
        )
        segments = dp.split_payload(payload, positions)
        if len(segments) < 2 and not self.config.decoy:
            handle.send(packet, addr)
            self.stats.passthrough += 1
            return

        # 1) decoy first, so the DPI state machine locks onto it
        if self.config.decoy:
            fooling = self.config.decoy_fooling
            decoy = dp.make_decoy_payload(payload, span if kind == "tls" else None)
            decoy_ttl = self._decoy_ttl(pkt.dst_ip)

            # A DPI box that tracks sequence numbers ignores an out-of-window
            # decoy completely — which is exactly what a "badseq" fake is. To
            # fool a stateful box the decoy has to sit at the *correct* sequence
            # number and be stopped from reaching the server by its TTL instead.
            ttl_only = "ttl" in fooling and not ({"badseq", "badsum"} & set(fooling))

            if ttl_only and decoy_ttl is None:
                # Distance to this server not learned yet. A TTL-only decoy with
                # a guessed hop count would reach the server and corrupt the real
                # handshake, so skip it rather than gamble with the connection.
                logger.debug("TTL sahte paketi atlandı — sunucu mesafesi bilinmiyor")
            else:
                seq = pkt.seq
                if "badseq" in fooling:
                    seq = (pkt.seq - self.config.decoy_seq_offset) & 0xFFFFFFFF

                fake = dp.build_segment(pkt, decoy, seq, ip_id=self._next_ip_id(),
                                        ttl=decoy_ttl)
                if "badsum" in fooling:
                    dp.finalize_badsum(fake, pkt)
                    sent = handle.send_precomputed(fake, addr.copy())
                else:
                    sent = handle.send(fake, addr.copy())
                if sent:
                    self.stats.decoys_sent += 1

        # 2) the real payload — either as IP fragments or as TCP segments
        if len(segments) < 2:
            # Decoy-only strategy: the fake goes first, then the request itself
            # travels untouched. Useful when a DPI reassembles fragments anyway.
            if handle.send(packet, addr):
                self.stats.segments_sent += 1
        elif self.config.native_frag and pkt.version == 4:
            self._send_ip_fragments(handle, pkt, payload, positions, addr)
        elif self.config.seqovl > 0 and kind == "tls":
            self._send_seqovl(handle, pkt, segments, addr)
        else:
            ordered: List[Tuple[int, bytes]] = list(segments)
            if self.config.reverse_order:
                ordered.reverse()

            for rel_offset, chunk in ordered:
                seg = dp.build_segment(pkt, chunk, pkt.seq + rel_offset,
                                       ip_id=self._next_ip_id())
                if handle.send(seg, addr.copy()):
                    self.stats.segments_sent += 1

        self._remember_flow(pkt)
        self.stats.packets_rewritten += 1
        self.stats.process_us_total += (time.perf_counter() - started_at) * 1e6
        if host:
            self.stats.last_hosts.append(host)

    def _send_seqovl(self, handle: wd.WinDivertHandle, pkt: "dp.TcpPacket",
                     segments: List[Tuple[int, bytes]], addr: wd.WinDivertAddress) -> None:
        """
        Send the request with the first segment overlapping backwards into a fake.

        The first segment is placed `seqovl` bytes before the real start and that
        gap is filled with a ClientHello for an innocuous host. The server is
        waiting for the real first byte, so it trims everything before it and
        assembles only the genuine request. A DPI box that reassembles from the
        earliest sequence number it has seen reads the fake hello first and
        classifies the connection by that.

        Segments go out in order on purpose: the overlap only works if the DPI
        meets the fake before the rest.
        """
        overlap = self.config.seqovl
        pattern = dp.seqovl_pattern(overlap)
        for index, (rel_offset, chunk) in enumerate(segments):
            if index == 0:
                data = pattern + chunk
                seq = (pkt.seq + rel_offset - overlap) & 0xFFFFFFFF
            else:
                data = chunk
                seq = pkt.seq + rel_offset
            seg = dp.build_segment(pkt, data, seq, ip_id=self._next_ip_id())
            if handle.send(seg, addr.copy()):
                self.stats.segments_sent += 1
        self.stats.seqovl_sent += 1

    def _send_ip_fragments(self, handle: wd.WinDivertHandle, pkt: "dp.TcpPacket",
                           payload: bytes, positions: List[int],
                           addr: wd.WinDivertAddress) -> None:
        """
        Send the request as genuine IP fragments instead of TCP segments.

        A DPI box that reassembles TCP streams may still refuse to reassemble IP
        fragments — and one that inspects only the first fragment never sees the
        hostname at all. Checksums are finalised before the split because the
        second fragment carries no TCP header for the driver to work from.
        """
        segment = dp.build_segment(pkt, payload, pkt.seq, ip_id=self._next_ip_id())
        dp.seal_checksums(segment, pkt)

        # Cut inside the hostname: the SNI position, expressed in IP-payload
        # bytes, rounded down to the 8-byte unit the offset field uses.
        cut = positions[-1] if positions else 2
        first_len = pkt.tcp_hlen + cut

        fragments = dp.fragment_ipv4(bytes(segment), first_len)
        if len(fragments) < 2:
            if handle.send_precomputed(segment, addr.copy()):
                self.stats.segments_sent += 1
            return

        if self.config.reverse_order:
            fragments.reverse()

        for fragment in fragments:
            if handle.send_precomputed(fragment, addr.copy()):
                self.stats.segments_sent += 1
        self.stats.native_frags += 1


# ─── Module-level singleton (mirrors the old goodbyedpi process handling) ────────

_engine: Optional[NativeDpiEngine] = None


def get_engine() -> NativeDpiEngine:
    global _engine
    if _engine is None:
        _engine = NativeDpiEngine()
    return _engine


# Options the user switches on in the interface, layered over whichever preset
# runs. Kept apart from the presets so the strategy scan keeps measuring the
# plain profiles, while the connection it finally makes still carries them.
_USER_OPTION_KEYS = ("udp_voice",)
_user_options: Dict[str, object] = {"udp_voice": False}


def set_user_options(**options) -> None:
    """Remember interface toggles (currently: udp_voice) for the next start."""
    for key, value in options.items():
        if key in _USER_OPTION_KEYS:
            _user_options[key] = bool(value)


def user_options() -> Dict[str, object]:
    return dict(_user_options)


def configured(mode: str) -> DpiConfig:
    """A preset with the user's options applied on top."""
    return replace(PRESETS.get(mode, PRESETS["general"]), **_user_options)


def start(mode: str = "general", hostnames: Optional[Tuple[str, ...]] = None) -> Tuple[bool, str]:
    """Start the native engine with a named preset."""
    config = configured(mode)
    if hostnames is not None:
        config = DpiConfig(**{**config.__dict__, "hostnames": tuple(hostnames)})
    engine = get_engine()
    engine.config = config
    return engine.start()


def stop() -> Tuple[bool, str]:
    return get_engine().stop() if _engine is not None else (True, "Yerel DPI motoru kapalı.")


def is_running() -> bool:
    return _engine is not None and _engine.is_running


def stats() -> dict:
    return get_engine().stats.snapshot() if _engine is not None else EngineStats().snapshot()


def self_test() -> Tuple[bool, str]:
    """
    Verify the driver can actually be opened on this machine (admin rights,
    driver signature, no conflicting WinDivert version) without touching traffic.
    """
    try:
        version = wd.driver_version()
        if version:
            return True, f"WinDivert sürücüsü hazır (sürüm {version})."
        return False, "WinDivert sürücüsü açılamadı."
    except wd.WinDivertError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Sürücü testi başarısız: {e}"
