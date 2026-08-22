"""
Discord DNS v3.6 — Local DNS-over-HTTPS Resolver
A tiny DNS server that listens on 127.0.0.1:53 (UDP + TCP) and answers by
forwarding every query over HTTPS (RFC 8484) to Cloudflare / Google / Quad9.

Why this exists
---------------
The old "DoH" switch only ran `Set-DnsClientServerAddress -DnsOverHttps`, which
is not a real parameter — nothing was ever encrypted. Pointing the adapter at
this proxy instead encrypts *every* lookup the machine makes, on Windows 10 as
well as 11, which is what actually defeats ISP DNS hijacking.

Upstreams are contacted by IP with the correct SNI + certificate validation, so
there is no bootstrap lookup that the ISP could poison.
"""

from __future__ import annotations

import http.client
import logging
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("DoHProxy")

DNS_PORT = 53
MAX_UDP = 4096
MIN_TTL = 30
MAX_TTL = 3600
RCODE_SERVFAIL = 2


# ─── Upstreams ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DohUpstream:
    name: str
    ip: str
    hostname: str
    path: str = "/dns-query"

    def __str__(self) -> str:
        return f"{self.name} ({self.hostname})"


DEFAULT_UPSTREAMS: Tuple[DohUpstream, ...] = (
    DohUpstream("Cloudflare", "1.1.1.1", "cloudflare-dns.com"),
    DohUpstream("Google", "8.8.8.8", "dns.google"),
    DohUpstream("Quad9", "9.9.9.9", "dns.quad9.net"),
    DohUpstream("AdGuard", "94.140.14.14", "dns.adguard-dns.com"),
)


# DNS profile names used by the GUI → preferred DoH upstream
_PRESET_TO_UPSTREAM = {
    "Cloudflare": "Cloudflare",
    "Google": "Google",
    "Quad9": "Quad9",
    "AdGuard": "AdGuard",
    "OpenDNS": "Cloudflare",     # no public DoH-by-IP endpoint, fall back
    "ControlD": "Cloudflare",
}


def upstreams_for(preset_name: str) -> Tuple[DohUpstream, ...]:
    """Order the upstream list so the user's chosen DNS profile is tried first."""
    wanted = _PRESET_TO_UPSTREAM.get(preset_name, "Cloudflare")
    first = [u for u in DEFAULT_UPSTREAMS if u.name == wanted]
    rest = [u for u in DEFAULT_UPSTREAMS if u.name != wanted]
    return tuple(first + rest)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """
    Connect to a fixed IP while presenting (and validating) the real hostname.
    This is what removes the bootstrap problem: no plaintext DNS is ever needed
    to reach the encrypted resolver.
    """

    def __init__(self, ip: str, hostname: str, timeout: float, context: ssl.SSLContext):
        super().__init__(hostname, 443, timeout=timeout, context=context)
        self._target_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._target_ip, 443), self.timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


# ─── Minimal DNS wire helpers ────────────────────────────────────────────────────

def parse_question(msg: bytes) -> Tuple[Optional[str], int]:
    """Return (qname, qtype) of the first question, or (None, 0)."""
    try:
        if len(msg) < 12:
            return None, 0
        pos = 12
        labels: List[str] = []
        while pos < len(msg):
            length = msg[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xC0:               # compression pointer: not valid here
                return None, 0
            pos += 1
            labels.append(msg[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        if pos + 2 > len(msg):
            return ".".join(labels) or ".", 0
        qtype = struct.unpack_from("!H", msg, pos)[0]
        return ".".join(labels) or ".", qtype
    except Exception:
        return None, 0


def _skip_name(msg: bytes, pos: int) -> int:
    while pos < len(msg):
        length = msg[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0:
            return pos + 2
        pos += 1 + length
    return pos


def min_answer_ttl(msg: bytes) -> int:
    """Smallest TTL across the answer section, clamped to sane cache bounds."""
    try:
        ancount = struct.unpack_from("!H", msg, 6)[0]
        if not ancount:
            return MIN_TTL
        pos = _skip_name(msg, 12) + 4       # question name + qtype/qclass
        best = MAX_TTL
        for _ in range(ancount):
            pos = _skip_name(msg, pos)
            if pos + 10 > len(msg):
                break
            ttl = struct.unpack_from("!I", msg, pos + 4)[0]
            rdlen = struct.unpack_from("!H", msg, pos + 8)[0]
            best = min(best, ttl)
            pos += 10 + rdlen
        return max(MIN_TTL, min(MAX_TTL, best))
    except Exception:
        return MIN_TTL


def servfail(query: bytes) -> bytes:
    """Build a SERVFAIL answer that mirrors the query's id and question."""
    if len(query) < 12:
        return b""
    out = bytearray(query)
    out[2] = 0x81                            # QR=1, RD copied loosely
    out[3] = (out[3] & 0xF0) | RCODE_SERVFAIL
    struct.pack_into("!HHH", out, 6, 0, 0, 0)  # no answer/authority/additional
    return bytes(out[:12] + query[12:])


# ─── Cache ───────────────────────────────────────────────────────────────────────

@dataclass
class _CacheEntry:
    response: bytes
    expires_at: float


@dataclass
class ProxyStats:
    started_at: float = 0.0
    queries: int = 0
    cache_hits: int = 0
    upstream_errors: int = 0
    active_upstream: str = ""
    last_names: List[str] = field(default_factory=list)

    def snapshot(self) -> dict:
        return {
            "uptime_s": int(time.time() - self.started_at) if self.started_at else 0,
            "queries": self.queries,
            "cache_hits": self.cache_hits,
            "upstream_errors": self.upstream_errors,
            "active_upstream": self.active_upstream,
            "last_names": list(self.last_names[-15:]),
        }


# ─── Proxy ───────────────────────────────────────────────────────────────────────

class LocalDohProxy:
    """Listens on 127.0.0.1:53 and resolves everything over HTTPS."""

    LOCAL_IPV4 = "127.0.0.1"
    LOCAL_IPV6 = "::1"

    def __init__(self, upstreams: Optional[Tuple[DohUpstream, ...]] = None,
                 listen_addr: str = "127.0.0.1", port: int = DNS_PORT,
                 timeout: float = 4.0, workers: int = 12,
                 listen_ipv6: bool = True):
        self.upstreams = list(upstreams or DEFAULT_UPSTREAMS)
        self.listen_addr = listen_addr
        self.port = port
        self.timeout = timeout
        self.workers = workers
        self.listen_ipv6 = listen_ipv6

        self.stats = ProxyStats()
        self.last_error = ""

        # One UDP + one TCP socket per address family we serve. Without the IPv6
        # listener Windows would happily resolve over a leftover IPv6 DNS server
        # and walk straight around the encrypted path.
        self._udp_socks: List[socket.socket] = []
        self._tcp_socks: List[socket.socket] = []
        self._threads: List[threading.Thread] = []
        self._pool: Optional[ThreadPoolExecutor] = None
        self._stop = threading.Event()
        self._cache: Dict[Tuple[str, int], _CacheEntry] = {}
        self._cache_lock = threading.Lock()
        self._conn_local = threading.local()
        self._ssl_ctx = ssl.create_default_context()
        self._upstream_index = 0
        self._running = False

    # ── lifecycle ───────────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> Tuple[bool, str]:
        if self._running:
            return True, "DoH çözümleyici zaten çalışıyor."

        self._stop.clear()

        # IPv4 is mandatory; IPv6 is best-effort (a machine may have it disabled)
        try:
            self._bind_family(socket.AF_INET, self.listen_addr)
        except OSError as e:
            self.last_error = str(e)
            self._close_sockets()
            return False, (f"{self.listen_addr}:{self.port} dinlenemedi ({e}). "
                           "Başka bir DNS servisi (Acrylic, Pi-hole, Internet Connection "
                           "Sharing) portu kullanıyor olabilir.")

        ipv6_ok = False
        if self.listen_ipv6:
            try:
                self._bind_family(socket.AF_INET6, self.LOCAL_IPV6)
                ipv6_ok = True
            except OSError as e:
                logger.info("IPv6 dinleyici açılamadı (%s) — yalnızca IPv4 kullanılacak.", e)

        self._pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="doh")
        self.stats = ProxyStats(started_at=time.time(), active_upstream=str(self.upstreams[0]))
        self._running = True

        for sock in self._udp_socks:
            self._spawn(self._udp_loop, sock, "DoH-UDP")
        for sock in self._tcp_socks:
            self._spawn(self._tcp_loop, sock, "DoH-TCP")

        families = "IPv4+IPv6" if ipv6_ok else "IPv4"
        return True, (f"🔒 Yerel DoH çözümleyici aktif — {self.listen_addr}:{self.port} "
                      f"({families}) → {self.upstreams[0]}")

    def _bind_family(self, family: int, address: str) -> None:
        udp = socket.socket(family, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind((address, self.port))
        udp.settimeout(0.5)
        self._udp_socks.append(udp)

        tcp = socket.socket(family, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            tcp.bind((address, self.port))
            tcp.listen(32)
            tcp.settimeout(0.5)
        except OSError:
            tcp.close()
            raise
        self._tcp_socks.append(tcp)

    def _spawn(self, target, sock: socket.socket, name: str) -> None:
        thread = threading.Thread(target=target, args=(sock,), name=name, daemon=True)
        thread.start()
        self._threads.append(thread)

    def _close_sockets(self) -> None:
        for sock in self._udp_socks + self._tcp_socks:
            try:
                sock.close()
            except Exception:
                pass
        self._udp_socks.clear()
        self._tcp_socks.clear()

    def stop(self) -> Tuple[bool, str]:
        if not self._running:
            return True, "DoH çözümleyici zaten kapalı."

        self._stop.set()
        self._running = False

        for thread in self._threads:
            thread.join(timeout=2)
        self._threads.clear()
        self._close_sockets()

        if self._pool:
            self._pool.shutdown(wait=False)
            self._pool = None

        with self._cache_lock:
            self._cache.clear()

        return True, "Yerel DoH çözümleyici durduruldu."

    # ── listeners ───────────────────────────────────────────────────────────────

    def _udp_loop(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                data, client = sock.recvfrom(MAX_UDP)
            except socket.timeout:
                continue
            except OSError:
                break
            if self._pool:
                self._pool.submit(self._serve_udp, sock, data, client)

    def _serve_udp(self, sock: socket.socket, query: bytes, client) -> None:
        try:
            response = self.resolve(query)
            if response:
                # Truncated answers tell the client to retry over TCP
                if len(response) > 512:
                    response = self._truncate(response)
                sock.sendto(response, client)
        except Exception as e:
            logger.debug("UDP sorgusu başarısız: %s", e)

    def _tcp_loop(self, sock: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self._pool:
                self._pool.submit(self._serve_tcp, conn)

    def _serve_tcp(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(self.timeout)
            header = conn.recv(2)
            if len(header) < 2:
                return
            length = struct.unpack("!H", header)[0]
            query = b""
            while len(query) < length:
                chunk = conn.recv(length - len(query))
                if not chunk:
                    return
                query += chunk
            response = self.resolve(query)
            if response:
                conn.sendall(struct.pack("!H", len(response)) + response)
        except Exception as e:
            logger.debug("TCP sorgusu başarısız: %s", e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _truncate(response: bytes) -> bytes:
        out = bytearray(response[:512])
        out[2] |= 0x02          # TC bit
        return bytes(out)

    # ── resolution ──────────────────────────────────────────────────────────────

    def resolve(self, query: bytes) -> bytes:
        if len(query) < 12:
            return b""

        self.stats.queries += 1
        qid = query[:2]
        name, qtype = parse_question(query)
        key = (name or "", qtype)

        if name:
            self.stats.last_names.append(name)
            if len(self.stats.last_names) > 60:
                del self.stats.last_names[:30]

        cached = self._cache_get(key)
        if cached is not None:
            self.stats.cache_hits += 1
            return qid + cached[2:]

        # RFC 8484 recommends id=0 so responses are cacheable by the upstream
        normalized = b"\x00\x00" + query[2:]
        answer = self._query_upstreams(normalized)
        if answer is None:
            self.stats.upstream_errors += 1
            return servfail(query)

        self._cache_put(key, answer)
        return qid + answer[2:]

    def _cache_get(self, key: Tuple[str, int]) -> Optional[bytes]:
        if not key[0]:
            return None
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.expires_at <= time.time():
                self._cache.pop(key, None)
                return None
            return entry.response

    def _cache_put(self, key: Tuple[str, int], response: bytes) -> None:
        if not key[0]:
            return
        ttl = min_answer_ttl(response)
        with self._cache_lock:
            if len(self._cache) > 4096:
                now = time.time()
                for k, v in list(self._cache.items()):
                    if v.expires_at <= now:
                        self._cache.pop(k, None)
                if len(self._cache) > 4096:
                    self._cache.clear()
            self._cache[key] = _CacheEntry(response, time.time() + ttl)

    def _query_upstreams(self, query: bytes) -> Optional[bytes]:
        """Try the active upstream first, then the rest, rotating on failure."""
        order = self.upstreams[self._upstream_index:] + self.upstreams[:self._upstream_index]
        for offset, upstream in enumerate(order):
            try:
                response = self._post(upstream, query)
                if response:
                    idx = (self._upstream_index + offset) % len(self.upstreams)
                    if idx != self._upstream_index:
                        self._upstream_index = idx
                        self.stats.active_upstream = str(upstream)
                        logger.info("DoH upstream değişti: %s", upstream)
                    return response
            except Exception as e:
                self.last_error = f"{upstream.name}: {e}"
                logger.debug("DoH upstream hatası %s: %s", upstream.name, e)
                self._drop_connection(upstream)
        return None

    def _post(self, upstream: DohUpstream, query: bytes) -> Optional[bytes]:
        conn = self._get_connection(upstream)
        headers = {
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            "Content-Length": str(len(query)),
        }
        try:
            conn.request("POST", upstream.path, body=query, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200 or len(body) < 12:
                raise OSError(f"HTTP {resp.status}")
            return body
        except Exception:
            self._drop_connection(upstream)
            # One transparent retry on a fresh connection (keep-alive can go stale)
            conn = self._get_connection(upstream, force_new=True)
            conn.request("POST", upstream.path, body=query, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            if resp.status != 200 or len(body) < 12:
                raise OSError(f"HTTP {resp.status}")
            return body

    def _connections(self) -> Dict[str, _PinnedHTTPSConnection]:
        if not hasattr(self._conn_local, "conns"):
            self._conn_local.conns = {}
        return self._conn_local.conns

    def _get_connection(self, upstream: DohUpstream, force_new: bool = False) -> _PinnedHTTPSConnection:
        conns = self._connections()
        if force_new or upstream.name not in conns:
            conns[upstream.name] = _PinnedHTTPSConnection(
                upstream.ip, upstream.hostname, self.timeout, self._ssl_ctx
            )
        return conns[upstream.name]

    def _drop_connection(self, upstream: DohUpstream) -> None:
        conn = self._connections().pop(upstream.name, None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ─── Module-level singleton ──────────────────────────────────────────────────────

_proxy: Optional[LocalDohProxy] = None


def get_proxy() -> LocalDohProxy:
    global _proxy
    if _proxy is None:
        _proxy = LocalDohProxy()
    return _proxy


def start(preset_name: str = "Cloudflare") -> Tuple[bool, str]:
    """Start the local resolver, preferring the upstream that matches the profile."""
    proxy = get_proxy()
    if not proxy.is_running:
        proxy.upstreams = list(upstreams_for(preset_name))
        proxy._upstream_index = 0
    return proxy.start()


def stop() -> Tuple[bool, str]:
    return get_proxy().stop() if _proxy is not None else (True, "DoH çözümleyici kapalı.")


def build_query(name: str, qtype: int = 1) -> bytes:
    """Assemble a minimal DNS query message for one name."""
    labels = b"".join(bytes([len(p)]) + p.encode("idna" if not p.isascii() else "ascii")
                      for p in name.rstrip(".").split("."))
    return (struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0)
            + labels + b"\x00" + struct.pack("!HH", qtype, 1))


def parse_a_records(message: bytes) -> List[str]:
    """Pull the A records out of a response, skipping CNAMEs and other types."""
    try:
        pos = _skip_name(message, 12) + 4
        found: List[str] = []
        for _ in range(struct.unpack_from("!H", message, 6)[0]):
            pos = _skip_name(message, pos)
            if pos + 10 > len(message):
                break
            rtype = struct.unpack_from("!H", message, pos)[0]
            rdlen = struct.unpack_from("!H", message, pos + 8)[0]
            if rtype == 1 and rdlen == 4:
                found.append(socket.inet_ntoa(message[pos + 10:pos + 14]))
            pos += 10 + rdlen
        return found
    except Exception:
        return []


def resolve_a(name: str, timeout: float = 6.0) -> List[str]:
    """
    Resolve a name over HTTPS without needing the local listener to be running.

    This is what lets diagnostics and the strategy finder test the DPI layer on its
    own: on a line whose ISP hijacks DNS, resolving through the system resolver
    would send every probe to the block server and every profile would look
    broken, no matter how well the engine works.
    """
    proxy = get_proxy()
    answer = proxy._query_upstreams(build_query(name))
    return parse_a_records(answer) if answer else []


def rotate_upstream() -> Tuple[bool, str]:
    """
    Move to the next DoH provider. Used by the heartbeat guard instead of
    rewriting the adapter's DNS, which would drop the machine back to plaintext.
    """
    if _proxy is None or not _proxy.is_running:
        return False, "DoH çözümleyici çalışmıyor."
    proxy = _proxy
    proxy._upstream_index = (proxy._upstream_index + 1) % len(proxy.upstreams)
    upstream = proxy.upstreams[proxy._upstream_index]
    proxy.stats.active_upstream = str(upstream)
    with proxy._cache_lock:
        proxy._cache.clear()
    return True, f"DoH sağlayıcısı değiştirildi → {upstream}"


def is_running() -> bool:
    return _proxy is not None and _proxy.is_running


def stats() -> dict:
    return get_proxy().stats.snapshot() if _proxy is not None else ProxyStats().snapshot()
