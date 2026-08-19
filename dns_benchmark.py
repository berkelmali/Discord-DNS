"""
Discord DNS v3.6 — Multi-DNS Speed Benchmark Engine
Concurrently measures DNS resolution latency to Discord domain endpoints (discord.com)
across top DNS providers using direct socket DNS queries.
"""

import socket
import time
import threading
import struct
from typing import Callable, Optional

# ─── DNS Providers to Benchmark ─────────────────────────────────────────────────

BENCHMARK_PROVIDERS = {
    "Cloudflare": {
        "v4_primary": "1.1.1.1",
        "v4_secondary": "1.0.0.1",
        "v6_primary": "2606:4700:4700::1111",
        "v6_secondary": "2606:4700:4700::1001",
    },
    "Google": {
        "v4_primary": "8.8.8.8",
        "v4_secondary": "8.8.4.4",
        "v6_primary": "2001:4860:4860::8888",
        "v6_secondary": "2001:4860:4860::8844",
    },
    "Quad9": {
        "v4_primary": "9.9.9.9",
        "v4_secondary": "149.112.112.112",
        "v6_primary": "2620:fe::fe",
        "v6_secondary": "2620:fe::9",
    },
    "AdGuard": {
        "v4_primary": "94.140.14.14",
        "v4_secondary": "94.140.15.15",
        "v6_primary": "2a10:50c0::ad1:ff",
        "v6_secondary": "2a10:50c0::ad2:ff",
    },
    "OpenDNS": {
        "v4_primary": "208.67.222.222",
        "v4_secondary": "208.67.220.220",
        "v6_primary": "2620:119:35::35",
        "v6_secondary": "2620:119:53::53",
    },
    "ControlD": {
        "v4_primary": "76.76.2.0",
        "v4_secondary": "76.76.10.0",
        "v6_primary": "2606:1a40::",
        "v6_secondary": "2606:1a40:1::",
    },
}

TARGET_HOST = "discord.com"


# ─── Raw DNS Query Builder (Standard A-record query) ────────────────────────────

def _build_dns_query(hostname: str) -> bytes:
    """Build raw DNS A-record query packet for given hostname."""
    # Transaction ID (2 bytes) + Flags 0x0100 (Standard query)
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = b""
    for part in hostname.split("."):
        encoded = part.encode("ascii")
        question += bytes([len(encoded)]) + encoded
    question += b"\x00"  # Null label
    question += struct.pack(">HH", 1, 1)  # Type A (1), Class IN (1)
    return header + question


# ─── Single Server Benchmark ────────────────────────────────────────────────────

def ping_dns_server(ip: str, timeout: float = 2.0) -> int:
    """
    Send direct raw DNS query packet to given DNS IP over UDP:53.
    Returns latency in ms, or -1 if unreachable/timeout.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        query = _build_dns_query(TARGET_HOST)

        start = time.perf_counter()
        sock.sendto(query, (ip, 53))
        _, _ = sock.recvfrom(512)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return elapsed_ms
    except Exception:
        # Fallback to TCP port 53 if UDP is throttled/blocked
        try:
            start = time.perf_counter()
            s = socket.create_connection((ip, 53), timeout=timeout)
            s.close()
            return int((time.perf_counter() - start) * 1000)
        except Exception:
            return -1
    finally:
        if sock:
            sock.close()


# ─── Multi-Provider Benchmark ───────────────────────────────────────────────────

def benchmark_all_providers(timeout: float = 2.5) -> dict[str, dict]:
    """
    Benchmark all DNS providers concurrently.

    Returns:
        dict: provider_name -> {
            'ms': int,             # Latency in ms (-1 if unreachable)
            'ok': bool,
            'ip': str,
            'info': dict
        }
    """
    results: dict[str, dict] = {}
    threads = []

    def _worker(name: str, info: dict):
        ip = info["v4_primary"]
        ms = ping_dns_server(ip, timeout=timeout)
        results[name] = {
            "ms": ms,
            "ok": ms >= 0,
            "ip": ip,
            "info": info,
        }

    for name, info in BENCHMARK_PROVIDERS.items():
        t = threading.Thread(target=_worker, args=(name, info), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=timeout + 1)

    return results


def find_fastest_provider(timeout: float = 2.5) -> tuple[Optional[str], int, dict]:
    """
    Run benchmark and return the fastest available provider.

    Returns:
        tuple: (fastest_name, latency_ms, provider_info_dict)
    """
    results = benchmark_all_providers(timeout=timeout)
    valid = [
        (name, data["ms"], data["info"])
        for name, data in results.items()
        if data["ok"] and data["ms"] > 0
    ]

    if not valid:
        return None, -1, {}

    valid.sort(key=lambda x: x[1])
    fastest_name, fastest_ms, fastest_info = valid[0]
    return fastest_name, fastest_ms, fastest_info


if __name__ == "__main__":
    print("=== Multi-DNS Benchmark Test ===")
    res = benchmark_all_providers()
    for name, data in sorted(res.items(), key=lambda x: x[1]["ms"] if x[1]["ok"] else 9999):
        status = f"{data['ms']} ms" if data["ok"] else "Erişilemiyor"
        print(f"  {name:12s} ({data['ip']}): {status}")

    fastest, ms, _ = find_fastest_provider()
    print(f"\nEn Hızlı DNS: {fastest} ({ms} ms)")
