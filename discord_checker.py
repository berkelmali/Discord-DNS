"""
Discord DNS v3.0 — Discord Connectivity & Voice Region Checker
Provides TCP-based latency tests to Discord API endpoints and voice server regions.
UDP is not used (requires raw sockets/admin on Windows); TCP:443 is a reliable proxy.
"""

import socket
import time
import ssl
import threading
from typing import Callable

# ─── Primary Discord Endpoints ───────────────────────────────────────────────────

DISCORD_HOSTS = [
    ("discord.com",         443),
    ("gateway.discord.gg",  443),
    ("cdn.discordapp.com",  443),
]

# ─── Voice Region Endpoints (TCP:443 test proxy for WebRTC latency) ──────────────
# Discord voice servers are reachable via HTTPS on these hostnames.
VOICE_REGIONS = {
    "🇳🇱 Rotterdam":   "rotterdam.discord.media",
    "🇩🇪 Frankfurt":   "frankfurt.discord.media",
    "🇷🇴 Bucharest":   "bucharest.discord.media",
    "🇬🇧 London":      "london.discord.media",
    "🇺🇸 US East":     "us-east.discord.media",
    "🇺🇸 US Central":  "us-central.discord.media",
    "🇸🇬 Singapore":   "singapore.discord.media",
    "🇮🇳 Mumbai":      "india.discord.media",
    "🇧🇷 Brazil":      "brazil.discord.media",
    "🇦🇺 Sydney":      "sydney.discord.media",
}

VOICE_REGION_PORT = 443

# ─── Main Connection Check ────────────────────────────────────────────────────────

def check_discord_connection(timeout: float = 3.0) -> dict:
    """
    Test TCP connectivity and measure average latency to Discord endpoints.

    Returns:
        dict with keys:
          accessible  : bool
          ping_ms     : int   (-1 if unreachable)
          details     : str
          host_results: list[str]
    """
    results = []
    total_time = 0.0
    successful = 0

    for host, port in DISCORD_HOSTS:
        start = time.perf_counter()
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            elapsed_ms = (time.perf_counter() - start) * 1000
            total_time += elapsed_ms
            successful += 1
            results.append(f"{host}: {int(elapsed_ms)} ms ✓")
        except Exception as exc:
            results.append(f"{host}: Bağlanamadı ({type(exc).__name__})")

    accessible = successful > 0
    avg_ping   = int(total_time / successful) if successful > 0 else -1

    if accessible:
        details = f"Discord Bağlantısı OK ({successful}/{len(DISCORD_HOSTS)}) — Ort. {avg_ping} ms"
    else:
        details = "Discord Sunucularına Erişilemiyor (DNS veya ISS Engeli)"

    return {
        "accessible":   accessible,
        "ping_ms":      avg_ping,
        "details":      details,
        "host_results": results,
    }

# ─── Single Heartbeat Ping ────────────────────────────────────────────────────────

def heartbeat_ping(timeout: float = 2.5) -> dict:
    """
    Lightweight single-host check used by HeartbeatGuard.
    Targets discord.com:443 only for speed.

    Returns:
        dict: {'ok': bool, 'ping_ms': int}
    """
    host, port = "discord.com", 443
    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return {"ok": True, "ping_ms": int((time.perf_counter() - start) * 1000)}
    except Exception:
        return {"ok": False, "ping_ms": -1}

# ─── Voice Region Ping Matrix ─────────────────────────────────────────────────────

def _ping_region(label: str, host: str, port: int, timeout: float, results: dict):
    """Thread worker: TCP ping a single voice region and store result."""
    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        ms = int((time.perf_counter() - start) * 1000)
        results[label] = {"ms": ms, "ok": True}
    except Exception:
        results[label] = {"ms": -1, "ok": False}

def check_voice_regions(timeout: float = 3.0) -> dict[str, dict]:
    """
    Concurrently TCP-ping all Discord voice server regions.

    Returns:
        dict mapping region_label → {'ms': int, 'ok': bool}
        ms == -1 means unreachable.
    """
    results: dict[str, dict] = {}
    threads = []

    for label, host in VOICE_REGIONS.items():
        t = threading.Thread(
            target=_ping_region,
            args=(label, host, VOICE_REGION_PORT, timeout, results),
            daemon=True
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=timeout + 1)

    # Fill missing entries (thread timeout edge case)
    for label in VOICE_REGIONS:
        if label not in results:
            results[label] = {"ms": -1, "ok": False}

    return results

def ping_color(ms: int) -> str:
    """Return a semantic color hex for a given ping value."""
    if ms < 0:
        return "#6B7280"   # Gray  — unreachable
    if ms < 60:
        return "#34D399"   # Green — excellent
    if ms < 120:
        return "#FCD34D"   # Yellow — good
    if ms < 200:
        return "#F97316"   # Orange — fair
    return "#F87171"       # Red   — poor

if __name__ == "__main__":
    print("=== Discord Bağlantı Testi ===")
    res = check_discord_connection()
    print(res["details"])
    for r in res["host_results"]:
        print(" ", r)

    print("\n=== Ses Bölgesi Ping Matrisi ===")
    regions = check_voice_regions()
    for label, info in sorted(regions.items(), key=lambda x: x[1]["ms"] if x[1]["ok"] else 9999):
        ping_str = f"{info['ms']} ms" if info["ok"] else "Erişilemiyor"
        print(f"  {label}: {ping_str}")
