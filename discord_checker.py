"""
Discord DNS v3.6 — Discord Connectivity & Voice Region Checker
Provides TCP-based latency tests to Discord API endpoints and voice server regions.
Uses Discord Voice Anycast endpoints & fallback IPs for 100% reliable latency measurement.
"""

import socket
import time
import threading
from typing import Dict, List, Any

# ─── Primary Discord Endpoints ───────────────────────────────────────────────────

DISCORD_HOSTS = [
    ("discord.com",         443),
    ("gateway.discord.gg",  443),
    ("cdn.discordapp.com",  443),
]

# ─── Voice Region Endpoints (TCP:443 test proxy for WebRTC latency) ──────────────
# Anycast Discord Voice Endpoints & Cloudflare IPs
VOICE_REGIONS: Dict[str, List[str]] = {
    "🇳🇱 Rotterdam":   ["rotterdam.discord.gg", "rotterdam.discord.media", "162.159.128.233"],
    "🇩🇪 Frankfurt":   ["frankfurt.discord.gg", "frankfurt.discord.media", "162.159.129.232"],
    "🇷🇴 Bucharest":   ["bucharest.discord.gg", "bucharest.discord.media", "162.159.134.2"],
    "🇬🇧 London":      ["london.discord.gg", "london.discord.media", "162.159.135.2"],
    "🇺🇸 US East":     ["us-east.discord.gg", "us-east.discord.media", "162.159.136.2"],
    "🇺🇸 US Central":  ["us-central.discord.gg", "us-central.discord.media", "162.159.136.3"],
    "🇸🇬 Singapore":   ["singapore.discord.gg", "singapore.discord.media", "162.159.137.2"],
    "🇮🇳 Mumbai":      ["india.discord.gg", "india.discord.media", "162.159.138.2"],
    "🇧🇷 Brazil":      ["brazil.discord.gg", "brazil.discord.media", "162.159.139.2"],
    "🇦🇺 Sydney":      ["sydney.discord.gg", "sydney.discord.media", "162.159.140.2"],
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
            results.append(f"{host}: {int(elapsed_ms)} ms OK")
        except Exception as exc:
            results.append(f"{host}: Baglanamadi ({type(exc).__name__})")

    accessible = successful > 0
    avg_ping   = int(total_time / successful) if successful > 0 else -1

    if accessible:
        details = f"Discord Baglantisi OK ({successful}/{len(DISCORD_HOSTS)}) - Ort. {avg_ping} ms"
    else:
        details = "Discord Sunucularina Erisilemiyor (DNS veya ISS Engeli)"

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

def _ping_region(label: str, targets: Any, port: int, timeout: float, results: dict):
    """Thread worker: TCP ping a single voice region via host/IP candidates."""
    candidates = targets if isinstance(targets, list) else [targets]
    for target in candidates:
        start = time.perf_counter()
        try:
            sock = socket.create_connection((target, port), timeout=timeout)
            sock.close()
            ms = int((time.perf_counter() - start) * 1000)
            results[label] = {"ms": ms, "ok": True}
            return
        except Exception:
            pass
    results[label] = {"ms": -1, "ok": False}

def check_voice_regions(timeout: float = 3.0) -> dict[str, dict]:
    """
    Concurrently TCP-ping all Discord voice server regions.

    Returns:
        dict mapping region_label -> {'ms': int, 'ok': bool}
        ms == -1 means unreachable.
    """
    results: dict[str, dict] = {}
    threads = []

    for label, hosts in VOICE_REGIONS.items():
        t = threading.Thread(
            target=_ping_region,
            args=(label, hosts, VOICE_REGION_PORT, timeout, results),
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
    print("=== Discord Connection Test ===")
    res = check_discord_connection()
    print(res["details"])
    for r in res["host_results"]:
        print(" ", r)

    print("\n=== Voice Region Ping Matrix ===")
    regions = check_voice_regions()
    for label, info in sorted(regions.items(), key=lambda x: x[1]["ms"] if x[1]["ok"] else 9999):
        ping_str = f"{info['ms']} ms" if info["ok"] else "Unreachable"
        name_only = label.split(" ", 1)[-1] if " " in label else label
        print(f"  {name_only}: {ping_str}")
