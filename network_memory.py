"""
Discord DNS v3.7 — Network Memory
Remembers which settings measurably worked on each network, so the next
connection on that network starts on the right channel and profile instead of
walking the whole strategy ladder again.

A "network" is identified by the ISP's autonomous system, the Wi-Fi name (or
adapter for wired links) and the default gateway. The three are hashed into a
short fingerprint; only that fingerprint and a human-readable label are stored,
locally, in %APPDATA%\\DiscordDNS\\networks.json. Nothing here leaves the machine.

Choices the user makes by hand always win: the interface only applies a
remembered entry when the user has not picked a channel or profile themselves.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger("NetworkMemory")

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
MAX_ENTRIES = 32
_lock = threading.Lock()


def _store_path() -> str:
    base = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "DiscordDNS")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "networks.json")


STORE_FILE = _store_path()


# ─── Identifying the network ─────────────────────────────────────────────────────

def _run(args) -> str:
    try:
        result = subprocess.run(args, capture_output=True, timeout=6,
                                creationflags=CREATE_NO_WINDOW)
        for encoding in ("utf-8", "cp857", "cp1254"):
            try:
                return result.stdout.decode(encoding)
            except UnicodeDecodeError:
                continue
        return result.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def parse_ssid(netsh_output: str) -> str:
    """The connected Wi-Fi name from `netsh wlan show interfaces` (any locale)."""
    for line in netsh_output.splitlines():
        # "    SSID                   : MyNetwork" — but not the "BSSID" line
        match = re.match(r"^\s*SSID\s*:\s*(.+?)\s*$", line)
        if match:
            return match.group(1)
    return ""


def current_ssid() -> str:
    return parse_ssid(_run(["netsh", "wlan", "show", "interfaces"]))


def default_gateway() -> str:
    """Next hop of the preferred IPv4 default route."""
    out = _run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Sort-Object RouteMetric | Select-Object -First 1).NextHop",
    ])
    return out.strip().splitlines()[0].strip() if out.strip() else ""


def parse_asn(isp_info: Optional[dict]) -> str:
    """'AS12735 TurkNet …' → 'AS12735'. Falls back to the ISP name."""
    if not isp_info:
        return ""
    text = f"{isp_info.get('as', '')} {isp_info.get('org', '')}"
    match = re.search(r"\bAS(\d+)\b", text, re.IGNORECASE)
    if match:
        return f"AS{match.group(1)}"
    return (isp_info.get("isp") or "").strip()


def fingerprint(asn: str, ssid: str, adapter: str, gateway: str) -> str:
    raw = "|".join(part.strip().lower() for part in (asn, ssid or adapter, gateway))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def identify(isp_info: Optional[dict], adapter: str) -> Tuple[str, str]:
    """
    (fingerprint, label) for the network the machine is on right now.
    The label is for the log only — "TurkNet · EvWiFi".
    """
    asn = parse_asn(isp_info)
    ssid = current_ssid()
    gateway = default_gateway()
    isp_name = (isp_info or {}).get("isp") or asn or "Bilinmeyen İSS"
    label = f"{isp_name} · {ssid or adapter}"
    return fingerprint(asn, ssid, adapter, gateway), label


# ─── Storage ─────────────────────────────────────────────────────────────────────

def _load(path: Optional[str] = None) -> Dict[str, dict]:
    try:
        with open(path or STORE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {k: v for k, v in data.items()
                    if isinstance(k, str) and isinstance(v, dict)}
    except Exception:
        pass
    return {}


def _save(data: Dict[str, dict], path: Optional[str] = None) -> bool:
    target = path or STORE_FILE
    tmp = target + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, target)   # never leave a half-written file behind
        return True
    except Exception as e:
        logger.warning("Ağ hafızası kaydedilemedi: %s", e)
        return False


_FIELDS = {"channel": str, "dpi_profile": str, "dns_preset": str}


def remember(key: str, label: str, channel: str, dpi_profile: Optional[str],
             dns_preset: str, path: Optional[str] = None) -> None:
    """Record a verified-working setup for this network."""
    if not key:
        return
    with _lock:
        data = _load(path)
        entry = data.get(key, {})
        entry.update({
            "label": label,
            "channel": channel,
            "dpi_profile": dpi_profile or "",
            "dns_preset": dns_preset,
            "verified_at": int(time.time()),
            "successes": int(entry.get("successes", 0)) + 1,
        })
        data[key] = entry
        if len(data) > MAX_ENTRIES:
            # Drop the networks we have not seen for the longest time
            oldest = sorted(data, key=lambda k: data[k].get("verified_at", 0))
            for stale in oldest[:len(data) - MAX_ENTRIES]:
                data.pop(stale, None)
        _save(data, path)


def recall(key: str, path: Optional[str] = None) -> Optional[dict]:
    """The remembered setup for this network, validated, or None."""
    if not key:
        return None
    with _lock:
        entry = _load(path).get(key)
    if not entry:
        return None
    clean = {}
    for name, kind in _FIELDS.items():
        value = entry.get(name)
        if isinstance(value, kind):
            clean[name] = value
    if "channel" not in clean:
        return None
    clean["label"] = entry.get("label", "") if isinstance(entry.get("label"), str) else ""
    clean["successes"] = entry.get("successes", 0) if isinstance(entry.get("successes"), int) else 0
    clean["dpi_profile"] = clean.get("dpi_profile") or None
    return clean


def forget(key: str, path: Optional[str] = None) -> bool:
    with _lock:
        data = _load(path)
        if key in data:
            data.pop(key)
            return _save(data, path)
    return False


def forget_all(path: Optional[str] = None) -> bool:
    with _lock:
        return _save({}, path)


def count(path: Optional[str] = None) -> int:
    return len(_load(path))
