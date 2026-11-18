"""
Discord DNS v3.7 — DNS Leak Test & Browser Secure-DNS Check

Two questions a user cannot answer by looking at their adapter settings:

1. *Who actually answers my DNS queries?*  The adapter can say 127.0.0.1 or
   1.1.1.1 while a second adapter, an IPv6 router advertisement or a VPN
   client quietly sends the queries to the ISP. The test asks the system
   resolver for whoami.akamai.net — Akamai's authoritative server replies with
   the address of whichever resolver asked it — and matches that address to a
   known public DNS operator.

2. *Does my browser even use the system DNS?*  Chrome, Edge, Brave, Opera and
   Firefox can run their own encrypted DNS. In "secure" mode they ignore the
   system completely, which is why a site can keep opening in the browser after
   the app has disconnected (and why the app's own DNS channels do not affect
   that browser at all).

Only reads — nothing here changes a browser or system setting.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

PROBE_NAME = "whoami.akamai.net"

# Published egress / anycast ranges of the operators the app offers. These are
# the networks whoami.akamai.net reports when the resolver belongs to them.
_OPERATOR_RANGES: Dict[str, Tuple[str, ...]] = {
    "Cloudflare": (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "1.1.1.0/24", "1.0.0.0/24",
    ),
    "Google": (
        "8.8.8.0/24", "8.8.4.0/24", "172.217.0.0/16", "172.253.0.0/16",
        "173.194.0.0/16", "74.125.0.0/16", "108.177.0.0/17", "142.250.0.0/15",
        "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19", "209.85.128.0/17",
        "216.239.32.0/19",
    ),
    "Quad9": ("9.9.9.0/24", "149.112.112.0/24"),
    "AdGuard": ("94.140.14.0/24", "94.140.15.0/24"),
    "OpenDNS": ("208.67.216.0/21", "146.112.0.0/16"),
    "ControlD": ("76.76.2.0/24", "76.76.10.0/24"),
}

_NETWORKS = {
    name: tuple(ipaddress.ip_network(cidr) for cidr in cidrs)
    for name, cidrs in _OPERATOR_RANGES.items()
}


def operator_for(address: str) -> Optional[str]:
    """Which public DNS operator owns this resolver address, if any."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    for name, networks in _NETWORKS.items():
        if any(ip in net for net in networks if net.version == ip.version):
            return name
    return None


# ─── Leak test ───────────────────────────────────────────────────────────────────

@dataclass
class LeakResult:
    resolver_ip: str = ""
    operator: Optional[str] = None
    expected: Optional[str] = None      # operator the app configured, None = ISP/DHCP
    error: str = ""

    @property
    def leaking(self) -> bool:
        """The app set a public provider, but someone else answered."""
        return bool(self.resolver_ip) and self.expected is not None \
            and self.operator != self.expected

    @property
    def verdict(self) -> str:
        if self.error:
            return f"Test yapılamadı: {self.error}"
        who = self.operator or "tanınmayan bir sunucu (büyük olasılıkla İSS'niz)"
        if self.expected is None:
            return f"DNS yönetilmiyor — sorguları {who} yanıtlıyor."
        if not self.leaking:
            return f"✓ Sızıntı yok — sorgular beklendiği gibi {self.operator} üzerinden gidiyor."
        return (f"⚠ Olası sızıntı — {self.expected} bekleniyordu ama sorguları {who} yanıtladı. "
                "Başka bir ağ kartı, IPv6 yönlendirici DNS'i veya bir VPN istemcisi sorguları "
                "başka yere gönderiyor olabilir.")


def run_leak_test(expected: Optional[str]) -> LeakResult:
    """
    Resolve the probe through the normal Windows resolver — the same path every
    application on the machine uses — and identify who answered.
    """
    result = LeakResult(expected=expected)
    try:
        infos = socket.getaddrinfo(PROBE_NAME, None, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            result.resolver_ip = infos[0][4][0]
            result.operator = operator_for(result.resolver_ip)
    except Exception as e:
        result.error = str(e)[:80]
    return result


# ─── Browser secure-DNS check ────────────────────────────────────────────────────

@dataclass
class BrowserDns:
    browser: str
    mode: str                   # off | automatic | secure | unknown
    provider: str = ""
    policy: bool = False        # forced by group policy

    @property
    def bypasses_system(self) -> bool:
        return self.mode == "secure"

    @property
    def summary(self) -> str:
        source = " (kurum ilkesiyle)" if self.policy else ""
        if self.mode == "secure":
            via = f" → {self.provider}" if self.provider else ""
            return (f"{self.browser}: kendi şifreli DNS'i AÇIK{via}{source} — sistem DNS'ini "
                    "kullanmaz, uygulamanın DNS kanalları bu tarayıcıyı etkilemez.")
        if self.mode == "automatic":
            return (f"{self.browser}: otomatik{source} — sistem DNS'i destekliyorsa şifreliye "
                    "yükseltir, yoksa sistem DNS'ini kullanır.")
        if self.mode == "off":
            return f"{self.browser}: kapalı{source} — sistem DNS'ini kullanır."
        return f"{self.browser}: durum okunamadı."


_CHROMIUM_STATES = (
    ("Chrome", r"%LOCALAPPDATA%\Google\Chrome\User Data\Local State",
     r"SOFTWARE\Policies\Google\Chrome"),
    ("Edge", r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State",
     r"SOFTWARE\Policies\Microsoft\Edge"),
    ("Brave", r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Local State",
     r"SOFTWARE\Policies\BraveSoftware\Brave"),
    ("Opera", r"%APPDATA%\Opera Software\Opera Stable\Local State", None),
    ("Vivaldi", r"%LOCALAPPDATA%\Vivaldi\User Data\Local State", None),
)


def provider_name(template: str) -> str:
    """'https://cloudflare-dns.com/dns-query' → 'cloudflare-dns.com'."""
    match = re.search(r"https://([^/{\s]+)", template or "")
    return match.group(1) if match else ""


def parse_chromium_state(state: dict) -> Tuple[str, str]:
    """(mode, provider) from a Chromium 'Local State' document."""
    doh = state.get("dns_over_https") if isinstance(state, dict) else None
    if not isinstance(doh, dict):
        # Chromium's default when the user never touched the setting
        return "automatic", ""
    mode = doh.get("mode") if isinstance(doh.get("mode"), str) else "automatic"
    return mode, provider_name(doh.get("templates", ""))


def parse_firefox_prefs(text: str) -> Tuple[str, str]:
    """(mode, provider) from a Firefox prefs.js. TRR modes: 2 first, 3 only, 0/5 off."""
    mode_match = re.search(r'user_pref\("network\.trr\.mode",\s*(\d+)\)', text)
    uri_match = re.search(r'user_pref\("network\.trr\.uri",\s*"([^"]*)"\)', text)
    provider = provider_name(uri_match.group(1)) if uri_match else ""
    if not mode_match:
        return "off", provider
    value = int(mode_match.group(1))
    if value == 3:
        return "secure", provider
    if value == 2:
        return "automatic", provider
    return "off", provider


def _policy_mode(key_path: Optional[str]) -> Tuple[Optional[str], str]:
    if not key_path or sys.platform != "win32":
        return None, ""
    try:
        import winreg
    except ImportError:
        return None, ""
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            with winreg.OpenKey(hive, key_path) as key:
                mode, _ = winreg.QueryValueEx(key, "DnsOverHttpsMode")
                try:
                    templates, _ = winreg.QueryValueEx(key, "DnsOverHttpsTemplates")
                except OSError:
                    templates = ""
                if isinstance(mode, str):
                    return mode, provider_name(templates)
        except OSError:
            continue
    return None, ""


def check_browsers() -> List[BrowserDns]:
    """Secure-DNS mode of every installed browser we know how to read."""
    found: List[BrowserDns] = []
    for name, state_path, policy_key in _CHROMIUM_STATES:
        path = os.path.expandvars(state_path)
        if not os.path.exists(path):
            continue
        policy, policy_provider = _policy_mode(policy_key)
        if policy:
            found.append(BrowserDns(name, policy, policy_provider, policy=True))
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                mode, provider = parse_chromium_state(json.load(f))
        except Exception:
            mode, provider = "unknown", ""
        found.append(BrowserDns(name, mode, provider))

    profiles = os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
    if os.path.isdir(profiles):
        for profile in sorted(os.listdir(profiles)):
            prefs = os.path.join(profiles, profile, "prefs.js")
            if not os.path.exists(prefs):
                continue
            try:
                with open(prefs, "r", encoding="utf-8", errors="replace") as f:
                    mode, provider = parse_firefox_prefs(f.read())
            except Exception:
                mode, provider = "unknown", ""
            found.append(BrowserDns("Firefox", mode, provider))
            break   # the default profile is enough to explain the behaviour
    return found


# ─── Report ──────────────────────────────────────────────────────────────────────

def expected_operator(doh_running: bool, active_upstream: str,
                      adapter_preset: str, is_dhcp: bool,
                      servers=()) -> Optional[str]:
    """Which operator should be answering, given how the adapter is configured."""
    if doh_running:
        for name in _OPERATOR_RANGES:
            if name.lower() in (active_upstream or "").lower():
                return name
        return None
    if is_dhcp:
        return None
    if adapter_preset in _OPERATOR_RANGES:
        return adapter_preset
    # Hand-typed servers: recognise them by address
    for server in servers or ():
        name = operator_for(server)
        if name:
            return name
    return None


def report_lines(leak: LeakResult, browsers: List[BrowserDns]) -> List[str]:
    """Plain Turkish lines for the log and the diagnostics report."""
    import diagnostics   # local import: diagnostics imports this module too
    lines = []
    if leak.resolver_ip:
        lines.append(f"Yanıtlayan  : {diagnostics.mask_ip(leak.resolver_ip)} "
                     f"({leak.operator or 'tanınmadı'})")
    lines.append(f"Sızıntı     : {leak.verdict}")
    if not browsers:
        lines.append("Tarayıcılar : okunabilen tarayıcı bulunamadı")
    for item in browsers:
        lines.append(f"Tarayıcı    : {item.summary}")
    if any(item.bypasses_system for item in browsers):
        lines.append("Not         : Bağlantıyı kestikten sonra bir site tarayıcıda açılmaya devam "
                     "ediyorsa nedeni budur — tarayıcı kendi şifreli DNS'ini kullanıyor.")
    return lines
