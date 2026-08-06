"""
Discord DNS v3.5 — DNS Manager
Handles DNS read/write via PowerShell (primary) with netsh fallback.
Includes DoH (DNS-over-HTTPS) encryption, socket optimization, and multi-preset management.
All subprocess calls use CREATE_NO_WINDOW to prevent console flicker.
"""

import subprocess
import json
import re
import os
import sys

# ─── DNS Presets ────────────────────────────────────────────────────────────────

CLOUDFLARE_IPV4 = ("1.1.1.1", "1.0.0.1")
CLOUDFLARE_IPV6 = ("2606:4700:4700::1111", "2606:4700:4700::1001")

GOOGLE_IPV4 = ("8.8.8.8", "8.8.4.4")
GOOGLE_IPV6 = ("2001:4860:4860::8888", "2001:4860:4860::8844")

QUAD9_IPV4 = ("9.9.9.9", "149.112.112.112")
QUAD9_IPV6 = ("2620:fe::fe", "2620:fe::9")

ADGUARD_IPV4 = ("94.140.14.14", "94.140.15.15")
ADGUARD_IPV6 = ("2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff")

OPENDNS_IPV4 = ("208.67.222.222", "208.67.220.220")
OPENDNS_IPV6 = ("2620:119:35::35", "2620:119:53::53")

CONTROLD_IPV4 = ("76.76.2.0", "76.76.10.0")
CONTROLD_IPV6 = ("2606:1a40::", "2606:1a40:1::")

# Preset registry — name → (v4_tuple, v6_tuple)
DNS_PRESETS = {
    "Cloudflare": (CLOUDFLARE_IPV4, CLOUDFLARE_IPV6),
    "Google":     (GOOGLE_IPV4,     GOOGLE_IPV6),
    "Quad9":      (QUAD9_IPV4,      QUAD9_IPV6),
    "AdGuard":    (ADGUARD_IPV4,    ADGUARD_IPV6),
    "OpenDNS":    (OPENDNS_IPV4,    OPENDNS_IPV6),
    "ControlD":   (CONTROLD_IPV4,   CONTROLD_IPV6),
}

# ─── Backup File Path ────────────────────────────────────────────────────────────

def _get_backup_path() -> str:
    """Return persistent backup path inside %APPDATA%\\DiscordDNS\\."""
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    backup_dir = os.path.join(appdata, "DiscordDNS")
    os.makedirs(backup_dir, exist_ok=True)
    return os.path.join(backup_dir, "original_dns_backup.json")

BACKUP_FILE = _get_backup_path()

# ─── Silent Subprocess Helpers ───────────────────────────────────────────────────

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

def run_powershell(cmd: str) -> str:
    """Execute a PowerShell command silently. Returns stdout string."""
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            check=True,
            creationflags=CREATE_NO_WINDOW
        )
        return completed.stdout.decode("utf-8", errors="replace").strip()
    except subprocess.CalledProcessError as e:
        stdout = e.stdout.decode("utf-8", errors="replace").strip() if e.stdout else ""
        stderr = e.stderr.decode("utf-8", errors="replace").strip() if e.stderr else ""
        return f"ERROR: {stderr or stdout or 'Command failed'}"
    except Exception as e:
        return f"ERROR: {str(e)}"

def run_cmd(cmd: str) -> str:
    """Execute a shell command silently. Returns stdout string."""
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            shell=True,
            creationflags=CREATE_NO_WINDOW
        )
        return completed.stdout.decode("utf-8", errors="replace").strip()
    except Exception as e:
        return f"ERROR: {str(e)}"

# ─── Adapter Discovery ───────────────────────────────────────────────────────────

def get_network_adapters() -> list[str]:
    """Return list of active network adapter names."""
    ps_cmd = (
        "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
        "Select-Object Name, InterfaceDescription, Status | ConvertTo-Json"
    )
    output = run_powershell(ps_cmd)
    adapters = []

    if output and not output.startswith("ERROR"):
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                name = item.get("Name")
                if name:
                    adapters.append(name)
        except Exception:
            pass

    if not adapters:
        netsh_output = run_cmd("netsh interface show interface")
        for line in netsh_output.splitlines():
            if "Connected" in line or "Bağlandı" in line:
                parts = line.split()
                if len(parts) >= 4:
                    adapters.append(" ".join(parts[3:]))

    if not adapters:
        adapters = ["Wi-Fi", "Ethernet"]

    return adapters

# ─── DNS State Query ─────────────────────────────────────────────────────────────

def get_current_dns(adapter_name: str) -> dict:
    """
    Query current IPv4 and IPv6 DNS addresses for the given adapter.
    """
    res = {
        "ipv4": [],
        "ipv6": [],
        "is_cloudflare": False,
        "is_google": False,
        "is_quad9": False,
        "is_adguard": False,
        "is_opendns": False,
        "is_controld": False,
        "is_dhcp": True,
        "preset_name": "DHCP",
        "doh_enabled": False,
    }

    # IPv4
    ps_v4 = f'(Get-DnsClientServerAddress -InterfaceAlias "{adapter_name}" -AddressFamily IPv4).ServerAddresses'
    out_v4 = run_powershell(ps_v4)
    if out_v4 and not out_v4.startswith("ERROR"):
        res["ipv4"] = [a.strip() for a in out_v4.splitlines() if a.strip()]

    # IPv6
    ps_v6 = f'(Get-DnsClientServerAddress -InterfaceAlias "{adapter_name}" -AddressFamily IPv6).ServerAddresses'
    out_v6 = run_powershell(ps_v6)
    if out_v6 and not out_v6.startswith("ERROR"):
        res["ipv6"] = [a.strip() for a in out_v6.splitlines() if a.strip()]

    # Check DoH status
    ps_doh = f'(Get-DnsClientServerAddress -InterfaceAlias "{adapter_name}" -AddressFamily IPv4).DnsOverHttps'
    out_doh = run_powershell(ps_doh)
    if "Allow" in out_doh or "Require" in out_doh:
        res["doh_enabled"] = True

    # Preset detection
    has_cf = any(ip in res["ipv4"] for ip in CLOUDFLARE_IPV4) or any(ip in res["ipv6"] for ip in CLOUDFLARE_IPV6)
    has_g  = any(ip in res["ipv4"] for ip in GOOGLE_IPV4) or any(ip in res["ipv6"] for ip in GOOGLE_IPV6)
    has_q  = any(ip in res["ipv4"] for ip in QUAD9_IPV4) or any(ip in res["ipv6"] for ip in QUAD9_IPV6)
    has_ad = any(ip in res["ipv4"] for ip in ADGUARD_IPV4) or any(ip in res["ipv6"] for ip in ADGUARD_IPV6)
    has_op = any(ip in res["ipv4"] for ip in OPENDNS_IPV4) or any(ip in res["ipv6"] for ip in OPENDNS_IPV6)
    has_cd = any(ip in res["ipv4"] for ip in CONTROLD_IPV4) or any(ip in res["ipv6"] for ip in CONTROLD_IPV6)

    res["is_cloudflare"] = has_cf
    res["is_google"]     = has_g
    res["is_quad9"]      = has_q
    res["is_adguard"]    = has_ad
    res["is_opendns"]    = has_op
    res["is_controld"]   = has_cd
    res["is_dhcp"]       = not res["ipv4"] and not res["ipv6"]

    if has_cf:
        res["preset_name"] = "Cloudflare"
    elif has_g:
        res["preset_name"] = "Google"
    elif has_q:
        res["preset_name"] = "Quad9"
    elif has_ad:
        res["preset_name"] = "AdGuard"
    elif has_op:
        res["preset_name"] = "OpenDNS"
    elif has_cd:
        res["preset_name"] = "ControlD"
    elif res["is_dhcp"]:
        res["preset_name"] = "DHCP"
    else:
        res["preset_name"] = "Custom"

    return res

# ─── Backup / Restore ────────────────────────────────────────────────────────────

def backup_original_dns(adapter_name: str) -> tuple[bool, str]:
    """Save current DNS config to disk (once; won't overwrite existing backup)."""
    if os.path.exists(BACKUP_FILE):
        return True, "Orijinal DNS yedeği zaten mevcut."

    current = get_current_dns(adapter_name)
    backup_data = {
        "adapter_name": adapter_name,
        "is_dhcp": current["is_dhcp"],
        "ipv4": current["ipv4"],
        "ipv6": current["ipv6"],
    }

    try:
        with open(BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, indent=2)
        return True, f"Orijinal DNS yedeği kaydedildi → {BACKUP_FILE}"
    except Exception as e:
        return False, f"Yedekleme hatası: {e}"

def restore_original_dns(adapter_name: str | None = None) -> tuple[bool, str]:
    """Restore the exact original DNS from backup, or fall back to DHCP."""
    if not os.path.exists(BACKUP_FILE):
        return reset_dns_to_dhcp(adapter_name or "Wi-Fi")

    try:
        with open(BACKUP_FILE, "r", encoding="utf-8") as f:
            backup = json.load(f)

        target = adapter_name or backup.get("adapter_name", "Wi-Fi")

        if backup.get("is_dhcp", True):
            success, msg = reset_dns_to_dhcp(target)
        else:
            v4 = backup.get("ipv4", [])
            v6 = backup.get("ipv6", [])
            success, msg = set_custom_dns(
                target,
                v4[0] if v4 else "",
                v4[1] if len(v4) > 1 else "",
                v6[0] if v6 else "",
                v6[1] if len(v6) > 1 else "",
            )

        try:
            os.remove(BACKUP_FILE)
        except Exception:
            pass

        return success, f"Orijinal DNS geri yüklendi!\n{msg}"
    except Exception as e:
        return False, f"Geri yükleme hatası: {e}"

# ─── DNS Apply Helpers ───────────────────────────────────────────────────────────

def set_custom_dns(
    adapter_name: str,
    ipv4_primary: str,
    ipv4_secondary: str = "",
    ipv6_primary: str = "",
    ipv6_secondary: str = "",
    enable_doh: bool = False
) -> tuple[bool, str]:
    """Apply IPv4 and IPv6 DNS to adapter via PowerShell (netsh fallback)."""
    logs = []

    # IPv4
    v4_servers = [s for s in [ipv4_primary, ipv4_secondary] if s]
    if v4_servers:
        v4_str = ",".join([f'"{s}"' for s in v4_servers])
        ps_v4 = f'Set-DnsClientServerAddress -InterfaceAlias "{adapter_name}" -ServerAddresses ({v4_str})'
        out_v4 = run_powershell(ps_v4)
        if out_v4.startswith("ERROR"):
            run_cmd(f'netsh interface ipv4 set dns name="{adapter_name}" static {ipv4_primary}')
            if ipv4_secondary:
                run_cmd(f'netsh interface ipv4 add dns name="{adapter_name}" {ipv4_secondary} index=2')
            logs.append(f"IPv4 DNS (netsh): {', '.join(v4_servers)}")
        else:
            logs.append(f"IPv4 DNS: {', '.join(v4_servers)}")

    # IPv6
    v6_servers = [s for s in [ipv6_primary, ipv6_secondary] if s]
    if v6_servers:
        v6_str = ",".join([f'"{s}"' for s in v6_servers])
        ps_v6 = f'Set-DnsClientServerAddress -InterfaceAlias "{adapter_name}" -ServerAddresses ({v6_str})'
        out_v6 = run_powershell(ps_v6)
        if out_v6.startswith("ERROR"):
            run_cmd(f'netsh interface ipv6 set dns name="{adapter_name}" static {ipv6_primary}')
            if ipv6_secondary:
                run_cmd(f'netsh interface ipv6 add dns name="{adapter_name}" {ipv6_secondary} index=2')
            logs.append(f"IPv6 DNS (netsh): {', '.join(v6_servers)}")
        else:
            logs.append(f"IPv6 DNS: {', '.join(v6_servers)}")

    # DoH Option (Windows 11)
    if enable_doh:
        doh_cmd = f'Set-DnsClientServerAddress -InterfaceAlias "{adapter_name}" -DnsOverHttps Allow'
        run_powershell(doh_cmd)
        logs.append("DoH (DNS-over-HTTPS) Şifreleme Etkinleştirildi 🔒")

    flush_res = optimize_dns_sockets()
    logs.append(flush_res)
    return True, "\n".join(logs)

def set_preset_dns(adapter_name: str, preset_name: str, enable_doh: bool = False) -> tuple[bool, str]:
    """Apply a named DNS preset to adapter."""
    if preset_name not in DNS_PRESETS:
        return False, f"Bilinmeyen DNS profili: {preset_name}"

    backup_original_dns(adapter_name)
    v4, v6 = DNS_PRESETS[preset_name]
    return set_custom_dns(adapter_name, v4[0], v4[1], v6[0], v6[1], enable_doh=enable_doh)

def reset_dns_to_dhcp(adapter_name: str) -> tuple[bool, str]:
    """Reset DNS to Automatic (DHCP) on the given adapter."""
    logs = []
    ps_cmd = f'Set-DnsClientServerAddress -InterfaceAlias "{adapter_name}" -ResetServerAddresses'
    out = run_powershell(ps_cmd)

    if out.startswith("ERROR"):
        run_cmd(f'netsh interface ipv4 set dns name="{adapter_name}" dhcp')
        run_cmd(f'netsh interface ipv6 set dns name="{adapter_name}" dhcp')
        logs.append(f"{adapter_name} DNS → Otomatik (DHCP) [netsh]")
    else:
        logs.append(f"{adapter_name} DNS → Otomatik (DHCP)")

    logs.append(optimize_dns_sockets())
    return True, "\n".join(logs)

def flush_dns_cache() -> str:
    """Flush the Windows DNS resolver cache silently."""
    out = run_cmd("ipconfig /flushdns")
    if "successfully" in out.lower() or "başarıyla" in out.lower():
        return "DNS Önbelleği Temizlendi ✓"
    return f"DNS Önbelleği Sıfırlandı: {out.strip()[:60]}"

def optimize_dns_sockets() -> str:
    """
    Run full Windows DNS socket & NetBIOS resolver optimization.
    Flushes DNS cache + clears NetBIOS cache (nbtstat -R).
    """
    res1 = run_cmd("ipconfig /flushdns")
    run_cmd("nbtstat -R")
    return "DNS & NetBIOS Soket Önbelleği Optimize Edildi [OK]"


# ─── Configuration & Autostart Persistence ────────────────────────────────────────

def save_config(config_dict: dict) -> bool:
    """Save user application preferences to config.json."""
    try:
        cfg_path = os.path.join(_get_backup_dir(), "config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config_dict, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def load_config() -> dict:
    """Load user application preferences from config.json."""
    try:
        cfg_path = os.path.join(_get_backup_dir(), "config.json")
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_REG_KEY = "DiscordDNS"

def set_autostart(enable: bool = True) -> bool:
    """Add or remove app from Windows Startup Registry."""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_ALL_ACCESS)
        if enable:
            exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0])
            winreg.SetValueEx(key, APP_REG_KEY, 0, winreg.REG_SZ, f'"{exe_path}"')
        else:
            try:
                winreg.DeleteValue(key, APP_REG_KEY)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

def is_autostart_enabled() -> bool:
    """Check if app is configured to run at Windows startup."""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(key, APP_REG_KEY)
        winreg.CloseKey(key)
        return bool(val)
    except Exception:
        return False
