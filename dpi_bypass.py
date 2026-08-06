"""
Discord DNS v3.5 — DPI Bypass Engine & ISP Auto-Detector
Provides deep packet inspection (DPI) bypass, SNI fragmenting, and DoH tunneling
specifically tailored for non-TurkNet Turkish ISPs (Superonline, Türk Telekom, Vodafone).
"""

import os
import sys
import json
import subprocess
import urllib.request
import zipfile
import shutil
import logging
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger("DPIBypass")

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

# ─── APPDATA STORAGE ──────────────────────────────────────────────────────────────

def _get_bin_dir() -> str:
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    bin_dir = os.path.join(appdata, "DiscordDNS", "bin")
    os.makedirs(bin_dir, exist_ok=True)
    return bin_dir

BIN_DIR = _get_bin_dir()
GOODBYEDPI_EXE = os.path.join(BIN_DIR, "goodbyedpi.exe")

# GoodbyeDPI download source (v0.2.2 stable release binary)
GOODBYEDPI_ZIP_URL = "https://github.com/ValdikSS/GoodbyeDPI/releases/download/0.2.2/goodbyedpi-0.2.2.zip"

# Global process handle
_dpi_process: Optional[subprocess.Popen] = None


# ─── ISP AUTO DETECTION ───────────────────────────────────────────────────────────

def detect_isp() -> Dict[str, Any]:
    """
    Detect the user's active Internet Service Provider (ISP).
    Returns dict with ISP name, organization, and recommended bypass mode.
    """
    info = {
        "isp": "Bilinmiyor",
        "org": "",
        "as": "",
        "ip": "",
        "is_turknet": False,
        "is_superonline": False,
        "is_ttnet": False,
        "is_vodafone": False,
        "recommended_channel": "Standart DNS",
        "recommendation_text": "TürkNet bağlantısı tespit edildi. Standart DNS yeterlidir.",
    }

    try:
        req = urllib.request.Request("http://ip-api.com/json", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as res:
            data = json.loads(res.read().decode("utf-8"))
            info["isp"] = data.get("isp", "Bilinmiyor")
            info["org"] = data.get("org", "")
            info["as"]  = data.get("as", "")
            info["ip"]  = data.get("query", "")
    except Exception:
        try:
            req = urllib.request.Request("https://ipinfo.io/json", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=4) as res:
                data = json.loads(res.read().decode("utf-8"))
                info["isp"] = data.get("org", "Bilinmiyor")
                info["org"] = data.get("org", "")
                info["ip"]  = data.get("ip", "")
        except Exception:
            pass

    full_str = f"{info['isp']} {info['org']} {info['as']}".lower()

    if "turknet" in full_str:
        info["is_turknet"] = True
        info["recommended_channel"] = "Standart DNS"
        info["recommendation_text"] = "TurkNet -- Engelleme yok. Standart Cloudflare DNS önerilir."
    elif "superonline" in full_str or "sol" in full_str:
        info["is_superonline"] = True
        info["recommended_channel"] = "Superonline DPI Bypass"
        info["recommendation_text"] = "Superonline -- Ağır DPI & SNI engeli var. DPI Bypass Kanalı ÖNERİLİR!"
    elif "turk telekom" in full_str or "ttnet" in full_str or "tt-net" in full_str:
        info["is_ttnet"] = True
        info["recommended_channel"] = "Türk Telekom DPI Bypass"
        info["recommendation_text"] = "Türk Telekom -- SNI & DNS Yönlendirmesi var. DoH + DPI Bypass ÖNERİLİR!"
    elif "vodafone" in full_str:
        info["is_vodafone"] = True
        info["recommended_channel"] = "DoH Şifreli DNS"
        info["recommendation_text"] = "Vodafone -- DNS Hijacking var. DoH Şifreli DNS ÖNERİLİR!"
    else:
        info["recommended_channel"] = "DoH Şifreli DNS"
        info["recommendation_text"] = f"İSS: {info['isp']} -- DoH veya DPI Bypass kanalı önerilir."

    return info


# ─── GOODBYEDPI INSTALLER ─────────────────────────────────────────────────────────

def ensure_goodbyedpi_installed() -> Tuple[bool, str]:
    """Ensure goodbyedpi.exe and WinDivert binaries exist in BIN_DIR."""
    if os.path.exists(GOODBYEDPI_EXE):
        return True, "GoodbyeDPI hazır."

    # Check if bundled in assets/goodbyedpi/
    _base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    assets_gb = os.path.join(_base, "assets", "goodbyedpi")
    if os.path.exists(os.path.join(assets_gb, "goodbyedpi.exe")):
        try:
            for item in os.listdir(assets_gb):
                s = os.path.join(assets_gb, item)
                d = os.path.join(BIN_DIR, item)
                if os.path.isfile(s):
                    shutil.copy2(s, d)
            return True, "GoodbyeDPI yerel paketten kopyalandı."
        except Exception as e:
            logger.warning("Local copy failed: %s", e)

    # Download from GitHub release
    try:
        zip_path = os.path.join(BIN_DIR, "gbdpi.zip")
        req = urllib.request.Request(GOODBYEDPI_ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=12) as response, open(zip_path, "wb") as out_file:
            shutil.copyfileobj(response, out_file)

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(BIN_DIR)

        os.remove(zip_path)

        # Move files from x86_64 subfolder if present
        for root, dirs, files in os.walk(BIN_DIR):
            if "goodbyedpi.exe" in files:
                for f in files:
                    src = os.path.join(root, f)
                    dst = os.path.join(BIN_DIR, f)
                    if src != dst:
                        shutil.copy2(src, dst)
                break

        if os.path.exists(GOODBYEDPI_EXE):
            return True, "GoodbyeDPI indirme ve kurulumu tamamlandı [OK]"
        return False, "GoodbyeDPI indirildi ancak çalıştırılabilir dosya bulunamadı."
    except Exception as e:
        return False, f"GoodbyeDPI indirilemedi: {e}"


# ─── DPI BYPASS ENGINE ────────────────────────────────────────────────────────────

def start_dpi_bypass(mode: str = "superonline") -> Tuple[bool, str]:
    """
    Start GoodbyeDPI process silently with ISP-specific parameters.
    Modes: "superonline", "ttnet", "vodafone", "general"
    """
    global _dpi_process

    stop_dpi_bypass()  # Ensure previous process is terminated

    ok, msg = ensure_goodbyedpi_installed()
    if not ok:
        return False, msg

    # Select parameters based on target ISP mode
    if mode == "superonline":
        # Superonline Fiber: -9 (aggressive fragment), --set-ttl 3, Cloudflare DNS
        cmd_args = [
            GOODBYEDPI_EXE,
            "-9",
            "--set-ttl", "3",
            "--dns-addr", "1.1.1.1",
            "--dns-port", "53",
            "--dnsv6-addr", "2606:4700:4700::1111",
            "--dnsv6-port", "53",
        ]
        label = "Superonline DPI Bypass (Mod -9 + TTL 3)"
    elif mode == "ttnet":
        # Türk Telekom: -5 (HTTP/HTTPS split), --set-ttl 3
        cmd_args = [
            GOODBYEDPI_EXE,
            "-5",
            "--set-ttl", "3",
            "--dns-addr", "1.1.1.1",
            "--dns-port", "53",
        ]
        label = "Türk Telekom DPI Bypass (Mod -5)"
    else:
        # General / Vodafone: -7
        cmd_args = [
            GOODBYEDPI_EXE,
            "-7",
            "--dns-addr", "1.1.1.1",
            "--dns-port", "53",
        ]
        label = "Genel DPI Bypass (Mod -7)"

    try:
        _dpi_process = subprocess.Popen(
            cmd_args,
            cwd=BIN_DIR,
            creationflags=CREATE_NO_WINDOW
        )
        return True, f"⚡ {label} Başlatıldı! (PID: {_dpi_process.pid})"
    except Exception as e:
        return False, f"DPI Bypass başlatılamadı: {e}"


def stop_dpi_bypass() -> Tuple[bool, str]:
    """Stop the running GoodbyeDPI process and clean up WinDivert service."""
    global _dpi_process

    stopped = False

    if _dpi_process:
        try:
            _dpi_process.terminate()
            _dpi_process.wait(timeout=3)
            stopped = True
        except Exception:
            try:
                _dpi_process.kill()
                stopped = True
            except Exception:
                pass
        _dpi_process = None

    # Kill any dangling goodbyedpi processes & clean WinDivert driver
    try:
        subprocess.run(["taskkill", "/F", "/IM", "goodbyedpi.exe"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["sc", "stop", "WinDivert"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["sc", "delete", "WinDivert"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["sc", "stop", "WinDivert14"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["sc", "delete", "WinDivert14"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        stopped = True
    except Exception:
        pass

    return True, "DPI Bypass Servisi Durduruldu ve Temizlendi [OK]"


def is_dpi_bypass_running() -> bool:
    """Return True if GoodbyeDPI is currently running."""
    global _dpi_process
    if _dpi_process and _dpi_process.poll() is None:
        return True

    # Check process list via tasklist
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq goodbyedpi.exe"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        return "goodbyedpi.exe" in out.stdout.lower()
    except Exception:
        return False
