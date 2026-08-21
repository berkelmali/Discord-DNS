"""
Discord DNS v3.6 — DPI Bypass Facade & ISP Auto-Detector

The bypass itself is now ours: dpi_engine.py drives WinDivert directly, so no
external goodbyedpi.exe process is downloaded or launched in the normal path.
The legacy GoodbyeDPI launcher is kept only as an opt-in fallback for machines
where our engine cannot open the driver.

Public API (unchanged for gui.py):
    detect_isp() -> dict
    start_dpi_bypass(mode) -> (ok, message)
    stop_dpi_bypass() -> (ok, message)
    is_dpi_bypass_running() -> bool
"""

import os
import re
import sys
import json
import time
import subprocess
import urllib.request
import zipfile
import shutil
import logging
from typing import Optional, Tuple, Dict, Any

import dpi_engine

logger = logging.getLogger("DPIBypass")

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

ENGINE_NATIVE = "native"
ENGINE_GOODBYEDPI = "goodbyedpi"

# ─── APPDATA STORAGE ──────────────────────────────────────────────────────────────

def _get_bin_dir() -> str:
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    bin_dir = os.path.join(appdata, "DiscordDNS", "bin")
    os.makedirs(bin_dir, exist_ok=True)
    return bin_dir

BIN_DIR = _get_bin_dir()
GOODBYEDPI_EXE = os.path.join(BIN_DIR, "goodbyedpi.exe")

# GoodbyeDPI download source (fallback engine only)
GOODBYEDPI_ZIP_URL = "https://github.com/ValdikSS/GoodbyeDPI/releases/download/0.2.2/goodbyedpi-0.2.2.zip"

# State of whichever engine is currently active
_dpi_process: Optional[subprocess.Popen] = None
_active_engine: Optional[str] = None


# ─── ISP AUTO DETECTION ───────────────────────────────────────────────────────────

# Word-boundary patterns: plain substrings used to misfire (e.g. "sol" matched
# any "…Solutions" ISP and mislabelled it as Superonline).
_ISP_PATTERNS = (
    ("turknet",     r"\bturk\s*net\b|\bturknet\b"),
    ("superonline", r"\bsuperonline\b|\bturkcell\b"),
    # Türk Telekom trades under several names, and its mobile arm shows up as
    # "Avea" or "TT Mobil" in WHOIS/AS records. Missing those meant a TT mobile
    # line fell through to the weakest generic profile.
    ("ttnet",       r"\bt(?:ü|u)rk\s*telekom\b|\bttnet\b|\btt-?net\b|"
                    r"\bavea\b|\btt\s*mobil\b|\bas9121\b|\bas20978\b"),
    ("vodafone",    r"\bvodafone\b"),
    ("kablonet",    r"\bkablonet\b|\bkablo\s*net\b|\bturksat\b"),
    ("millenicom",  r"\bmillenicom\b"),
)

_ISP_PROFILES: Dict[str, Dict[str, str]] = {
    "turknet": {
        # TurkNet does not appear to do SNI-level blocking, but its resolver does
        # answer blocked domains with the national block server instead of the
        # real address (verifiable with: nslookup discord.com <ISS DNS>).
        # Encrypted DNS — not a DPI strategy — is what fixes that.
        "channel": "DoH Şifreli DNS",
        "text": "TurkNet -- DNS yönlendirmesi var (discord.com engel sunucusuna gidiyor). Şifreli DoH ÖNERİLİR!",
        "mode": "general",
    },
    "superonline": {
        "channel": "Superonline DPI Bypass",
        "text": "Superonline/Turkcell -- Ağır DPI & SNI engeli var. DPI Bypass Kanalı ÖNERİLİR!",
        "mode": "superonline",
    },
    "ttnet": {
        "channel": "Türk Telekom DPI Bypass",
        "text": "Türk Telekom / Avea -- DNS yönlendirmesi + SNI RST enjeksiyonu var. DoH + DPI Bypass ŞART!",
        "mode": "ttnet",
    },
    "vodafone": {
        "channel": "DoH Şifreli DNS",
        "text": "Vodafone -- DNS Hijacking var. DoH Şifreli DNS ÖNERİLİR!",
        "mode": "vodafone",
    },
    "kablonet": {
        "channel": "DoH Şifreli DNS",
        "text": "KabloNet/Türksat -- DNS müdahalesi var. DoH Şifreli DNS önerilir.",
        "mode": "vodafone",
    },
    "millenicom": {
        "channel": "Standart DNS",
        "text": "Millenicom -- Genelde engelsiz. Standart DNS yeterlidir.",
        "mode": "general",
    },
}


def detect_isp() -> Dict[str, Any]:
    """
    Detect the user's active Internet Service Provider (ISP).
    Returns dict with ISP name, organization, and recommended bypass mode.
    """
    info: Dict[str, Any] = {
        "isp": "Bilinmiyor",
        "org": "",
        "as": "",
        "ip": "",
        "is_turknet": False,
        "is_superonline": False,
        "is_ttnet": False,
        "is_vodafone": False,
        "is_kablonet": False,
        "bypass_mode": "general",
        "recommended_channel": "DoH Şifreli DNS",
        "recommendation_text": "İSS tespit edilemedi. DoH veya DPI Bypass kanalı önerilir.",
    }

    for url, mapping in (
        ("http://ip-api.com/json", {"isp": "isp", "org": "org", "as": "as", "ip": "query"}),
        ("https://ipinfo.io/json", {"isp": "org", "org": "org", "ip": "ip"}),
    ):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=4) as res:
                data = json.loads(res.read().decode("utf-8"))
            for key, source in mapping.items():
                info[key] = data.get(source, info.get(key, ""))
            if info["isp"]:
                break
        except Exception:
            continue

    full_str = f"{info['isp']} {info['org']} {info['as']}".lower()

    matched = None
    for key, pattern in _ISP_PATTERNS:
        if re.search(pattern, full_str):
            matched = key
            break

    if matched:
        info[f"is_{matched}"] = True
        profile = _ISP_PROFILES[matched]
        info["recommended_channel"] = profile["channel"]
        info["recommendation_text"] = profile["text"]
        info["bypass_mode"] = profile["mode"]
    else:
        info["recommendation_text"] = f"İSS: {info['isp']} -- DoH veya DPI Bypass kanalı önerilir."

    return info


def resolve_mode(isp_info: Optional[Dict[str, Any]]) -> str:
    """Pick the dpi_engine preset that fits a detect_isp() result."""
    if not isp_info:
        return "general"
    mode = isp_info.get("bypass_mode")
    if mode in dpi_engine.PRESETS:
        return mode
    if isp_info.get("is_superonline"):
        return "superonline"
    if isp_info.get("is_ttnet"):
        return "ttnet"
    if isp_info.get("is_vodafone") or isp_info.get("is_kablonet"):
        return "vodafone"
    return "general"


# ─── LEGACY GOODBYEDPI INSTALLER (fallback engine) ───────────────────────────────

def _preferred_arch_dirs() -> Tuple[str, ...]:
    return ("x86_64", "amd64", "x64") if sys.maxsize > 2 ** 32 else ("x86",)


def ensure_goodbyedpi_installed() -> Tuple[bool, str]:
    """Ensure goodbyedpi.exe and its WinDivert binaries exist in BIN_DIR."""
    if os.path.exists(GOODBYEDPI_EXE):
        return True, "GoodbyeDPI hazır."

    # Bundled copy in assets/goodbyedpi/ takes priority over any download
    _base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    assets_gb = os.path.join(_base, "assets", "goodbyedpi")
    if os.path.exists(os.path.join(assets_gb, "goodbyedpi.exe")):
        try:
            for item in os.listdir(assets_gb):
                s = os.path.join(assets_gb, item)
                if os.path.isfile(s):
                    shutil.copy2(s, os.path.join(BIN_DIR, item))
            return True, "GoodbyeDPI yerel paketten kopyalandı."
        except Exception as e:
            logger.warning("Local copy failed: %s", e)

    try:
        zip_path = os.path.join(BIN_DIR, "gbdpi.zip")
        req = urllib.request.Request(GOODBYEDPI_ZIP_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=12) as response, open(zip_path, "wb") as out_file:
            shutil.copyfileobj(response, out_file)

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(BIN_DIR)
        os.remove(zip_path)

        # Pick the folder matching *this* machine's architecture. Walking blindly
        # used to land on x86/ first and install the 32-bit build on 64-bit Windows.
        source_dir = None
        for root, dirs, files in os.walk(BIN_DIR):
            if "goodbyedpi.exe" not in files:
                continue
            if os.path.basename(root).lower() in _preferred_arch_dirs():
                source_dir = root
                break
            source_dir = source_dir or root

        if source_dir:
            for f in os.listdir(source_dir):
                src = os.path.join(source_dir, f)
                dst = os.path.join(BIN_DIR, f)
                if os.path.isfile(src) and src != dst:
                    shutil.copy2(src, dst)

        if os.path.exists(GOODBYEDPI_EXE):
            return True, "GoodbyeDPI indirme ve kurulumu tamamlandı [OK]"
        return False, "GoodbyeDPI indirildi ancak çalıştırılabilir dosya bulunamadı."
    except Exception as e:
        return False, f"GoodbyeDPI indirilemedi: {e}"


def _goodbyedpi_args(mode: str) -> Tuple[list, str]:
    if mode == "superonline":
        return ([GOODBYEDPI_EXE, "-9", "--set-ttl", "3",
                 "--dns-addr", "1.1.1.1", "--dns-port", "53",
                 "--dnsv6-addr", "2606:4700:4700::1111", "--dnsv6-port", "53"],
                "Superonline DPI Bypass (GoodbyeDPI -9 + TTL 3)")
    if mode == "ttnet":
        return ([GOODBYEDPI_EXE, "-5", "--set-ttl", "3",
                 "--dns-addr", "1.1.1.1", "--dns-port", "53"],
                "Türk Telekom DPI Bypass (GoodbyeDPI -5)")
    return ([GOODBYEDPI_EXE, "-7", "--dns-addr", "1.1.1.1", "--dns-port", "53"],
            "Genel DPI Bypass (GoodbyeDPI -7)")


def _start_goodbyedpi(mode: str) -> Tuple[bool, str]:
    """Fallback path: launch the external GoodbyeDPI process."""
    global _dpi_process, _active_engine

    ok, msg = ensure_goodbyedpi_installed()
    if not ok:
        return False, msg

    cmd_args, label = _goodbyedpi_args(mode)
    try:
        _dpi_process = subprocess.Popen(
            cmd_args, cwd=BIN_DIR, creationflags=CREATE_NO_WINDOW,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
    except Exception as e:
        return False, f"DPI Bypass başlatılamadı: {e}"

    # GoodbyeDPI exits immediately when the driver refuses to load, and the old
    # code reported success anyway. Confirm it is still alive before claiming so.
    time.sleep(1.0)
    if _dpi_process.poll() is not None:
        output = ""
        try:
            output = (_dpi_process.stdout.read() or b"").decode("utf-8", "replace").strip()
        except Exception:
            pass
        code = _dpi_process.returncode
        _dpi_process = None
        return False, f"GoodbyeDPI hemen kapandı (çıkış kodu {code}). {output[:200]}"

    _active_engine = ENGINE_GOODBYEDPI
    return True, f"⚡ {label} başlatıldı (PID: {_dpi_process.pid})"


# ─── DPI BYPASS ENGINE (public) ──────────────────────────────────────────────────

def start_dpi_bypass(mode: str = "superonline", allow_fallback: bool = True) -> Tuple[bool, str]:
    """
    Start the bypass. Uses our own WinDivert engine; only if that cannot open the
    driver does it fall back to the bundled/downloaded GoodbyeDPI process.
    Modes: "superonline", "ttnet", "vodafone", "general", "discord_only".
    """
    global _active_engine

    stop_dpi_bypass()

    ok, msg = dpi_engine.start(mode)
    if ok:
        _active_engine = ENGINE_NATIVE
        return True, msg

    logger.warning("Yerel motor başarısız: %s", msg)
    if not allow_fallback:
        return False, msg

    fb_ok, fb_msg = _start_goodbyedpi(mode)
    if fb_ok:
        return True, f"{msg}\n↪ Yedek motora geçildi: {fb_msg}"
    return False, f"{msg}\n↪ Yedek motor da başlatılamadı: {fb_msg}"


def stop_dpi_bypass() -> Tuple[bool, str]:
    """Stop whichever engine is active and release the WinDivert driver."""
    global _dpi_process, _active_engine

    messages = []

    if dpi_engine.is_running():
        _, msg = dpi_engine.stop()
        messages.append(msg)
    else:
        dpi_engine.stop()

    used_goodbyedpi = _active_engine == ENGINE_GOODBYEDPI or _dpi_process is not None

    if _dpi_process is not None:
        try:
            _dpi_process.terminate()
            _dpi_process.wait(timeout=3)
        except Exception:
            try:
                _dpi_process.kill()
            except Exception:
                pass
        _dpi_process = None

    if used_goodbyedpi or _goodbyedpi_process_alive():
        try:
            subprocess.run(["taskkill", "/F", "/IM", "goodbyedpi.exe"],
                           capture_output=True, creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass
        # Only the legacy 1.4 driver GoodbyeDPI installs is torn down here. The
        # 2.2 driver our engine uses unloads itself when the last handle closes,
        # and force-deleting the shared service would break other running tools.
        for service in ("WinDivert1.4", "WinDivert14"):
            try:
                subprocess.run(["sc", "stop", service], capture_output=True,
                               creationflags=CREATE_NO_WINDOW)
                subprocess.run(["sc", "delete", service], capture_output=True,
                               creationflags=CREATE_NO_WINDOW)
            except Exception:
                pass
        messages.append("GoodbyeDPI süreci ve eski WinDivert sürücüsü temizlendi.")

    _active_engine = None
    return True, "\n".join(messages) or "DPI Bypass servisi kapalı [OK]"


def _goodbyedpi_process_alive() -> bool:
    try:
        out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq goodbyedpi.exe"],
                             capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        return "goodbyedpi.exe" in (out.stdout or "").lower()
    except Exception:
        return False


def is_dpi_bypass_running() -> bool:
    """True when either the native engine or the fallback process is active."""
    if dpi_engine.is_running():
        return True
    if _dpi_process is not None and _dpi_process.poll() is None:
        return True
    return _goodbyedpi_process_alive()


def active_engine() -> Optional[str]:
    """Which engine is currently carrying traffic: "native", "goodbyedpi" or None."""
    if dpi_engine.is_running():
        return ENGINE_NATIVE
    if is_dpi_bypass_running():
        return ENGINE_GOODBYEDPI
    return None


def engine_stats() -> dict:
    """Live counters from the native engine (empty dict for the fallback)."""
    return dpi_engine.stats() if dpi_engine.is_running() else {}


def self_test() -> Tuple[bool, str]:
    """Check whether the native engine can open the WinDivert driver here."""
    return dpi_engine.self_test()
