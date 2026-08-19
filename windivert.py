"""
Discord DNS v3.6 — WinDivert 2.2 ctypes Binding
Minimal, dependency-free binding to the WinDivert user-mode API used by the
native DPI bypass engine. This replaces the external goodbyedpi.exe dependency:
all packet logic lives in dpi_engine.py, this module only talks to the driver.

Only the calls the engine needs are bound (Open / Recv / Send / Shutdown /
Close / SetParam / CalcChecksums / CompileFilter).
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import logging
import os
import platform
import shutil
import sys
from typing import Optional, Tuple

logger = logging.getLogger("WinDivert")

# ─── Constants ───────────────────────────────────────────────────────────────────

LAYER_NETWORK = 0
LAYER_NETWORK_FORWARD = 1

FLAG_SNIFF = 0x0001
FLAG_DROP = 0x0002
FLAG_RECV_ONLY = 0x0004
FLAG_SEND_ONLY = 0x0008
FLAG_NO_INSTALL = 0x0010
FLAG_FRAGMENTS = 0x0020

PARAM_QUEUE_LENGTH = 0
PARAM_QUEUE_TIME = 1
PARAM_QUEUE_SIZE = 2
PARAM_VERSION_MAJOR = 3
PARAM_VERSION_MINOR = 4

SHUTDOWN_RECV = 0x1
SHUTDOWN_SEND = 0x2
SHUTDOWN_BOTH = 0x3

MTU_MAX = 40 + 0xFFFF

# Windows error codes worth reporting with a human explanation
ERROR_ACCESS_DENIED = 5
ERROR_FILE_NOT_FOUND = 2
ERROR_INVALID_PARAMETER = 87
ERROR_INVALID_IMAGE_HASH = 577
ERROR_DRIVER_BLOCKED = 1275

_ERROR_HINTS = {
    ERROR_ACCESS_DENIED: "Yönetici yetkisi gerekli (uygulamayı 'Yönetici olarak çalıştır').",
    ERROR_FILE_NOT_FOUND: "WinDivert sürücü dosyası (.sys) bulunamadı.",
    ERROR_INVALID_PARAMETER: "Geçersiz filtre ifadesi veya sürücü sürüm uyuşmazlığı.",
    ERROR_INVALID_IMAGE_HASH: "Sürücü imzası Windows tarafından reddedildi (Secure Boot / imza politikası).",
    ERROR_DRIVER_BLOCKED: "Eski/başka bir WinDivert sürücüsü yüklü. Diğer DPI araçlarını kapatın.",
}

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


# ─── WINDIVERT_ADDRESS ───────────────────────────────────────────────────────────

class WinDivertAddress(ctypes.Structure):
    """WINDIVERT_ADDRESS (80 bytes). Bitfields are exposed through properties."""

    _fields_ = [
        ("Timestamp", ctypes.c_int64),
        ("_bits", ctypes.c_uint32),
        ("Reserved2", ctypes.c_uint32),
        ("IfIdx", ctypes.c_uint32),      # union: WINDIVERT_DATA_NETWORK.IfIdx
        ("SubIfIdx", ctypes.c_uint32),   # union: WINDIVERT_DATA_NETWORK.SubIfIdx
        ("_reserved3", ctypes.c_uint8 * 56),
    ]

    def _get_bit(self, shift: int) -> bool:
        return bool((self._bits >> shift) & 1)

    def _set_bit(self, shift: int, value: bool) -> None:
        if value:
            self._bits |= (1 << shift)
        else:
            self._bits &= ~(1 << shift) & 0xFFFFFFFF

    @property
    def layer(self) -> int:
        return self._bits & 0xFF

    @property
    def event(self) -> int:
        return (self._bits >> 8) & 0xFF

    sniffed      = property(lambda s: s._get_bit(16), lambda s, v: s._set_bit(16, v))
    outbound     = property(lambda s: s._get_bit(17), lambda s, v: s._set_bit(17, v))
    loopback     = property(lambda s: s._get_bit(18), lambda s, v: s._set_bit(18, v))
    impostor     = property(lambda s: s._get_bit(19), lambda s, v: s._set_bit(19, v))
    ipv6         = property(lambda s: s._get_bit(20), lambda s, v: s._set_bit(20, v))
    ip_checksum  = property(lambda s: s._get_bit(21), lambda s, v: s._set_bit(21, v))
    tcp_checksum = property(lambda s: s._get_bit(22), lambda s, v: s._set_bit(22, v))
    udp_checksum = property(lambda s: s._get_bit(23), lambda s, v: s._set_bit(23, v))

    def copy(self) -> "WinDivertAddress":
        clone = WinDivertAddress()
        ctypes.memmove(ctypes.byref(clone), ctypes.byref(self), ctypes.sizeof(self))
        return clone


assert ctypes.sizeof(WinDivertAddress) == 80, "WINDIVERT_ADDRESS layout mismatch"


class WinDivertError(OSError):
    """WinDivert driver / API failure carrying a human-readable Turkish hint."""

    def __init__(self, message: str, code: int = 0):
        self.code = code
        hint = _ERROR_HINTS.get(code)
        if code:
            message = f"{message} (Win32 hata {code})"
        if hint:
            message = f"{message} — {hint}"
        super().__init__(message)


# ─── Driver binaries ─────────────────────────────────────────────────────────────

def _app_bin_dir() -> str:
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    path = os.path.join(appdata, "DiscordDNS", "bin", "windivert")
    os.makedirs(path, exist_ok=True)
    return path


def _asset_dir() -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    arch = "x64" if platform.machine().endswith("64") else "x86"
    return os.path.join(base, "assets", "windivert", arch)


DRIVER_DIR = _app_bin_dir()
DLL_PATH = os.path.join(DRIVER_DIR, "WinDivert.dll")


def deploy_driver_files() -> Tuple[bool, str]:
    """
    Copy the bundled WinDivert 2.2 DLL + .sys side by side into %APPDATA%.
    WinDivert loads the .sys from the DLL's own directory, so both must live in
    a real, stable folder (a PyInstaller _MEIPASS temp dir is not one).
    """
    src = _asset_dir()
    if not os.path.isdir(src):
        return False, f"WinDivert paketi bulunamadı: {src}"

    try:
        for name in os.listdir(src):
            if not name.lower().endswith((".dll", ".sys")):
                continue
            s = os.path.join(src, name)
            d = os.path.join(DRIVER_DIR, name)
            # Skip files the running driver already holds open and that match
            if os.path.exists(d) and os.path.getsize(d) == os.path.getsize(s):
                continue
            try:
                shutil.copy2(s, d)
            except PermissionError:
                logger.warning("WinDivert dosyası kullanımda, atlandı: %s", name)
        if not os.path.exists(DLL_PATH):
            return False, "WinDivert.dll kopyalanamadı."
        return True, DRIVER_DIR
    except Exception as e:
        return False, f"WinDivert dosyaları hazırlanamadı: {e}"


_dll: Optional[ctypes.WinDLL] = None


def _bind(dll: ctypes.WinDLL) -> None:
    dll.WinDivertOpen.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int16, ctypes.c_uint64]
    dll.WinDivertOpen.restype = wintypes.HANDLE

    dll.WinDivertRecv.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_uint,
                                  ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(WinDivertAddress)]
    dll.WinDivertRecv.restype = wintypes.BOOL

    dll.WinDivertSend.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_uint,
                                  ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(WinDivertAddress)]
    dll.WinDivertSend.restype = wintypes.BOOL

    dll.WinDivertShutdown.argtypes = [wintypes.HANDLE, ctypes.c_int]
    dll.WinDivertShutdown.restype = wintypes.BOOL

    dll.WinDivertClose.argtypes = [wintypes.HANDLE]
    dll.WinDivertClose.restype = wintypes.BOOL

    dll.WinDivertSetParam.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_uint64]
    dll.WinDivertSetParam.restype = wintypes.BOOL

    dll.WinDivertGetParam.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(ctypes.c_uint64)]
    dll.WinDivertGetParam.restype = wintypes.BOOL

    dll.WinDivertHelperCalcChecksums.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                                 ctypes.POINTER(WinDivertAddress), ctypes.c_uint64]
    dll.WinDivertHelperCalcChecksums.restype = wintypes.BOOL

    dll.WinDivertHelperCompileFilter.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                                                 ctypes.c_uint, ctypes.POINTER(ctypes.c_char_p),
                                                 ctypes.POINTER(ctypes.c_uint)]
    dll.WinDivertHelperCompileFilter.restype = wintypes.BOOL


def load_dll() -> ctypes.WinDLL:
    """Load (once) the bundled WinDivert.dll and bind the functions we use."""
    global _dll
    if _dll is not None:
        return _dll

    ok, info = deploy_driver_files()
    if not ok:
        raise WinDivertError(info)

    # Absolute path, so the .sys sitting next to it is the driver that loads.
    dll = ctypes.WinDLL(DLL_PATH, use_last_error=True)
    _bind(dll)
    _dll = dll
    return _dll


def check_filter(filter_str: str, layer: int = LAYER_NETWORK) -> Tuple[bool, str]:
    """Validate a filter expression before opening a handle."""
    dll = load_dll()
    err_str = ctypes.c_char_p()
    err_pos = ctypes.c_uint()
    ok = dll.WinDivertHelperCompileFilter(
        filter_str.encode("ascii"), layer, None, 0,
        ctypes.byref(err_str), ctypes.byref(err_pos)
    )
    if ok:
        return True, "OK"
    detail = err_str.value.decode("ascii", "replace") if err_str.value else "geçersiz filtre"
    return False, f"Filtre hatası @{err_pos.value}: {detail}"


# ─── Handle wrapper ──────────────────────────────────────────────────────────────

class WinDivertHandle:
    """
    Context manager around a WinDivert handle.

        with WinDivertHandle("outbound and tcp") as h:
            packet, addr = h.recv()
            h.send(packet, addr)
    """

    def __init__(self, filter_str: str, layer: int = LAYER_NETWORK,
                 priority: int = 0, flags: int = 0,
                 queue_length: int = 8192, queue_time: int = 2000):
        self.filter_str = filter_str
        self.layer = layer
        self.priority = priority
        self.flags = flags
        self.queue_length = queue_length
        self.queue_time = queue_time

        self._dll = load_dll()
        self._handle: Optional[int] = None
        self._buffer = ctypes.create_string_buffer(MTU_MAX)
        self._recv_len = ctypes.c_uint(0)
        self._addr = WinDivertAddress()

    # ── lifecycle ───────────────────────────────────────────────────────────────

    def open(self) -> "WinDivertHandle":
        valid, msg = check_filter(self.filter_str, self.layer)
        if not valid:
            raise WinDivertError(msg)

        handle = self._dll.WinDivertOpen(
            self.filter_str.encode("ascii"), self.layer, self.priority, self.flags
        )
        if not handle or handle == INVALID_HANDLE_VALUE:
            raise WinDivertError("WinDivert sürücüsü açılamadı", ctypes.get_last_error())

        self._handle = handle
        # A bigger queue means fewer ClientHello packets dropped under load
        self._dll.WinDivertSetParam(handle, PARAM_QUEUE_LENGTH, self.queue_length)
        self._dll.WinDivertSetParam(handle, PARAM_QUEUE_TIME, self.queue_time)
        return self

    def close(self) -> None:
        if self._handle is None:
            return
        try:
            self._dll.WinDivertClose(self._handle)
        finally:
            self._handle = None

    def shutdown(self, how: int = SHUTDOWN_BOTH) -> None:
        """Unblock a thread parked in recv() so it can exit cleanly."""
        if self._handle is not None:
            self._dll.WinDivertShutdown(self._handle, how)

    @property
    def is_open(self) -> bool:
        return self._handle is not None

    def __enter__(self) -> "WinDivertHandle":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    # ── I/O ─────────────────────────────────────────────────────────────────────

    def recv(self) -> Optional[Tuple[bytearray, WinDivertAddress]]:
        """
        Receive one diverted packet. Returns (packet, addr), or None once the
        handle has been shut down / the driver has no more data.
        """
        if self._handle is None:
            return None
        self._recv_len.value = 0
        ok = self._dll.WinDivertRecv(
            self._handle, self._buffer, MTU_MAX,
            ctypes.byref(self._recv_len), ctypes.byref(self._addr)
        )
        if not ok:
            code = ctypes.get_last_error()
            # 995 ABORTED, 232 NO_DATA, 6 INVALID_HANDLE → handle is shutting down
            if code in (0, 6, 232, 995):
                return None
            raise WinDivertError("Paket alınamadı", code)
        return bytearray(self._buffer.raw[:self._recv_len.value]), self._addr.copy()

    def send(self, packet: bytes | bytearray, addr: WinDivertAddress,
             recalc_checksums: bool = True) -> int:
        """(Re)inject a packet. Returns the number of bytes accepted by the driver."""
        if self._handle is None:
            return 0
        buf = ctypes.create_string_buffer(bytes(packet), len(packet))
        if recalc_checksums:
            addr.ip_checksum = False
            addr.tcp_checksum = False
            addr.udp_checksum = False
            self._dll.WinDivertHelperCalcChecksums(buf, len(packet), ctypes.byref(addr), 0)
        sent = ctypes.c_uint(0)
        ok = self._dll.WinDivertSend(self._handle, buf, len(packet),
                                     ctypes.byref(sent), ctypes.byref(addr))
        if not ok:
            # A dead route or unreachable host is normal for decoy packets
            logger.debug("WinDivertSend başarısız (%d)", ctypes.get_last_error())
            return 0
        return sent.value

    def send_precomputed(self, packet: bytes | bytearray, addr: WinDivertAddress) -> int:
        """
        Inject a packet exactly as given, telling the stack its checksums are
        already final. Used for deliberately corrupt (badsum) decoy packets so
        NIC checksum offload does not repair them.
        """
        addr.ip_checksum = True
        addr.tcp_checksum = True
        addr.udp_checksum = True
        return self.send(packet, addr, recalc_checksums=False)


def driver_version() -> Optional[str]:
    """Return the loaded driver version string, or None if it cannot be opened."""
    try:
        with WinDivertHandle("false", flags=FLAG_SNIFF | FLAG_RECV_ONLY) as h:
            major = ctypes.c_uint64(0)
            minor = ctypes.c_uint64(0)
            h._dll.WinDivertGetParam(h._handle, PARAM_VERSION_MAJOR, ctypes.byref(major))
            h._dll.WinDivertGetParam(h._handle, PARAM_VERSION_MINOR, ctypes.byref(minor))
            return f"{major.value}.{minor.value}"
    except Exception as e:
        logger.debug("driver_version failed: %s", e)
        return None
