import ctypes
import os
import sys
import time

def is_admin():
    """Check if the application is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

_INSTANCE_MUTEX = None
_MUTEX_NAME = "Global\\DiscordDNS_SingleInstance"


def claim_single_instance(wait_seconds: float = 3.0) -> bool:
    """
    Take the app's single-instance lock. False means a copy is already running.

    This matters more now that the app can start itself at logon: a second copy
    would open a second resolver on the same port, divert the same packets
    twice, and fight the first one over the adapter's DNS settings. The mutex is
    released by Windows when the process ends, including a crash, so a stale
    lock cannot lock the user out.
    """
    global _INSTANCE_MUTEX
    if sys.platform != "win32":
        return True

    ERROR_ALREADY_EXISTS = 183
    deadline = time.time() + wait_seconds
    while True:
        try:
            handle = ctypes.windll.kernel32.CreateMutexW(None, False, _MUTEX_NAME)
            if not handle:
                return True                  # cannot tell — do not block startup
            if ctypes.windll.kernel32.GetLastError() != ERROR_ALREADY_EXISTS:
                _INSTANCE_MUTEX = handle
                return True
            ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            return True

        # A handover — an unelevated copy launching an elevated one — leaves the
        # lock held for a moment by the process on its way out. Waiting briefly
        # tells that apart from a copy that is genuinely already running.
        if time.time() >= deadline:
            return False
        time.sleep(0.25)


def release_single_instance() -> None:
    """Give up the lock so a replacement copy can take it immediately."""
    global _INSTANCE_MUTEX
    if _INSTANCE_MUTEX:
        try:
            ctypes.windll.kernel32.ReleaseMutex(_INSTANCE_MUTEX)
            ctypes.windll.kernel32.CloseHandle(_INSTANCE_MUTEX)
        except Exception:
            pass
        _INSTANCE_MUTEX = None


def focus_existing_instance() -> bool:
    """Bring the already-running window to the front, if it can be found."""
    try:
        hwnd = ctypes.windll.user32.FindWindowW(None, "Discord DNS v3.6")
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 9)      # SW_RESTORE
            ctypes.windll.user32.SetForegroundWindow(hwnd)
            return True
    except Exception:
        pass
    return False


def relaunch_as_admin():
    """
    Start an elevated copy of the app and report whether it was launched.

    This deliberately does not end the current process. Exiting is the caller's
    job, because how to leave differs by context: before the interface exists a
    plain exit is right, while a running window has to tear itself down first —
    and inside a Tk callback sys.exit does not end the process at all, it raises
    SystemExit that Tk swallows, which is what left the old unelevated window
    sitting behind the elevated one.
    """
    if is_admin():
        return True

    if getattr(sys, 'frozen', False):
        executable = sys.executable
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    else:
        executable = sys.executable
        script = os.path.abspath(sys.argv[0])
        params = f'"{script}" ' + " ".join([f'"{arg}"' for arg in sys.argv[1:]])

    try:
        # 1 = SW_SHOWNORMAL, 'runas' triggers the UAC prompt
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, None, 1
        )
        return int(ret) > 32
    except Exception as e:
        print(f"Elevation error: {e}")
        return False


def run_as_admin():
    """Re-launch elevated and end this process. For use before the UI exists."""
    if is_admin():
        return True
    if relaunch_as_admin():
        sys.exit(0)
    return False
