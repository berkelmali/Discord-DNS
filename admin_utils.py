import ctypes
import sys
import os

def is_admin():
    """Check if the application is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_as_admin():
    """Re-launch the application with Administrator privileges via UAC prompt."""
    if is_admin():
        return True

    # Re-launch script or exe as Administrator
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        executable = sys.executable
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    else:
        # Running as python script
        executable = sys.executable
        script = os.path.abspath(sys.argv[0])
        params = f'"{script}" ' + " ".join([f'"{arg}"' for arg in sys.argv[1:]])

    try:
        # 1 = SW_SHOWNORMAL, 'runas' triggers UAC prompt
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, None, 1
        )
        if int(ret) > 32:
            sys.exit(0) # Exit the non-admin process if elevation succeeded
        else:
            return False
    except Exception as e:
        print(f"Elevation error: {e}")
        return False
