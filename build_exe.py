"""
Discord DNS v3.0 — PyInstaller Build Script
Produces a single-file, windowless, UAC-elevated Windows executable.
Run: python build_exe.py
"""

import PyInstaller.__main__
import os
import sys

ICON_PATH = r".\assets\app_icon.ico"
EXE_NAME = "Discord_DNS_v3"
DIST_DIR = "./dist"
BUILD_DIR = "./build"


def build():
    print("=" * 55)
    print("  Discord DNS v3.0 -- PyInstaller Derleme Baslatiliyor")
    print("=" * 55)

    # Clean up old exes and spec files to keep a single application
    for f in os.listdir(DIST_DIR) if os.path.exists(DIST_DIR) else []:
        if f.endswith(".exe"):
            try:
                os.remove(os.path.join(DIST_DIR, f))
                print(f"Eski sürüm silindi: {f}")
            except Exception as e:
                print(f"Silinemedi: {f} ({e})")

    for f in os.listdir("."):
        if f.endswith(".spec") and f != f"{EXE_NAME}.spec":
            try:
                os.remove(f)
                print(f"Eski spec silindi: {f}")
            except Exception:
                pass

    exe_name = EXE_NAME

    args = [
        "main.py",
        f"--name={exe_name}",
        "--onefile",
        "--windowed",          # No console window
        "--uac-admin",         # Triggers UAC elevation dialog on launch
        "--clean",
        f"--distpath={DIST_DIR}",
        f"--workpath={BUILD_DIR}",
        "--specpath=.",
        f"--icon={ICON_PATH}",  # App icon
        "--add-data=assets;assets",  # Bundle assets folder
        # Hidden imports for pystray / PIL dynamic imports
        "--hidden-import=pystray",
        "--hidden-import=pystray._win32",
        "--hidden-import=PIL._tkinter_finder",
        "--hidden-import=PIL.ImageDraw",
        "--hidden-import=dns_benchmark",
        "--hidden-import=dpi_bypass",
    ]

    PyInstaller.__main__.run(args)

    final = os.path.abspath(f"{DIST_DIR}/{exe_name}.exe")
    print("\n" + "=" * 55)
    print("  Derleme Tamamlandi!")
    print(f"  Cikti: {final}")
    print("=" * 55)


if __name__ == "__main__":
    build()
