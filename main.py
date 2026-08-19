"""
Discord DNS v3.6 — Entry Point
Auto-elevates to Administrator via UAC if required, then launches the GUI.
"""

import sys
import admin_utils
import gui


def main():
    # Ensure Administrator privileges (required for netsh / Set-DnsClientServerAddress)
    if not admin_utils.is_admin():
        admin_utils.run_as_admin()
        # run_as_admin re-launches the process with UAC and calls sys.exit(0)
        # so code below only runs in the elevated instance.

    gui.main()


if __name__ == "__main__":
    main()
