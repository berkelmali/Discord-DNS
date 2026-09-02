"""
Discord DNS v3.6 — Entry Point
Auto-elevates to Administrator via UAC if required, then launches the GUI.
"""

import admin_utils
import gui


def main():
    # Elevation first: run_as_admin() ends this process when it starts an
    # elevated copy, so only the instance that will really run the interface
    # reaches the lock below. Claiming it earlier would leave the elevated copy
    # locked out by the process that just spawned it.
    if not admin_utils.is_admin():
        admin_utils.run_as_admin()
        # Reaching here means elevation was declined; carry on unelevated so the
        # user still gets a window explaining what is missing.

    # One copy at a time. With start-at-logon available a second copy is easy to
    # end up with, and two of them would bind the same resolver port, divert the
    # same packets twice, and overwrite each other's DNS settings.
    if not admin_utils.claim_single_instance():
        admin_utils.focus_existing_instance()
        return

    gui.main()


if __name__ == "__main__":
    main()
