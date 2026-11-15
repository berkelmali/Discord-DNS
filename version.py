"""
Discord DNS — single source of truth for the version.

The version used to be typed by hand into the window title, the tray, the
guide, the diagnostics header and the single-instance lookup. Bumping it meant
finding every copy, and the window lookup silently broke when one was missed.
Everything now reads it from here.
"""

APP_NAME = "Discord DNS"
APP_VERSION = "3.7.0"
APP_TITLE = f"{APP_NAME} v{APP_VERSION.rsplit('.', 1)[0]}"   # "Discord DNS v3.7"

# Public repository the update checker and the guide point at
REPO_SLUG = "berkelmali/Discord-DNS"
REPO_URL = f"https://github.com/{REPO_SLUG}"
RELEASES_URL = f"{REPO_URL}/releases"


def parse_version(text: str) -> tuple:
    """'v3.7.0' / '3.7' / 'v3.10.1-beta' → comparable tuple (3, 7, 0)."""
    core = text.strip().lstrip("vV").split("-", 1)[0].split("+", 1)[0]
    parts = []
    for piece in core.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])
