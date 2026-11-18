"""
Discord DNS v3.7 — Update Checker
Asks GitHub whether a newer release has been published. It never downloads or
runs anything: when an update exists the interface only offers to open the
release page, and the user installs it themselves.

The request carries nothing about the user — a generic User-Agent and the
public releases endpoint of the project repository.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass

import version

logger = logging.getLogger("Updater")

API_URL = f"https://api.github.com/repos/{version.REPO_SLUG}/releases/latest"
TIMEOUT_S = 6.0


@dataclass
class UpdateInfo:
    available: bool
    latest: str = ""
    url: str = version.RELEASES_URL
    notes: str = ""
    error: str = ""

    @property
    def message(self) -> str:
        if self.error:
            return f"Güncelleme denetlenemedi: {self.error}"
        if self.available:
            return (f"⬆ Yeni sürüm var: {self.latest} (kullandığınız: v{version.APP_VERSION}). "
                    "İndirmek için başlıktaki güncelleme düğmesine basın.")
        return f"Uygulama güncel (v{version.APP_VERSION})."


def is_newer(remote_tag: str, local: str = version.APP_VERSION) -> bool:
    """True only when the remote tag is strictly ahead of the running version."""
    remote = version.parse_version(remote_tag)
    if not any(remote):
        return False
    return remote > version.parse_version(local)


def interpret(payload: dict) -> UpdateInfo:
    """Turn the releases/latest JSON into an UpdateInfo."""
    if not isinstance(payload, dict):
        return UpdateInfo(False, error="beklenmeyen yanıt")
    if payload.get("draft") or payload.get("prerelease"):
        return UpdateInfo(False)
    tag = payload.get("tag_name") or ""
    url = payload.get("html_url") or version.RELEASES_URL
    # Only ever point at the project's own release pages
    if not str(url).startswith(version.REPO_URL + "/"):
        url = version.RELEASES_URL
    notes = (payload.get("body") or "").strip()
    return UpdateInfo(is_newer(tag), latest=tag, url=url, notes=notes[:600])


def check_for_update(timeout: float = TIMEOUT_S) -> UpdateInfo:
    request = urllib.request.Request(API_URL, headers={
        "User-Agent": "DiscordDNS-UpdateCheck",
        "Accept": "application/vnd.github+json",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:          # no published release yet
            return UpdateInfo(False)
        return UpdateInfo(False, error=f"HTTP {e.code}")
    except Exception as e:
        return UpdateInfo(False, error=type(e).__name__)
    return interpret(payload)
