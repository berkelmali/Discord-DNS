"""
Discord DNS v3.0 — Heartbeat Guard (Smart Failover)
Background daemon thread that monitors Discord connectivity every N seconds.
If consecutive failures exceed the threshold, it triggers an automatic DNS failover
to the next available preset without interrupting an active Discord voice session.
"""

import threading
import time
import logging
from typing import Callable, Optional

import discord_checker
import dns_manager

logger = logging.getLogger("HeartbeatGuard")

# ─── Configuration ────────────────────────────────────────────────────────────────

# Seconds between heartbeat checks (20–30 s recommended)
HEARTBEAT_INTERVAL_S: int = 25

# How many consecutive failures before triggering failover
FAILURE_THRESHOLD: int = 2

# Failover chain: if current preset fails, try the next one in order
FAILOVER_CHAIN: list[str] = ["Cloudflare", "Google", "Quad9"]


# ─── HeartbeatGuard Class ─────────────────────────────────────────────────────────

class HeartbeatGuard:
    """
    Monitors Discord connectivity in the background and performs automatic
    DNS failover when the current preset becomes unreliable.

    Usage:
        guard = HeartbeatGuard(adapter_name="Wi-Fi", on_status_change=my_callback)
        guard.start()
        ...
        guard.stop()

    Callback signature:
        on_status_change(event: str, data: dict) -> None

        Events:
          "heartbeat"  — periodic status update  {ok, ping_ms, consecutive_failures}
          "failover"   — DNS switched             {from_preset, to_preset, reason}
          "all_failed" — all presets exhausted    {message}
    """

    def __init__(
        self,
        adapter_name: str = "Wi-Fi",
        on_status_change: Optional[Callable[[str, dict], None]] = None,
        interval: int = HEARTBEAT_INTERVAL_S,
        failure_threshold: int = FAILURE_THRESHOLD,
    ):
        self.adapter_name      = adapter_name
        self.on_status_change  = on_status_change or (lambda e, d: None)
        self.interval          = interval
        self.failure_threshold = failure_threshold

        self._stop_event       = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.consecutive_failures = 0
        self.current_preset_index = 0   # index into FAILOVER_CHAIN
        self.is_running           = False
        self.is_dns_active        = False

    # ── Public API ────────────────────────────────────────────────────────────────

    def start(self):
        """Start the background heartbeat thread."""
        if self.is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="HeartbeatGuard",
            daemon=True
        )
        self._thread.start()
        self.is_running = True
        logger.info("HeartbeatGuard started (interval=%ds, threshold=%d)", self.interval, self.failure_threshold)

    def stop(self):
        """Signal the heartbeat thread to stop."""
        self._stop_event.set()
        self.is_running = False
        logger.info("HeartbeatGuard stopped.")

    def sync_preset(self, preset_name: str):
        """Notify the guard about a manually selected DNS preset so failover chain stays in sync."""
        if preset_name in FAILOVER_CHAIN:
            self.current_preset_index = FAILOVER_CHAIN.index(preset_name)
            self.consecutive_failures = 0

    def get_status(self) -> dict:
        """Return current guard state snapshot."""
        return {
            "is_running":           self.is_running,
            "adapter_name":         self.adapter_name,
            "consecutive_failures": self.consecutive_failures,
            "current_preset":       FAILOVER_CHAIN[self.current_preset_index],
            "interval":             self.interval,
        }

    # ── Internal Loop ─────────────────────────────────────────────────────────────

    def _run_loop(self):
        """Main heartbeat loop — runs every self.interval seconds."""
        while not self._stop_event.is_set():
            self._tick()
            # Interruptible sleep: wakes up immediately if stop() is called
            self._stop_event.wait(timeout=self.interval)

    def _tick(self):
        """Single heartbeat tick: ping Discord and decide whether to failover."""
        result = discord_checker.heartbeat_ping()

        if result["ok"]:
            self.consecutive_failures = 0
            self.on_status_change("heartbeat", {
                "ok":                  True,
                "ping_ms":             result["ping_ms"],
                "consecutive_failures": 0,
                "preset":              FAILOVER_CHAIN[self.current_preset_index],
            })
            logger.debug("Heartbeat OK — %d ms", result["ping_ms"])

        else:
            self.consecutive_failures += 1
            self.on_status_change("heartbeat", {
                "ok":                  False,
                "ping_ms":             -1,
                "consecutive_failures": self.consecutive_failures,
                "preset":              FAILOVER_CHAIN[self.current_preset_index],
            })
            logger.warning("Heartbeat FAIL #%d", self.consecutive_failures)

            if self.consecutive_failures >= self.failure_threshold:
                self._attempt_failover()

    def _attempt_failover(self):
        """Try switching to the next DNS preset in the failover chain."""
        if not self.is_dns_active:
            logger.info("Heartbeat failover skipped because DNS protection is inactive.")
            return

        from_preset = FAILOVER_CHAIN[self.current_preset_index]
        next_index  = (self.current_preset_index + 1) % len(FAILOVER_CHAIN)

        # Avoid looping back to the same preset if all have been tried
        if next_index == 0 and self.current_preset_index == len(FAILOVER_CHAIN) - 1:
            self.on_status_change("all_failed", {
                "message": "Tüm DNS profilleri denendi, Discord hâlâ erişilemiyor. İSS engeli olabilir."
            })
            logger.error("All DNS presets exhausted — ISP block suspected.")
            self.consecutive_failures = 0
            return

        to_preset = FAILOVER_CHAIN[next_index]
        logger.info("Failover: %s → %s (adapter: %s)", from_preset, to_preset, self.adapter_name)

        success, log_msg = dns_manager.set_preset_dns(self.adapter_name, to_preset)

        self.current_preset_index = next_index
        self.consecutive_failures = 0

        self.on_status_change("failover", {
            "from_preset": from_preset,
            "to_preset":   to_preset,
            "success":     success,
            "reason":      f"{self.failure_threshold} ardışık başarısız bağlantı sonrası otomatik geçiş.",
            "log":         log_msg,
        })


# ─── Convenience Factory ──────────────────────────────────────────────────────────

def create_guard(
    adapter_name: str,
    on_status_change: Optional[Callable[[str, dict], None]] = None,
) -> HeartbeatGuard:
    """Create and return a HeartbeatGuard (not yet started)."""
    return HeartbeatGuard(
        adapter_name=adapter_name,
        on_status_change=on_status_change,
    )
