"""
Discord DNS v3.6 — Heartbeat Guard (Smart Failover)
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
import doh_proxy

logger = logging.getLogger("HeartbeatGuard")

# ─── Configuration ────────────────────────────────────────────────────────────────

# Seconds between checks when nothing of ours is applied
HEARTBEAT_INTERVAL_S: int = 25

# Seconds between checks while protection is on. Detection used to take two
# 25-second cycles — roughly 50 seconds of broken Discord before anything
# reacted. Checking more often only while we are actually protecting keeps the
# idle cost unchanged.
ACTIVE_INTERVAL_S: int = 10

# After a failed check, confirm quickly instead of waiting a whole cycle
CONFIRM_DELAY_S: int = 2

# How many consecutive failures before triggering failover
FAILURE_THRESHOLD: int = 2

# What a check is allowed to take before it counts as a failure
PROBE_TIMEOUT_S: float = 5.0

# Failover chain: if the current preset fails, try the next one in order.
# It used to list three of the six providers, which meant the app could never
# fail over to AdGuard — the provider its own benchmark measured as the fastest
# on the line it was running on. The order is refreshed from that benchmark at
# runtime via set_chain().
FAILOVER_CHAIN: list[str] = ["Cloudflare", "Google", "Quad9",
                             "AdGuard", "OpenDNS", "ControlD"]


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
        active_interval: int = ACTIVE_INTERVAL_S,
        confirm_delay: int = CONFIRM_DELAY_S,
        probe_timeout: float = PROBE_TIMEOUT_S,
        target_host: str = "discord.com",
    ):
        self.adapter_name      = adapter_name
        self.on_status_change  = on_status_change or (lambda e, d: None)
        self.interval          = interval
        self.failure_threshold = failure_threshold
        self.active_interval   = active_interval
        self.confirm_delay     = confirm_delay
        self.probe_timeout     = probe_timeout
        self.target_host       = target_host
        self.last_diagnosis    = ""
        self.chain             = list(FAILOVER_CHAIN)

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
        if preset_name in self.chain:
            self.current_preset_index = self.chain.index(preset_name)
            self.consecutive_failures = 0

    def set_chain(self, providers: list) -> None:
        """
        Reorder the failover chain, normally from measured latency.

        Falling back to a provider that was measured to be slower than the one
        that just failed is a poor trade, so the benchmark's ranking decides the
        order rather than a hard-coded list.
        """
        current = self.chain[self.current_preset_index] if self.chain else None
        chain = [p for p in providers if p in dns_manager.DNS_PRESETS]
        if not chain:
            return
        self.chain = chain
        self.current_preset_index = chain.index(current) if current in chain else 0

    def get_status(self) -> dict:
        """Return current guard state snapshot."""
        return {
            "is_running":           self.is_running,
            "adapter_name":         self.adapter_name,
            "consecutive_failures": self.consecutive_failures,
            "current_preset":       self.chain[self.current_preset_index],
            "interval":             self.interval,
            "active_interval":      self.active_interval,
            "last_diagnosis":       self.last_diagnosis,
            "detection_budget_s":   self.active_interval + self.confirm_delay
                                    * max(0, self.failure_threshold - 1),
        }

    # ── Internal Loop ─────────────────────────────────────────────────────────────

    def _run_loop(self):
        """Main heartbeat loop — the gap between checks depends on the state."""
        while not self._stop_event.is_set():
            self._tick()
            self._stop_event.wait(timeout=self._next_delay())

    def _next_delay(self) -> float:
        """
        Check often when it matters, rarely when it does not.

        A failed check is confirmed within a couple of seconds rather than a
        whole cycle later, so a real outage is recognised in about twelve
        seconds instead of fifty.
        """
        if self.consecutive_failures:
            return self.confirm_delay
        if self.is_dns_active:
            return self.active_interval
        return self.interval

    def probe(self) -> dict:
        """
        Decide whether Discord is genuinely reachable.

        A bare TCP connect is not an answer to that question, and measurement
        showed it wrong in both directions on Turkish lines: where DNS is
        hijacked, the connect lands on the block server and reports success
        while nothing works; where the block server is unroutable, the connect
        fails and reports an outage even though the app's own encrypted path is
        fine. A full TLS handshake against an address resolved out of band tests
        what the user actually cares about.
        """
        try:
            import strategy_finder
            result = strategy_finder.probe_host(self.target_host, timeout=self.probe_timeout)
            return {
                "ok": result.ok,
                "ping_ms": int(result.ms) if result.ok else -1,
                "diagnosis": result.diagnosis,
            }
        except Exception as e:
            logger.debug("TLS sondası kullanılamadı (%s), TCP kontrolüne dönülüyor", e)
            fallback = discord_checker.heartbeat_ping()
            fallback.setdefault("diagnosis", "TCP kontrolü")
            return fallback

    def _tick(self):
        """Single heartbeat tick: check Discord and decide whether to failover."""
        result = self.probe()
        self.last_diagnosis = result.get("diagnosis", "")

        if result["ok"]:
            self.consecutive_failures = 0
            self.on_status_change("heartbeat", {
                "ok":                  True,
                "ping_ms":             result["ping_ms"],
                "consecutive_failures": 0,
                "preset":              self.chain[self.current_preset_index],
                "diagnosis":           self.last_diagnosis,
            })
            logger.debug("Heartbeat OK — %d ms", result["ping_ms"])

        else:
            self.consecutive_failures += 1
            self.on_status_change("heartbeat", {
                "ok":                  False,
                "ping_ms":             -1,
                "consecutive_failures": self.consecutive_failures,
                "preset":              self.chain[self.current_preset_index],
                "diagnosis":           self.last_diagnosis,
            })
            logger.warning("Heartbeat FAIL #%d", self.consecutive_failures)

            if self.consecutive_failures >= self.failure_threshold:
                self._attempt_failover()

    def _attempt_failover(self):
        """Try switching to the next DNS preset in the failover chain."""
        if not self.is_dns_active:
            logger.info("Heartbeat failover skipped because DNS protection is inactive.")
            return

        from_preset = self.chain[self.current_preset_index]
        next_index  = (self.current_preset_index + 1) % len(self.chain)

        # Avoid looping back to the same preset if all have been tried
        if next_index == 0 and self.current_preset_index == len(self.chain) - 1:
            self.on_status_change("all_failed", {
                "message": "Tüm DNS profilleri denendi, Discord hâlâ erişilemiyor. İSS engeli olabilir."
            })
            logger.error("All DNS presets exhausted — ISP block suspected.")
            self.consecutive_failures = 0
            return

        to_preset = self.chain[next_index]

        # When the adapter points at the local DoH resolver, switching presets
        # would replace 127.0.0.1 with a plaintext server and quietly turn the
        # encryption off. Rotate the upstream provider instead.
        if doh_proxy.is_running():
            success, log_msg = doh_proxy.rotate_upstream()
            logger.info("DoH failover: %s", log_msg)
            self.current_preset_index = next_index
            self.consecutive_failures = 0
            self.on_status_change("failover", {
                "from_preset": from_preset,
                "to_preset":   to_preset,
                "success":     success,
                "reason":      "Şifreli DNS açık — sağlayıcı değiştirildi, ağ kartına dokunulmadı.",
                "log":         log_msg,
            })
            return

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
