"""
Discord DNS v3.6 — Automatic Strategy Finder
Works out which bypass profile actually works on *this* line, by measuring
instead of guessing.

No two ISPs run the same DPI box, and a profile tuned for Superonline may do
nothing on Türk Telekom. So rather than shipping a guess, the finder walks the
aggression ladder: for each profile it starts the engine, opens real TLS
connections to the target hosts, counts what succeeded, and keeps the first
(least invasive) profile that gets everything through.

It also detects the two cases where no DPI profile can help:
  • nothing is blocked to begin with, and
  • the block is at the DNS layer (hijacked answers), which Channel 2 fixes.
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import dpi_engine
import doh_proxy

logger = logging.getLogger("StrategyFinder")

DEFAULT_TARGETS: Tuple[str, ...] = (
    "discord.com",
    "gateway.discord.gg",
    "cdn.discordapp.com",
)

PROBE_TIMEOUT_S = 6.0
SETTLE_S = 0.4          # let the engine's handle be ready before probing


# ─── Result types ────────────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    host: str
    ok: bool
    ms: float
    detail: str = ""

    @property
    def dns_hijacked(self) -> bool:
        """A wrong certificate on a reachable host means we were sent elsewhere."""
        return not self.ok and "CERTIFICATE_VERIFY_FAILED" in self.detail

    @property
    def sni_reset(self) -> bool:
        """
        The signature of an active SNI block: TCP connects, then the connection
        dies the moment the hostname goes out. The ISP forges a reset.
        """
        return not self.ok and ("ConnectionResetError" in self.detail
                                or "WinError 10054" in self.detail)

    @property
    def timed_out(self) -> bool:
        return not self.ok and ("TimeoutError" in self.detail or "timed out" in self.detail)

    @property
    def diagnosis(self) -> str:
        """Plain-language reason this probe failed, for the log and the report."""
        if self.ok:
            return "bağlandı"
        if self.sni_reset:
            return "SNI engeli — İSS bağlantıyı RST ile kesti"
        if self.dns_hijacked:
            return "DNS kaçırma — sahte sertifika sunuldu"
        if self.timed_out:
            return "zaman aşımı — paketler yutuluyor"
        if "DoH" in self.detail:
            return "şifreli DNS'e ulaşılamadı"
        return self.detail


@dataclass
class StrategyResult:
    profile: str
    label: str
    probes: List[ProbeResult] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(1 for p in self.probes if p.ok)

    @property
    def total(self) -> int:
        return len(self.probes)

    @property
    def perfect(self) -> bool:
        return self.total > 0 and self.score == self.total

    @property
    def median_ms(self) -> float:
        good = sorted(p.ms for p in self.probes if p.ok)
        return good[len(good) // 2] if good else 0.0


@dataclass
class FinderReport:
    baseline: StrategyResult
    attempts: List[StrategyResult] = field(default_factory=list)
    best: Optional[StrategyResult] = None
    bypass_needed: bool = True
    dns_hijack_suspected: bool = False
    sni_block_detected: bool = False

    @property
    def block_kind(self) -> str:
        """What kind of block this line uses, in one phrase."""
        kinds = []
        if self.dns_hijack_suspected:
            kinds.append("DNS kaçırma")
        if self.sni_block_detected:
            kinds.append("SNI engeli (RST enjeksiyonu)")
        if not kinds and self.bypass_needed:
            kinds.append("bilinmeyen engel (zaman aşımı)")
        return " + ".join(kinds) if kinds else "engel yok"

    def summary(self) -> str:
        if not self.bypass_needed:
            return ("Bu hatta engel görünmüyor — tüm hedeflere motor kapalıyken de "
                    "erişildi. DPI Bypass gerekmez.")
        if self.best is None:
            reason = f"Tespit edilen engel türü: {self.block_kind}. "
            if self.sni_block_detected:
                return (reason + "Hiçbir profil bu DPI kutusunu aşamadı — "
                        "daha agresif bir strateji ya da farklı bir bölme noktası gerekiyor.")
            if self.dns_hijack_suspected:
                return (reason + "Kanal 2 (şifreli DNS) bunu çözer, DPI profili çözmez.")
            return reason + "Hiçbir profil hedeflerin tamamını açamadı."

        extra = f" Engel türü: {self.block_kind}."
        if self.dns_hijack_suspected:
            extra += " DNS kaçırma da var — Kanal 2'yi açık tutun."
        return (f"En uygun profil: {self.best.label} "
                f"({self.best.score}/{self.best.total} hedef açıldı, "
                f"ortanca {self.best.median_ms:.0f} ms).{extra}")


# ─── Probing ─────────────────────────────────────────────────────────────────────

def probe_host(host: str, timeout: float = PROBE_TIMEOUT_S,
               resolve_over_doh: bool = True) -> ProbeResult:
    """
    A real, fully verified TLS handshake — the same thing a browser does.
    Certificate verification stays ON, because a block page answering with a
    forged certificate must count as a failure, not a success.

    The address is resolved over HTTPS rather than through the system resolver.
    That separation is the whole point of the probe: on a line whose ISP hijacks
    DNS, a system lookup returns the block server, every probe times out, and the
    scan concludes "no profile works" even when the engine is doing its job
    perfectly. Resolving out of band puts the probe on the real server, so what
    it measures is the DPI layer alone.
    """
    started = time.time()
    target = host

    if resolve_over_doh:
        try:
            addresses = doh_proxy.resolve_a(host, timeout)
            if addresses:
                target = addresses[0]
        except Exception as e:
            return ProbeResult(host, False, (time.time() - started) * 1000,
                               f"DoH çözümlemesi başarısız: {e}"[:120])

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((target, 443), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                version = tls.version() or "TLS"
        return ProbeResult(host, True, (time.time() - started) * 1000, version)
    except Exception as e:
        return ProbeResult(host, False, (time.time() - started) * 1000,
                           f"{type(e).__name__}: {e}"[:120])


def _run_probes(hosts: Sequence[str]) -> List[ProbeResult]:
    return [probe_host(host) for host in hosts]


# ─── The finder ──────────────────────────────────────────────────────────────────

def find_best_strategy(
    targets: Sequence[str] = DEFAULT_TARGETS,
    ladder: Sequence[str] = dpi_engine.AGGRESSION_LADDER,
    on_progress: Optional[Callable[[str], None]] = None,
    stop_when_perfect: bool = True,
) -> FinderReport:
    """
    Measure which profile works here. Requires Administrator rights, since it
    starts and stops the real engine between rounds.

    `on_progress` receives short Turkish status lines suitable for the GUI log.
    """
    say = on_progress or (lambda text: None)
    engine = dpi_engine.get_engine()
    was_running = engine.is_running
    previous_config = engine.config

    say(f"🔬 Strateji taraması başlıyor — {len(targets)} hedef, {len(ladder)} profil.")

    # Round 0: how does the line behave with no help at all?
    if was_running:
        engine.stop()
    baseline = StrategyResult("kapalı", "Motor kapalı (temel ölçüm)", _run_probes(targets))
    say(f"   Temel ölçüm: {baseline.score}/{baseline.total} hedef açıldı.")

    report = FinderReport(baseline=baseline)
    report.dns_hijack_suspected = any(p.dns_hijacked for p in baseline.probes)
    report.sni_block_detected = any(p.sni_reset for p in baseline.probes)

    for probe in baseline.probes:
        if not probe.ok:
            say(f"     {probe.host}: {probe.diagnosis}")
    if report.sni_block_detected:
        say("   ⚠ SNI engeli tespit edildi → DPI motorunun çözmesi gereken durum bu.")
    if report.dns_hijack_suspected:
        say("   ⚠ Sahte sertifika görüldü → DNS kaçırma (Kanal 2 gerekli).")

    if baseline.perfect:
        report.bypass_needed = False
        say("   Engel yok — DPI Bypass gerekmiyor.")
        _restore(engine, previous_config, was_running)
        return report

    for profile in ladder:
        config = dpi_engine.PRESETS.get(profile)
        if config is None:
            continue

        say(f"   → {config.name} deneniyor…")
        engine.config = config
        ok, message = engine.start()
        if not ok:
            say(f"     başlatılamadı: {message}")
            continue

        time.sleep(SETTLE_S)
        attempt = StrategyResult(profile, config.name, _run_probes(targets))
        stats = engine.stats.snapshot()
        engine.stop()

        say(f"     {attempt.score}/{attempt.total} hedef açıldı "
            f"({stats.get('packets_rewritten', 0)} paket yeniden yazıldı, "
            f"{stats.get('rst_blocked', 0)} RST engellendi).")
        report.attempts.append(attempt)

        if report.best is None or attempt.score > report.best.score:
            report.best = attempt

        if stop_when_perfect and attempt.perfect:
            say(f"✅ Çalışan profil bulundu: {config.name}")
            break

    if report.best is not None and report.best.score <= baseline.score:
        # Nothing beat doing nothing — do not recommend a profile for show
        say("   Hiçbir profil temel ölçümden iyi sonuç vermedi.")
        report.best = None

    _restore(engine, previous_config, was_running)
    return report


def _restore(engine: "dpi_engine.NativeDpiEngine", config, was_running: bool) -> None:
    """Leave the engine exactly as we found it."""
    engine.config = config
    if was_running and not engine.is_running:
        engine.start()
    elif not was_running and engine.is_running:
        engine.stop()


def apply_report(report: FinderReport) -> Tuple[bool, str]:
    """Start the engine with whatever the scan decided is best."""
    if not report.bypass_needed:
        return False, "Engel bulunamadı — motor başlatılmadı."
    if report.best is None:
        return False, "Uygun bir profil bulunamadı."
    engine = dpi_engine.get_engine()
    engine.config = dpi_engine.PRESETS[report.best.profile]
    return engine.start()
