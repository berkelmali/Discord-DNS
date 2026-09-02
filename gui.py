"""
Discord DNS v3.6 — Premium GUI
CustomTkinter dark-mode interface with Discord-native design language.
Features: DNS preset switcher, Voice Region Ping Matrix, Heartbeat Guard,
          System Tray minimization, auto DNS restore on exit.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import threading
import datetime
import time
import sys
import os

# ─── Asset Resolution ────────────────────────────────────────────────────────────

if getattr(sys, "frozen", False):
    _BASE_DIR = sys._MEIPASS
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ASSETS_DIR = os.path.join(_BASE_DIR, "assets")
ICO_PATH   = os.path.join(ASSETS_DIR, "app_icon.ico")
PNG_PATH   = os.path.join(ASSETS_DIR, "app_icon.png")

# ─── Tray Support ────────────────────────────────────────────────────────────────

try:
    import pystray
    from pystray import MenuItem as TrayItem
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

# ─── App Modules ─────────────────────────────────────────────────────────────────

import atexit
import signal

import dns_manager
import discord_checker
import admin_utils
import heartbeat_guard
import dns_benchmark
import dpi_bypass
import dpi_engine
import doh_proxy
import diagnostics
import strategy_finder

# ─── Theme ────────────────────────────────────────────────────────────────────────

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Premium dark palette — inspired by Discord's native dark theme
BG           = "#0E0F13"     # App background
PANEL        = "#141620"     # Card background
PANEL_HOVER  = "#1A1D2B"     # Card hover
SURFACE      = "#1C1F2E"     # Elevated surface (inputs, inner cards)
BORDER       = "#262A3A"     # Subtle borders
BORDER_GLOW  = "#3B3F54"     # Lighter border for focus

BLURPLE      = "#5865F2"     # Discord Blurple primary
BLURPLE_DIM  = "#4752C4"     # Blurple dimmed/hover
BLURPLE_GLOW = "#7983F5"     # Blurple glow/light
BLURPLE_BG   = "#12142D"     # Blurple-tinted surface

CYAN         = "#00D4FF"     # Neon accent (console, highlights)
CYAN_DIM     = "#0099BB"     # Cyan hover

GREEN        = "#23A55A"     # Success / active
GREEN_DIM    = "#1A7D42"     # Green hover
GREEN_BG     = "#0C2E1B"     # Green tinted card

RED          = "#DA373C"     # Error / disconnect
RED_DIM      = "#A12328"     # Red hover
RED_BG       = "#2D0B0D"     # Red tinted card

GOLD         = "#F0B132"     # Warning
GOLD_BG      = "#2A2008"     # Gold tinted
PURPLE       = "#A78BFA"     # Quad9 accent
PURPLE_BG    = "#1A1230"     # Purple tinted

TEXT         = "#F2F3F5"     # Primary text (bright white)
TEXT_DIM     = "#B5BAC1"     # Secondary text
TEXT_MUTED   = "#6D6F78"     # Tertiary/muted text
TEXT_FAINT   = "#404249"     # Very muted (borders in text form)

CONSOLE_BG   = "#020409"     # Console background

# Typography
FONT_TITLE   = ("Segoe UI Variable Display", 28)  # Hero title
FONT_H1      = ("Segoe UI Variable", 18)           # Section headers
FONT_H2      = ("Segoe UI Variable", 14)           # Card titles
FONT_BODY    = ("Segoe UI Variable", 12)            # Body text
FONT_SMALL   = ("Segoe UI Variable", 11)            # Small text
FONT_TINY    = ("Segoe UI Variable", 10)            # Labels
FONT_MONO    = ("Cascadia Code", 12)                # Monospace / console
FONT_MONO_SM = ("Cascadia Code", 11)                # Small mono
FONT_BTN     = ("Segoe UI Variable", 14)            # Button text


# ─── Tray Icon ────────────────────────────────────────────────────────────────────

def _load_tray_icon(size: int = 128):
    """Load Wumpus PNG for tray with high resolution, fallback to generated icon."""
    if os.path.exists(PNG_PATH):
        try:
            return Image.open(PNG_PATH).convert("RGBA").resize((size, size), Image.LANCZOS)
        except Exception:
            pass
    # Fallback
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([2, 2, size-2, size-2], radius=size//4, fill="#5865F2")
    d.polygon([(size*0.5, size*0.2), (size*0.3, size*0.55), (size*0.5, size*0.55),
               (size*0.45, size*0.8), (size*0.7, size*0.45), (size*0.5, size*0.45)], fill="#FFF")
    return img


# ═══════════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════════

class DiscordDNSApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window setup
        self.title("Discord DNS v3.6")
        # Real sizing happens in _fit_window() once the widgets exist and their
        # true width is known. A fixed 820x980 assumed a big desktop at 100%
        # scaling: on a high-DPI laptop the same numbers become ~1550x1860 after
        # scaling, so the window ran off the screen and the right-hand column of
        # every panel was cut off with no way to scroll to it.
        self.geometry("900x900")
        self.configure(fg_color=BG)

        if os.path.exists(ICO_PATH):
            try:
                self.iconbitmap(ICO_PATH)
            except Exception:
                pass

        # State
        # Restore what the user chose last time before any widget is built, so
        # the window opens on their settings instead of resetting every launch.
        self._config = dns_manager.load_config() or {}
        self._cleanup_done        = False
        self._last_block_kind     = None
        self.connection_state     = "disconnected"
        self.selected_profile     = self._config.get("dpi_profile")
        self._recovery_running    = False  # auto-recovery in flight
        self._preset_user_chosen  = bool(self._config.get("dns_preset_manual"))
        self._channel_user_chosen = bool(self._config.get("channel_manual"))
        self.is_admin_user        = admin_utils.is_admin()
        self.adapters             = dns_manager.get_network_adapters()
        saved_adapter = self._config.get("adapter")
        self.selected_adapter     = (saved_adapter if saved_adapter in self.adapters
                                     else (self.adapters[0] if self.adapters else "Wi-Fi"))
        self.current_preset       = self._config.get("dns_preset") or "Cloudflare"
        self.dns_state            = None
        self.user_dns_enabled     = False
        self.auto_restore_on_exit = tk.BooleanVar(
            value=bool(self._config.get("auto_restore_on_exit", True)))
        self.autostart_var        = tk.BooleanVar(value=dns_manager.is_autostart_enabled())
        self.auto_connect_var     = tk.BooleanVar(
            value=bool(self._config.get("auto_connect_on_start", False)))
        self.dns_active_start_time = None
        self.doh_enabled_var       = tk.BooleanVar(value=False)
        self._autopilot_last_adapter = self.selected_adapter
        self.active_channel        = self._config.get("channel") or "Kanal 1: Standart"
        self.isp_info              = {"isp": "Algılanıyor...", "recommendation_text": "İSS Tespiti Yapılıyor..."}

        # Ensure app starts with normal DNS (DHCP) on launch until user presses button
        if self.is_admin_user:
            dns_manager.restore_original_dns(self.selected_adapter)

        # Heartbeat
        self._guard               = None
        self._hb_data             = {"ok": True, "ping_ms": -1, "consecutive_failures": 0, "preset": "Cloudflare"}

        # Tray
        self._tray_icon           = None

        # Wumpus logo TkImage reference (keep alive to prevent GC)
        self._logo_image          = None

        # Build
        self._build_ui()
        self.refresh_status()
        self._schedule_auto_refresh()
        self._start_heartbeat_guard()
        self._tick_active_timer()
        self._start_adapter_autopilot()
        self._detect_isp_async()
        self._register_emergency_cleanup()
        # Measure the providers up front so the connect screen is already set to
        # the fastest one for this location. The user had to press a button for
        # this before, which meant most people simply connected on the default.
        self.after(1500, self._start_dns_benchmark)
        # Late enough that detection and the speed test have settled
        self.after(6000, self._maybe_auto_connect)

        # X button → minimize to tray (not quit)
        self.protocol("WM_DELETE_WINDOW", self._minimize_to_tray)

        # Start tray icon immediately so it's always visible in the system tray
        self._start_persistent_tray()

    # ═══════════════════════════════════════════════════════════════════════════════
    #  UI BUILD
    # ═══════════════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        root = ctk.CTkScrollableFrame(
            self, fg_color=BG, corner_radius=0,
            scrollbar_button_color=SURFACE,
            scrollbar_button_hover_color=BORDER
        )
        root.grid(row=0, column=0, sticky="nsew")
        root.grid_columnconfigure(0, weight=1)
        self._root_frame = root

        row = 0
        # Order matters: this is a connect/disconnect app, so the control that
        # connects has to be the first thing on screen. It used to sit below the
        # stopwatch, the DNS benchmark and the recommendation banner, which meant
        # scrolling past three panels to reach the button the app exists for.
        row = self._build_header(root, row)
        row = self._build_controls(root, row)
        row = self._build_status_cards(root, row)
        row = self._build_timer_card(root, row)
        row = self._build_dns_banner(root, row)
        row = self._build_benchmark_panel(root, row)
        row = self._build_heartbeat_panel(root, row)
        row = self._build_voice_matrix(root, row)
        row = self._build_log_console(root, row)

        self._build_status_bar()
        self._fit_window()

        # Initial log
        self.log("Discord DNS v3.6 başlatıldı.")
        if not self.is_admin_user:
            self.log("⚠  Yönetici yetkisi yok. DNS değiştirmek için yetki yükseltin.")

    # ── HEADER ─────────────────────────────────────────────────────────────────────

    def _build_header(self, parent, row):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=18,
                              border_width=1, border_color=BORDER)
        frame.grid(row=row, column=0, sticky="ew", padx=22, pady=(20, 8))
        frame.grid_columnconfigure(1, weight=1)

        # Wumpus Logo (left side - Ultra-HD Lanczos Crisp CTkImage)
        mini_logo_path = os.path.join(ASSETS_DIR, "app_logo_mini.png")
        if not os.path.exists(mini_logo_path):
            mini_logo_path = PNG_PATH

        if os.path.exists(mini_logo_path):
            try:
                from PIL import Image
                orig_img = Image.open(mini_logo_path).convert("RGBA")
                # Downsample using Lanczos anti-aliasing to 168x168 (3x scale) for Retina crispness
                hd_img = orig_img.resize((168, 168), Image.Resampling.LANCZOS)
                self._logo_image = ctk.CTkImage(light_image=hd_img, dark_image=hd_img, size=(56, 56))
                logo_lbl = ctk.CTkLabel(frame, image=self._logo_image, text="", cursor="hand2")
                logo_lbl.grid(row=0, column=0, rowspan=2, padx=(22, 12), pady=16, sticky="w")
                logo_lbl.bind("<Button-1>", lambda e: self.show_info_dialog())
            except Exception:
                pass

        # Title
        title_frame = ctk.CTkFrame(frame, fg_color="transparent")
        title_frame.grid(row=0, column=1, sticky="sw", padx=0, pady=(20, 0))

        ctk.CTkLabel(
            title_frame, text="Discord DNS",
            font=ctk.CTkFont(family="Segoe UI Variable Display", size=28, weight="bold"),
            text_color=TEXT
        ).pack(side="left")

        version_badge = ctk.CTkLabel(
            title_frame, text="v3.6",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            fg_color=BLURPLE, text_color="#FFFFFF",
            corner_radius=6, padx=8, pady=2
        )
        version_badge.pack(side="left", padx=(10, 0), pady=(6, 0))

        info_btn = ctk.CTkButton(
            title_frame, text="ℹ  Bilgi & Rehber",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            fg_color=SURFACE, hover_color=BORDER, text_color=CYAN,
            height=26, corner_radius=6, border_width=1, border_color="#2A3048",
            command=self.show_info_dialog
        )
        info_btn.pack(side="left", padx=(10, 0), pady=(4, 0))

        # Subtitle
        ctk.CTkLabel(
            frame, text="Smart Failover  ·  System Tray  ·  TürkNet & ISS Bypass",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=TEXT_MUTED
        ).grid(row=1, column=1, sticky="nw", padx=0, pady=(0, 18))

        # Admin badge (right)
        if self.is_admin_user:
            badge = ctk.CTkLabel(
                frame, text="🛡  Yönetici",
                font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
                fg_color=GREEN_BG, text_color=GREEN,
                corner_radius=10, padx=14, pady=8
            )
            badge.grid(row=0, column=2, rowspan=2, padx=22, pady=18, sticky="e")
        else:
            btn = ctk.CTkButton(
                frame, text="⚠  Yönetici Yap",
                font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
                fg_color=GOLD_BG, hover_color="#3D2E0A", text_color=GOLD,
                height=36, corner_radius=10, border_width=1, border_color=GOLD,
                command=self.elevate_admin
            )
            btn.grid(row=0, column=2, rowspan=2, padx=22, pady=18, sticky="e")

        return row + 1

    # ── DNS BANNER & ISP DETECTOR ──────────────────────────────────────────────────

    def _build_dns_banner(self, parent, row):
        frame = ctk.CTkFrame(parent, fg_color=BLURPLE_BG, corner_radius=14,
                              border_width=1, border_color="#2A2F60")
        frame.grid(row=row, column=0, sticky="ew", padx=22, pady=6)
        frame.grid_columnconfigure(0, weight=1)

        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.pack(fill="x", padx=20, pady=14)

        top_r = ctk.CTkFrame(inner, fg_color="transparent")
        top_r.pack(fill="x")

        ctk.CTkLabel(
            top_r,
            text="⭐  Önerilen  ·  Cloudflare (Discord Optimize)",
            font=ctk.CTkFont(family="Segoe UI Variable", size=13, weight="bold"),
            text_color=BLURPLE_GLOW
        ).pack(side="left", anchor="w")

        # ISP Status Label
        self.isp_lbl = ctk.CTkLabel(
            top_r,
            text="🌐 İSS: Algılanıyor...",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            text_color=CYAN, fg_color=SURFACE, corner_radius=8, padx=10, pady=2
        )
        self.isp_lbl.pack(side="right", anchor="e")

        # ISP Recommendation
        self.isp_recom_lbl = ctk.CTkLabel(
            inner,
            text="İSS tespiti yapılıyor...",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=TEXT_MUTED
        )
        self.isp_recom_lbl.pack(anchor="w", pady=(4, 2))

        dns_text = ctk.CTkFrame(inner, fg_color="transparent")
        dns_text.pack(anchor="w", pady=(4, 0))

        for label, value in [("IPv4", "1.1.1.1  ·  1.0.0.1"), ("IPv6", "2606:4700:4700::1111  ·  2606:4700:4700::1001")]:
            r = ctk.CTkFrame(dns_text, fg_color="transparent")
            r.pack(anchor="w", pady=1)
            ctk.CTkLabel(r, text=f"{label}:", font=ctk.CTkFont(family="Segoe UI Variable", size=11),
                        text_color=TEXT_MUTED).pack(side="left")
            ctk.CTkLabel(r, text=f"  {value}", font=ctk.CTkFont(family="Cascadia Code", size=11, weight="bold"),
                        text_color=CYAN).pack(side="left")

        return row + 1

    def _detect_isp_async(self):
        def _job():
            info = dpi_bypass.detect_isp()
            self._ui(self._apply_isp_info, info)
        threading.Thread(target=_job, daemon=True).start()

    def _apply_isp_info(self, info):
        self.isp_info = info
        isp_name = info.get("isp", "Bilinmiyor")
        recom = info.get("recommendation_text", "")
        self.isp_lbl.configure(text=f"🌐 İSS: {isp_name}")
        self.isp_recom_lbl.configure(text=recom)
        self.log(f"🌐 İSS Algılandı: {isp_name} ({info.get('recommended_channel', 'Standart')})")

        # Auto select recommended channel. Setting a segmented button from code
        # does not fire its command, so the description underneath has to be
        # refreshed by hand — otherwise the app shows Kanal 2 selected while
        # explaining what Kanal 1 does.
        recommended = None
        if info.get("is_superonline") or info.get("is_ttnet"):
            recommended = "⚡ Kanal 3: DPI Bypass"
        elif "DoH" in info.get("recommended_channel", ""):
            recommended = "🔒 Kanal 2: DoH Şifreli"

        if recommended and self._channel_user_chosen:
            self.log(f"↪ Öneri: {recommended} — sizin seçiminiz korunuyor.")
            recommended = None

        if recommended:
            self.channel_seg.set(recommended)
            self.on_channel_change(recommended, user_initiated=False)

    # ── STATUS CARDS ───────────────────────────────────────────────────────────────

    def _build_status_cards(self, parent, row):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=row, column=0, sticky="ew", padx=22, pady=6)
        frame.grid_columnconfigure((0, 1), weight=1)

        # DNS Status Card
        self.dns_card = ctk.CTkFrame(frame, fg_color=PANEL, corner_radius=16,
                                      border_width=1, border_color=BORDER)
        self.dns_card.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        inner_dns = ctk.CTkFrame(self.dns_card, fg_color="transparent")
        inner_dns.pack(fill="both", padx=18, pady=16)

        self.dns_icon_lbl = ctk.CTkLabel(inner_dns, text="🌐",
                                          font=ctk.CTkFont(size=26))
        self.dns_icon_lbl.pack(anchor="w")

        self.dns_title_lbl = ctk.CTkLabel(
            inner_dns, text="DNS Durumu",
            font=ctk.CTkFont(family="Segoe UI Variable", size=16, weight="bold"),
            text_color=TEXT
        )
        self.dns_title_lbl.pack(anchor="w", pady=(4, 0))

        self.dns_desc_lbl = ctk.CTkLabel(
            inner_dns, text="Yükleniyor...",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=TEXT_MUTED
        )
        self.dns_desc_lbl.pack(anchor="w", pady=(2, 0))

        self.dns_timer_lbl = ctk.CTkLabel(
            inner_dns, text="⏱  Geçen Süre: --:--:--",
            font=ctk.CTkFont(family="Cascadia Code", size=11, weight="bold"),
            text_color=CYAN
        )
        self.dns_timer_lbl.pack(anchor="w", pady=(4, 0))

        # Discord Card
        self.disc_card = ctk.CTkFrame(frame, fg_color=PANEL, corner_radius=16,
                                       border_width=1, border_color=BORDER)
        self.disc_card.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        inner_disc = ctk.CTkFrame(self.disc_card, fg_color="transparent")
        inner_disc.pack(fill="both", padx=18, pady=16)

        self.disc_icon_lbl = ctk.CTkLabel(inner_disc, text="💬",
                                           font=ctk.CTkFont(size=26))
        self.disc_icon_lbl.pack(anchor="w")

        self.disc_title_lbl = ctk.CTkLabel(
            inner_disc, text="Discord Bağlantısı",
            font=ctk.CTkFont(family="Segoe UI Variable", size=16, weight="bold"),
            text_color=TEXT
        )
        self.disc_title_lbl.pack(anchor="w", pady=(4, 0))

        self.disc_desc_lbl = ctk.CTkLabel(
            inner_disc, text="Kontrol ediliyor...",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=TEXT_MUTED
        )
        self.disc_desc_lbl.pack(anchor="w", pady=(2, 0))

        return row + 1

    # ── DIGITAL STOPWATCH HERO CARD ───────────────────────────────────────────────

    def _build_timer_card(self, parent, row):
        self.timer_frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=16,
                                         border_width=1, border_color=BORDER)
        self.timer_frame.grid(row=row, column=0, sticky="ew", padx=22, pady=6)
        self.timer_frame.grid_columnconfigure(0, weight=1)

        inner = ctk.CTkFrame(self.timer_frame, fg_color="transparent")
        inner.pack(fill="x", padx=20, pady=16)

        # Header row inside timer card
        top_row = ctk.CTkFrame(inner, fg_color="transparent")
        top_row.pack(fill="x")
        top_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top_row, text="⏱  AKTİF KORUMA & KRONOMETRE",
            font=ctk.CTkFont(family="Segoe UI Variable", size=12, weight="bold"),
            text_color=TEXT_MUTED
        ).grid(row=0, column=0, sticky="w")

        self.timer_status_badge = ctk.CTkLabel(
            top_row, text="⚪ PASİF — DNS KAPALI",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            fg_color=SURFACE, text_color=TEXT_MUTED,
            corner_radius=8, padx=12, pady=4
        )
        self.timer_status_badge.grid(row=0, column=1, sticky="e")

        # Digital Clock Display Box
        clock_box = ctk.CTkFrame(inner, fg_color=SURFACE, corner_radius=12,
                                 border_width=1, border_color=BORDER)
        clock_box.pack(fill="x", pady=(12, 0))
        clock_box.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        # Hours
        h_frame = ctk.CTkFrame(clock_box, fg_color="transparent")
        h_frame.grid(row=0, column=0, pady=10)
        self.lbl_hours = ctk.CTkLabel(h_frame, text="00", font=ctk.CTkFont(family="Cascadia Code", size=26, weight="bold"), text_color=TEXT_FAINT)
        self.lbl_hours.pack()
        ctk.CTkLabel(h_frame, text="SAAT", font=ctk.CTkFont(family="Segoe UI Variable", size=9, weight="bold"), text_color=TEXT_MUTED).pack()

        # Sep 1
        self.lbl_sep1 = ctk.CTkLabel(clock_box, text=":", font=ctk.CTkFont(family="Cascadia Code", size=22, weight="bold"), text_color=TEXT_FAINT)
        self.lbl_sep1.grid(row=0, column=1, pady=10)

        # Minutes
        m_frame = ctk.CTkFrame(clock_box, fg_color="transparent")
        m_frame.grid(row=0, column=2, pady=10)
        self.lbl_mins = ctk.CTkLabel(m_frame, text="00", font=ctk.CTkFont(family="Cascadia Code", size=26, weight="bold"), text_color=TEXT_FAINT)
        self.lbl_mins.pack()
        ctk.CTkLabel(m_frame, text="DAKİKA", font=ctk.CTkFont(family="Segoe UI Variable", size=9, weight="bold"), text_color=TEXT_MUTED).pack()

        # Sep 2
        self.lbl_sep2 = ctk.CTkLabel(clock_box, text=":", font=ctk.CTkFont(family="Cascadia Code", size=22, weight="bold"), text_color=TEXT_FAINT)
        self.lbl_sep2.grid(row=0, column=3, pady=10)

        # Seconds
        s_frame = ctk.CTkFrame(clock_box, fg_color="transparent")
        s_frame.grid(row=0, column=4, pady=10)
        self.lbl_secs = ctk.CTkLabel(s_frame, text="00", font=ctk.CTkFont(family="Cascadia Code", size=26, weight="bold"), text_color=TEXT_FAINT)
        self.lbl_secs.pack()
        ctk.CTkLabel(s_frame, text="SANİYE", font=ctk.CTkFont(family="Segoe UI Variable", size=9, weight="bold"), text_color=TEXT_MUTED).pack()

        return row + 1

    # ── MULTI-DNS BENCHMARK PANEL ──────────────────────────────────────────────────

    def _build_benchmark_panel(self, parent, row):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=16,
                              border_width=1, border_color=BORDER)
        frame.grid(row=row, column=0, sticky="ew", padx=22, pady=6)
        frame.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(16, 10))
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top, text="⚡  Multi-DNS Hız Testi (DNS Jumper)",
            font=ctk.CTkFont(family="Segoe UI Variable", size=14, weight="bold"),
            text_color=TEXT
        ).grid(row=0, column=0, sticky="w")

        self.bench_btn = ctk.CTkButton(
            top, text="⚡  En Hızlı DNS'i Bul & Seç",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            fg_color=BLURPLE, hover_color=BLURPLE_DIM,
            height=32, corner_radius=8,
            command=self._start_dns_benchmark
        )
        self.bench_btn.grid(row=0, column=1, sticky="e")

        # Benchmark grid for 6 providers
        grid = ctk.CTkFrame(frame, fg_color="transparent")
        grid.pack(fill="x", padx=20, pady=(0, 14))
        for c in range(3):
            grid.grid_columnconfigure(c, weight=1)

        self._bench_widgets = {}
        providers = ["Cloudflare", "Google", "Quad9", "AdGuard", "OpenDNS", "ControlD"]

        for i, name in enumerate(providers):
            r, c = i // 3, i % 3
            card = ctk.CTkFrame(grid, fg_color=SURFACE, corner_radius=10,
                                 border_width=1, border_color=BORDER)
            card.grid(row=r, column=c, padx=3, pady=3, sticky="nsew")

            ctk.CTkLabel(card, text=name,
                        font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
                        text_color=TEXT).pack(pady=(8, 2))

            ms_lbl = ctk.CTkLabel(card, text="—",
                                   font=ctk.CTkFont(family="Cascadia Code", size=13, weight="bold"),
                                   text_color=TEXT_FAINT)
            ms_lbl.pack(pady=(2, 8))

            self._bench_widgets[name] = {"card": card, "lbl": ms_lbl}

        return row + 1

    # ── CONTROLS ───────────────────────────────────────────────────────────────────

    def _build_controls(self, parent, row):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=16,
                              border_width=1, border_color=BORDER)
        frame.grid(row=row, column=0, sticky="ew", padx=22, pady=6)
        frame.grid_columnconfigure(0, weight=1)

        # Channel Selection Row (Multi-Channel Engine)
        chan_frame = ctk.CTkFrame(frame, fg_color="transparent")
        chan_frame.pack(fill="x", padx=20, pady=(14, 4))

        ctk.CTkLabel(
            chan_frame, text="BAGLANTI KANALI (ENGEL ASMA MODU)",
            font=ctk.CTkFont(family="Segoe UI Variable", size=10, weight="bold"),
            text_color=TEXT_MUTED
        ).pack(anchor="w", padx=4, pady=(0, 4))

        self.channel_seg = ctk.CTkSegmentedButton(
            chan_frame,
            values=["🟢 Kanal 1: Standart", "🔒 Kanal 2: DoH Şifreli", "⚡ Kanal 3: DPI Bypass"],
            command=self.on_channel_change,
            fg_color=SURFACE, selected_color=BLURPLE, selected_hover_color=BLURPLE_DIM,
            unselected_color=PANEL, unselected_hover_color=SURFACE,
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            height=36, corner_radius=10
        )
        self.channel_seg.set("🟢 Kanal 1: Standart")
        self.channel_seg.pack(fill="x")

        # Channel description label
        self.chan_desc_lbl = ctk.CTkLabel(
            chan_frame,
            text="🟢 Kanal 1: TürkNet ve engelsiz İSS'ler için hızlı Cloudflare DNS.",
            font=ctk.CTkFont(family="Segoe UI Variable", size=10),
            text_color=TEXT_MUTED
        )
        self.chan_desc_lbl.pack(anchor="w", padx=4, pady=(4, 0))

        # Selectors row
        sel = ctk.CTkFrame(frame, fg_color="transparent")
        sel.pack(fill="x", padx=20, pady=(10, 10))
        sel.grid_columnconfigure((0, 1), weight=1)

        # Adapter
        ctk.CTkLabel(sel, text="AĞ KARTI",
                    font=ctk.CTkFont(family="Segoe UI Variable", size=10, weight="bold"),
                    text_color=TEXT_MUTED).grid(row=0, column=0, sticky="w", padx=4)

        self.adapter_dropdown = ctk.CTkOptionMenu(
            sel,
            values=self.adapters if self.adapters else ["Wi-Fi"],
            command=self.on_adapter_change,
            fg_color=SURFACE, button_color=BORDER,
            button_hover_color=BORDER_GLOW,
            dropdown_fg_color=PANEL,
            dropdown_hover_color=SURFACE,
            font=ctk.CTkFont(family="Segoe UI Variable", size=12),
            height=38, corner_radius=10
        )
        self.adapter_dropdown.grid(row=1, column=0, sticky="ew", padx=(4, 8), pady=(4, 0))

        # Preset OptionMenu (6 providers)
        ctk.CTkLabel(sel, text="DNS PROFİLİ",
                    font=ctk.CTkFont(family="Segoe UI Variable", size=10, weight="bold"),
                    text_color=TEXT_MUTED).grid(row=0, column=1, sticky="w", padx=4)

        self.preset_dropdown = ctk.CTkOptionMenu(
            sel,
            values=["Cloudflare", "Google", "Quad9", "AdGuard", "OpenDNS", "ControlD"],
            command=self.on_preset_change,
            fg_color=SURFACE, button_color=BORDER,
            button_hover_color=BORDER_GLOW,
            dropdown_fg_color=PANEL,
            dropdown_hover_color=SURFACE,
            font=ctk.CTkFont(family="Segoe UI Variable", size=12, weight="bold"),
            height=38, corner_radius=10
        )
        self.preset_dropdown.set("Cloudflare")
        self.preset_dropdown.grid(row=1, column=1, sticky="ew", padx=(8, 4), pady=(4, 0))

        # DPI profile picker — the equivalent of a VPN's server list. "Otomatik"
        # lets the ISP detector choose, and the strategy scan can overwrite it
        # with whatever measurably works on this line.
        ctk.CTkLabel(sel, text="DPI PROFİLİ (Kanal 3)",
                    font=ctk.CTkFont(family="Segoe UI Variable", size=10, weight="bold"),
                    text_color=TEXT_MUTED).grid(row=2, column=0, sticky="w", padx=4, pady=(10, 0))

        self.profile_dropdown = ctk.CTkOptionMenu(
            sel,
            # discord_only is deliberately outside the aggression ladder — the
            # scan should not pick a Discord-only profile on its own — but it
            # still belongs in the menu for people who want the engine to leave
            # the rest of their traffic completely untouched.
            values=["Otomatik (İSS'ye göre)"] + [
                dpi_engine.PRESETS[name].name
                for name in list(dpi_engine.AGGRESSION_LADDER) + ["discord_only"]
            ],
            command=self.on_profile_change,
            fg_color=SURFACE, button_color=BORDER,
            button_hover_color=BORDER_GLOW,
            dropdown_fg_color=PANEL,
            dropdown_hover_color=SURFACE,
            font=ctk.CTkFont(family="Segoe UI Variable", size=12),
            height=34, corner_radius=10
        )
        self.profile_dropdown.set("Otomatik (İSS'ye göre)")
        self.profile_dropdown.grid(row=3, column=0, columnspan=2, sticky="ew",
                                   padx=4, pady=(4, 0))

        # Connection status, stated plainly above the button that changes it
        status_row = ctk.CTkFrame(frame, fg_color="transparent")
        status_row.pack(fill="x", padx=20, pady=(12, 2))

        self.conn_led = ctk.CTkLabel(
            status_row, text="●",
            font=ctk.CTkFont(size=18), text_color=TEXT_FAINT
        )
        self.conn_led.pack(side="left", padx=(2, 8))

        self.conn_state_lbl = ctk.CTkLabel(
            status_row, text="BAĞLI DEĞİL",
            font=ctk.CTkFont(family="Segoe UI Variable", size=15, weight="bold"),
            text_color=TEXT_MUTED
        )
        self.conn_state_lbl.pack(side="left")

        self.conn_detail_lbl = ctk.CTkLabel(
            status_row, text="Sistem ayarlarınıza dokunulmadı",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=TEXT_FAINT
        )
        self.conn_detail_lbl.pack(side="right", padx=4)

        # Big Action Button
        self.action_btn = ctk.CTkButton(
            frame,
            text="⚡  BAĞLAN",
            font=ctk.CTkFont(family="Segoe UI Variable", size=15, weight="bold"),
            height=52, corner_radius=12,
            fg_color=BLURPLE, hover_color=BLURPLE_DIM,
            border_width=0,
            command=self.toggle_dns
        )
        self.action_btn.pack(fill="x", padx=20, pady=(8, 6))

        # DNS Info
        info = ctk.CTkFrame(frame, fg_color=SURFACE, corner_radius=10)
        info.pack(fill="x", padx=20, pady=(4, 6))
        info.grid_columnconfigure((0, 1), weight=1)

        self.v4_lbl = ctk.CTkLabel(
            info, text="IPv4:  —",
            font=ctk.CTkFont(family="Cascadia Code", size=11),
            text_color=TEXT_DIM, anchor="w"
        )
        self.v4_lbl.grid(row=0, column=0, sticky="w", padx=14, pady=10)

        self.v6_lbl = ctk.CTkLabel(
            info, text="IPv6:  —",
            font=ctk.CTkFont(family="Cascadia Code", size=11),
            text_color=TEXT_DIM, anchor="w"
        )
        self.v6_lbl.grid(row=0, column=1, sticky="w", padx=14, pady=10)

        # Options Row (DoH Checkbox + Auto restore Checkbox)
        self.doh_chk = ctk.CTkCheckBox(
            frame,
            text="🔒 Şifreli DNS (yerel DoH çözümleyici — Windows 10/11)",
            variable=self.doh_enabled_var,
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=CYAN,
            fg_color=BLURPLE, hover_color=BLURPLE_DIM,
            checkmark_color="#FFF", border_color=BORDER,
            corner_radius=6
        )
        self.doh_chk.pack(anchor="w", padx=22, pady=(4, 2))

        self.autostart_chk = ctk.CTkCheckBox(
            frame,
            text="🚀 Windows açıldığında uygulamayı başlat",
            variable=self.autostart_var,
            command=self.toggle_autostart,
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=TEXT_DIM,
            fg_color=BLURPLE, hover_color=BLURPLE_DIM,
            checkmark_color="#FFF", border_color=BORDER,
            corner_radius=6
        )
        self.autostart_chk.pack(anchor="w", padx=22, pady=(4, 2))

        self.auto_connect_chk = ctk.CTkCheckBox(
            frame,
            text="⚡ Uygulama açıldığında otomatik bağlan",
            variable=self.auto_connect_var,
            command=self.toggle_auto_connect,
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=TEXT_DIM,
            fg_color=BLURPLE, hover_color=BLURPLE_DIM,
            checkmark_color="#FFF", border_color=BORDER,
            corner_radius=6
        )
        self.auto_connect_chk.pack(anchor="w", padx=22, pady=(4, 2))

        self.auto_chk = ctk.CTkCheckBox(
            frame,
            text="Çıkışta orijinal DNS'e otomatik geri dön",
            variable=self.auto_restore_on_exit,
            command=self._save_settings,
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=TEXT_DIM,
            fg_color=GREEN, hover_color=GREEN_DIM,
            checkmark_color="#FFF", border_color=BORDER,
            corner_radius=6
        )
        self.auto_chk.pack(anchor="w", padx=22, pady=(4, 18))

        return row + 1

    # ── HEARTBEAT PANEL ────────────────────────────────────────────────────────────

    def _build_heartbeat_panel(self, parent, row):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=16,
                              border_width=1, border_color=BORDER)
        frame.grid(row=row, column=0, sticky="ew", padx=22, pady=6)
        frame.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(16, 8))
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top, text="💓  Heartbeat Guard",
            font=ctk.CTkFont(family="Segoe UI Variable", size=14, weight="bold"),
            text_color=TEXT
        ).grid(row=0, column=0, sticky="w")

        self.hb_toggle = ctk.CTkButton(
            top, text="Durdur",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            fg_color=SURFACE, hover_color=BORDER,
            text_color=TEXT_DIM,
            height=30, width=72, corner_radius=8,
            command=self.toggle_heartbeat_guard
        )
        self.hb_toggle.grid(row=0, column=1, sticky="e")

        # Status strip
        strip = ctk.CTkFrame(frame, fg_color=SURFACE, corner_radius=10)
        strip.pack(fill="x", padx=20, pady=(0, 16))
        strip.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.hb_led = ctk.CTkLabel(
            strip, text="●  Aktif",
            font=ctk.CTkFont(family="Segoe UI Variable", size=12, weight="bold"),
            text_color=GREEN
        )
        self.hb_led.grid(row=0, column=0, padx=14, pady=12, sticky="w")

        self.hb_ping = ctk.CTkLabel(
            strip, text="Ping: —",
            font=ctk.CTkFont(family="Cascadia Code", size=12),
            text_color=TEXT
        )
        self.hb_ping.grid(row=0, column=1, padx=8, pady=12)

        self.hb_fails = ctk.CTkLabel(
            strip, text="Hata: 0",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=TEXT_MUTED
        )
        self.hb_fails.grid(row=0, column=2, padx=8, pady=12)

        self.hb_preset = ctk.CTkLabel(
            strip, text="Cloudflare",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            text_color=BLURPLE
        )
        self.hb_preset.grid(row=0, column=3, padx=14, pady=12, sticky="e")

        return row + 1

    # ── VOICE REGION MATRIX ────────────────────────────────────────────────────────

    def _build_voice_matrix(self, parent, row):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=16,
                              border_width=1, border_color=BORDER)
        frame.grid(row=row, column=0, sticky="ew", padx=22, pady=6)
        frame.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(16, 10))
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top, text="📡  Ses Bölgesi Ping Matrisi",
            font=ctk.CTkFont(family="Segoe UI Variable", size=14, weight="bold"),
            text_color=TEXT
        ).grid(row=0, column=0, sticky="w")

        self.region_scan_btn = ctk.CTkButton(
            top, text="Tara",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            fg_color=BLURPLE, hover_color=BLURPLE_DIM,
            height=30, width=72, corner_radius=8,
            command=self._start_region_scan
        )
        self.region_scan_btn.grid(row=0, column=1, sticky="e")

        # Region grid
        grid = ctk.CTkFrame(frame, fg_color="transparent")
        grid.pack(fill="x", padx=20, pady=(0, 8))
        for c in range(5):
            grid.grid_columnconfigure(c, weight=1)

        self._region_widgets = {}
        regions = list(discord_checker.VOICE_REGIONS.keys())

        for i, label in enumerate(regions):
            r, c = i // 5, i % 5
            parts = label.split(" ", 1)
            flag = parts[0]
            name = parts[1] if len(parts) > 1 else label

            card = ctk.CTkFrame(grid, fg_color=SURFACE, corner_radius=10,
                                 border_width=1, border_color=BORDER)
            card.grid(row=r, column=c, padx=3, pady=3, sticky="nsew")

            ctk.CTkLabel(card, text=flag, font=ctk.CTkFont(size=18)).pack(pady=(10, 2))
            ctk.CTkLabel(card, text=name,
                        font=ctk.CTkFont(family="Segoe UI Variable", size=10),
                        text_color=TEXT_MUTED).pack()

            ping_lbl = ctk.CTkLabel(card, text="—",
                                     font=ctk.CTkFont(family="Cascadia Code", size=13, weight="bold"),
                                     text_color=TEXT_FAINT)
            ping_lbl.pack(pady=(4, 10))

            self._region_widgets[label] = {"card": card, "ping": ping_lbl}

        # Legend
        legend = ctk.CTkFrame(frame, fg_color="transparent")
        legend.pack(fill="x", padx=20, pady=(4, 14))
        for color, txt in [(GREEN, "<60ms"), ("#FCD34D", "60-120"), ("#F97316", "120-200"), (RED, ">200"), (TEXT_FAINT, "✗")]:
            ctk.CTkLabel(legend, text="●", font=ctk.CTkFont(size=10), text_color=color).pack(side="left", padx=(6, 2))
            ctk.CTkLabel(legend, text=txt, font=ctk.CTkFont(family="Segoe UI Variable", size=9), text_color=TEXT_MUTED).pack(side="left", padx=(0, 8))

        return row + 1

    # ── LOG CONSOLE ────────────────────────────────────────────────────────────────

    def _build_log_console(self, parent, row):
        frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=16,
                              border_width=1, border_color=BORDER)
        frame.grid(row=row, column=0, sticky="ew", padx=22, pady=(6, 16))
        frame.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(14, 6))
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top, text="📋  Sistem Günlüğü",
            font=ctk.CTkFont(family="Segoe UI Variable", size=12, weight="bold"),
            text_color=TEXT_MUTED
        ).grid(row=0, column=0, sticky="w")

        btn_frame = ctk.CTkFrame(top, fg_color="transparent")
        btn_frame.grid(row=0, column=1, sticky="e")

        ctk.CTkButton(
            btn_frame, text="📝 Liste",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            fg_color=SURFACE, hover_color=BORDER,
            text_color=TEXT_MUTED,
            height=26, width=70, corner_radius=6,
            command=self.open_blacklist_editor
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_frame, text="🎯 Strateji Bul",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            fg_color=SURFACE, hover_color=BORDER,
            text_color=GOLD,
            height=26, width=105, corner_radius=6,
            command=self.run_strategy_finder
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_frame, text="🔬 Test & Kanıtla",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            fg_color=SURFACE, hover_color=BORDER,
            text_color=CYAN,
            height=26, width=120, corner_radius=6,
            command=self.open_diagnostics
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_frame, text="💾 Kaydet",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            fg_color=SURFACE, hover_color=BORDER,
            text_color=TEXT_MUTED,
            height=26, width=70, corner_radius=6,
            command=self.save_logs_to_file
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_frame, text="Temizle",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            fg_color=SURFACE, hover_color=BORDER,
            text_color=TEXT_MUTED,
            height=26, width=65, corner_radius=6,
            command=self.clear_logs
        ).pack(side="left")

        self.log_box = ctk.CTkTextbox(
            frame, height=180,
            fg_color=CONSOLE_BG, text_color=CYAN,
            font=ctk.CTkFont(family="Cascadia Code", size=11),
            corner_radius=10, border_width=1, border_color=BORDER
        )
        self.log_box.pack(fill="x", padx=20, pady=(0, 16))

        return row + 1

    # ── STATUS BAR ─────────────────────────────────────────────────────────────────

    def _build_status_bar(self):
        bar = ctk.CTkFrame(self, fg_color="#080A0F", corner_radius=0, height=40)
        bar.grid(row=1, column=0, sticky="ew")
        bar.grid_columnconfigure(1, weight=1)
        bar.grid_propagate(False)

        self.bar_led = ctk.CTkLabel(bar, text="●", font=ctk.CTkFont(size=10), text_color=GOLD)
        self.bar_led.grid(row=0, column=0, padx=(18, 6), sticky="w")

        self.bar_text = ctk.CTkLabel(
            bar, text="Başlatılıyor...",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=TEXT_MUTED
        )
        self.bar_text.grid(row=0, column=1, padx=4, sticky="w")

        btn_kw = dict(
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            fg_color=SURFACE, hover_color=BORDER,
            text_color=TEXT_DIM, height=28, corner_radius=6
        )

        ctk.CTkButton(bar, text="Flush DNS", width=80, command=self.manual_flush_dns, **btn_kw).grid(row=0, column=2, padx=3, pady=6)
        ctk.CTkButton(bar, text="📡 Tara", width=70, command=self._start_region_scan, **btn_kw).grid(row=0, column=3, padx=3, pady=6)
        ctk.CTkButton(bar, text="Yenile", width=65, command=self.refresh_status, **btn_kw).grid(row=0, column=4, padx=(3, 18), pady=6)

    # ═══════════════════════════════════════════════════════════════════════════════
    #  SYSTEM TRAY  (always visible while app is running)
    # ═══════════════════════════════════════════════════════════════════════════════

    def _start_persistent_tray(self):
        """Launch tray icon at startup — stays visible as long as the app runs."""
        if not HAS_TRAY:
            return
        img = _load_tray_icon()
        menu = pystray.Menu(
            TrayItem("Discord DNS v3.6", lambda: None, enabled=False),
            pystray.Menu.SEPARATOR,
            TrayItem("Pencereyi Aç / Göster",  self._tray_show_window),
            TrayItem("DNS Durumunu Yenile",    lambda i, item: self._ui(self.refresh_status)),
            TrayItem("DNS Önbelleğini Temizle", lambda i, item: self._ui(self.manual_flush_dns)),
            pystray.Menu.SEPARATOR,
            TrayItem("Çıkış",                  self._tray_exit),
        )
        self._tray_icon = pystray.Icon("DiscordDNS", img, "Discord DNS v3.6 — Koruma kapalı", menu)
        threading.Thread(target=self._tray_icon.run, daemon=True).start()
        self._refresh_tray_tooltip()

    def _refresh_tray_tooltip(self):
        """
        Keep the hover text honest — Windows 11 usually tucks new tray icons into
        the overflow area, so the tooltip is often the only status the user sees
        without opening the window.
        """
        if not self._tray_icon:
            return
        parts = []
        if doh_proxy.is_running():
            parts.append("🔒 Şifreli DNS")
        engine = dpi_bypass.active_engine()
        if engine:
            parts.append("⚡ DPI motoru")
        if not parts and self.user_dns_enabled and self.dns_state and not self.dns_state.get("is_dhcp"):
            parts.append(f"🟢 {self.dns_state.get('preset_name', 'DNS')}")
        status = " · ".join(parts) if parts else "Koruma kapalı"
        try:
            self._tray_icon.title = f"Discord DNS v3.6 — {status}"
        except Exception:
            pass

    def _minimize_to_tray(self):
        """X only hides the window — the app (and DNS management) keeps running."""
        self.withdraw()
        if self._tray_icon and (self.user_dns_enabled or doh_proxy.is_running()):
            try:
                self._tray_icon.notify(
                    "Uygulama tepside çalışmaya devam ediyor. DNS ayarlarınız hâlâ "
                    "yönetiliyor — tamamen kapatmak için tepsi menüsünden Çıkış'ı seçin.",
                    "Discord DNS arka planda"
                )
            except Exception:
                pass

    def _tray_show_window(self, icon=None, item=None):
        """Restore the main window from tray."""
        self._ui(self._do_show_window)

    def _do_show_window(self):
        """Bring window back to foreground."""
        self.deiconify()
        self.lift()
        self.focus_force()

    def _tray_exit(self, icon=None, item=None):
        """Full quit from tray menu — stops tray, restores DNS, destroys window."""
        self._ui(self.on_app_close)

    # ═══════════════════════════════════════════════════════════════════════════════
    #  HEARTBEAT GUARD
    # ═══════════════════════════════════════════════════════════════════════════════

    def _start_heartbeat_guard(self):
        self._guard = heartbeat_guard.HeartbeatGuard(
            adapter_name=self.selected_adapter,
            on_status_change=self._on_hb_event,
        )
        self._guard.start()

    def toggle_heartbeat_guard(self):
        if self._guard and self._guard.is_running:
            self._guard.stop()
            self.hb_toggle.configure(text="Başlat")
            self.hb_led.configure(text="▪  Durduruldu", text_color=TEXT_MUTED)
            self.log("Heartbeat Guard durduruldu.")
        else:
            if self._guard:
                self._guard.start()
            else:
                self._start_heartbeat_guard()
            self.hb_toggle.configure(text="Durdur")
            self.hb_led.configure(text="●  Aktif", text_color=GREEN)
            self.log("Heartbeat Guard başlatıldı.")

    def _on_hb_event(self, event, data):
        self._ui(self._apply_hb, event, data)

    def _apply_hb(self, event, data):
        if event == "heartbeat":
            ok       = data.get("ok", True)
            ping_ms  = data.get("ping_ms", -1)
            failures = data.get("consecutive_failures", 0)
            preset   = data.get("preset", "—")

            self.hb_ping.configure(text=f"Ping: {ping_ms}ms" if ping_ms >= 0 else "Ping: —")
            self.hb_fails.configure(text=f"Hata: {failures}")
            self.hb_preset.configure(text=preset)

            diagnosis = data.get("diagnosis", "")
            if ok:
                self.hb_led.configure(text="●  Aktif", text_color=GREEN)
                self._recovery_running = False
            else:
                self.hb_led.configure(text=f"●  Hata ({failures}x)", text_color=RED)
                # Say what went wrong, not just that something did
                if diagnosis and failures == 1:
                    self.log(f"💓 Bağlantı kontrolü başarısız: {diagnosis}")
                self._maybe_auto_recover(failures)

        elif event == "failover":
            frm = data.get("from_preset", "?")
            to  = data.get("to_preset", "?")
            self.log(f"🔄 FAILOVER: {frm} → {to}")
            self.log(f"   {data.get('reason', '')}")
            self.hb_preset.configure(text=f"{to} (auto)")
            if to in ["Cloudflare", "Google DNS", "Quad9"]:
                self.preset_seg.set("Google DNS" if to == "Google" else to)
            self.refresh_status()

        elif event == "all_failed":
            self.log(f"⚠  {data.get('message', 'Tüm DNS profilleri başarısız.')}")

    # ═══════════════════════════════════════════════════════════════════════════════
    #  VOICE REGIONS
    # ═══════════════════════════════════════════════════════════════════════════════

    def _start_region_scan(self):
        self.region_scan_btn.configure(text="...", state="disabled")
        for w in self._region_widgets.values():
            w["ping"].configure(text="…", text_color=TEXT_FAINT)
        self.log("📡 Ses bölgeleri taranıyor...")
        threading.Thread(target=self._do_region_scan, daemon=True).start()

    def _do_region_scan(self):
        results = discord_checker.check_voice_regions()
        self._ui(self._apply_regions, results)

    def _apply_regions(self, results):
        for label, info in results.items():
            if label not in self._region_widgets:
                continue
            ms = info.get("ms", -1)
            ok = info.get("ok", False)
            color = discord_checker.ping_color(ms)
            self._region_widgets[label]["ping"].configure(
                text=f"{ms}ms" if ok else "✗",
                text_color=color
            )

        self.region_scan_btn.configure(text="Tara", state="normal")
        ok_count = sum(1 for v in results.values() if v["ok"])
        self.log(f"📡 Tarama tamamlandı: {ok_count}/{len(results)} bölge erişilebilir.")

    # ═══════════════════════════════════════════════════════════════════════════════
    #  MULTI-DNS BENCHMARK ENGINE & AUTOPILOT
    # ═══════════════════════════════════════════════════════════════════════════════

    def _start_dns_benchmark(self):
        if not self._alive():
            return
        self.bench_btn.configure(text="Taranıyor...", state="disabled")
        for w in self._bench_widgets.values():
            w["lbl"].configure(text="…", text_color=TEXT_FAINT)
            w["card"].configure(fg_color=SURFACE, border_color=BORDER)
        self.log("⚡ Multi-DNS Hız Testi başlatıldı (6 sağlayıcı taranıyor)...")
        threading.Thread(target=self._do_dns_benchmark, daemon=True).start()

    def _do_dns_benchmark(self):
        res = dns_benchmark.benchmark_all_providers()
        fastest_name, fastest_ms, _ = dns_benchmark.find_fastest_provider()
        self._ui(self._apply_benchmark_results, res, fastest_name)

    def _apply_benchmark_results(self, results, fastest_name):
        self.bench_btn.configure(text="⚡  En Hızlı DNS'i Bul & Seç", state="normal")
        for name, data in results.items():
            if name not in self._bench_widgets:
                continue
            ms = data.get("ms", -1)
            ok = data.get("ok", False)
            card = self._bench_widgets[name]["card"]
            lbl = self._bench_widgets[name]["lbl"]

            if ok and ms > 0:
                lbl.configure(text=f"{ms} ms", text_color=CYAN if name != fastest_name else GREEN)
                if name == fastest_name:
                    card.configure(fg_color="#0D1F15", border_color=GREEN)
                else:
                    card.configure(fg_color=SURFACE, border_color=BORDER)
            else:
                lbl.configure(text="Erişilemiyor", text_color=RED)
                card.configure(fg_color=SURFACE, border_color=BORDER)

        if fastest_name:
            if self._preset_user_chosen and self.current_preset != fastest_name:
                # Never overrule a deliberate choice; just say what was measured
                self.log(f"⚡ En hızlı DNS: {fastest_name} ({results[fastest_name]['ms']} ms) — "
                         f"sizin seçiminiz ({self.current_preset}) korunuyor.")
                return
            self.current_preset = fastest_name
            self.preset_dropdown.set(fastest_name)
            self.log(f"⚡ En hızlı DNS otomatik seçildi: {fastest_name} "
                     f"({results[fastest_name]['ms']} ms) — bağlanmaya hazır.")
            self._sync_action_button()

        # Order the failover chain by what was actually measured, so a fallback
        # never lands on a provider slower than the one that just failed.
        ranked = [name for name, data in
                  sorted(results.items(), key=lambda kv: kv[1].get("ms", 9999))
                  if data.get("ok")]
        if ranked and self._guard:
            self._guard.set_chain(ranked)

    def _start_adapter_autopilot(self):
        def _loop():
            while True:
                time.sleep(12)
                try:
                    adapters = dns_manager.get_network_adapters()
                    if adapters and adapters[0] != self._autopilot_last_adapter:
                        new_adapter = adapters[0]
                        self._autopilot_last_adapter = new_adapter
                        self._ui(self._on_adapter_auto_switched, new_adapter)
                except Exception:
                    pass
        threading.Thread(target=_loop, daemon=True).start()

    def _on_adapter_auto_switched(self, new_adapter):
        self.selected_adapter = new_adapter
        self.adapter_dropdown.set(new_adapter)
        self.log(f"🔄 AĞ OTOPİLOTU: Aktif ağ kartı değişti → {new_adapter}")
        is_managed = self.user_dns_enabled and self.dns_state and not self.dns_state.get("is_dhcp")
        if is_managed:
            dns_manager.set_preset_dns(new_adapter, self.current_preset, enable_doh=self.doh_enabled_var.get())
            self.log(f"⚡ {self.current_preset} DNS yeni karta ({new_adapter}) otomatik uygulandı!")
        self.refresh_status()

    # ═══════════════════════════════════════════════════════════════════════════════
    #  DNS ACTIONS
    # ═══════════════════════════════════════════════════════════════════════════════

    def on_adapter_change(self, choice):
        self.selected_adapter = choice
        self._save_settings()
        if self._guard:
            self._guard.adapter_name = choice
        self.log(f"Ağ kartı: {choice}")
        self.refresh_status()

    def on_preset_change(self, choice):
        self.current_preset = choice
        self._preset_user_chosen = True
        self._save_settings()
        if self._guard:
            self._guard.sync_preset(self.current_preset)
        self.log(f"Profil: {self.current_preset}")
        self._sync_action_button()

    def on_channel_change(self, choice, user_initiated: bool = True):
        self.active_channel = choice
        if user_initiated:
            self._channel_user_chosen = True
        if "Kanal 1" in choice:
            self.chan_desc_lbl.configure(text="🟢 Kanal 1: TürkNet ve engelsiz İSS'ler için hızlı Cloudflare DNS.")
        elif "Kanal 2" in choice:
            self.chan_desc_lbl.configure(text="🔒 Kanal 2: Yerel DoH çözümleyici -- tüm DNS sorguları 443/TLS üzerinden şifrelenir (Windows 10/11).")
        elif "Kanal 3" in choice:
            self.chan_desc_lbl.configure(text="⚡ Kanal 3: Yerel DPI motoru -- ClientHello'yu SNI içinden bölerek Superonline/TT engellerini aşar.")
        # Channels 2 and 3 both route DNS through the local encrypted resolver,
        # so the checkbox is not a separate choice there — showing it unticked
        # while encrypted DNS is actually in use was simply misleading.
        implied = ("Kanal 2" in choice) or ("Kanal 3" in choice)
        self.doh_enabled_var.set(True if implied else False)
        try:
            self.doh_chk.configure(state="disabled" if implied else "normal")
        except Exception:
            pass

        self.log(f"Kanal Değişti: {choice}")
        self._save_settings()
        self._sync_action_button()

    def _maybe_auto_recover(self, failures: int):
        """
        Re-establish protection without the user touching anything.

        An ISP can change its DPI behaviour mid-session, and a strategy that
        worked ten minutes ago can stop working. When the heartbeat keeps failing
        while we are connected through the engine, look for a strategy that works
        now instead of sitting there claiming to be connected.
        """
        if self.connection_state != "connected" or self._recovery_running:
            return
        if failures < 2 or "Kanal 3" not in self.active_channel:
            return
        if not self.is_admin_user:
            return

        self._recovery_running = True
        self.log("🔄 Bağlantı bozuldu — çalışan strateji yeniden aranıyor…")

        def worker():
            try:
                report = strategy_finder.find_best_strategy(
                    on_progress=lambda line: self._ui(self.log, line)
                )
                if report.best is not None:
                    ok, message = strategy_finder.apply_report(report)
                    self.selected_profile = report.best.profile
                    self._ui(self.log, message)
                    if ok:
                        self._ui(self.log,
                                   f"✅ Toparlandı — {report.best.label} profiline geçildi.")
                        return
                self._ui(self.log, f"⚠ Toparlanamadı: {report.summary()}")
                self._ui(self._set_connection_state, "error")
            except Exception as e:
                self._ui(self.log, f"✗ Otomatik toparlama başarısız: {e}")
            finally:
                self._ui(setattr, self, "_recovery_running", False)

        threading.Thread(target=worker, daemon=True).start()

    def on_profile_change(self, choice):
        """Pick a specific DPI strategy, or hand the decision back to detection."""
        if choice.startswith("Otomatik"):
            self.selected_profile = None
            self.log("DPI profili: otomatik (İSS tespitine göre)")
            self._save_settings()
            return
        for name in dpi_engine.PRESETS:
            if dpi_engine.PRESETS[name].name == choice:
                self.selected_profile = name
                config = dpi_engine.PRESETS[name]
                self.log(f"DPI profili: {config.name} — {config.description}")
                self._save_settings()
                if self.connection_state == "connected":
                    self.log("↪ Değişikliğin geçerli olması için bağlantıyı kesip yeniden bağlanın.")
                return

    def _alive(self) -> bool:
        """
        Whether there is still a window to update.

        Scheduled work outlives the window: a timer set with after() fires even
        after destroy(), and the callback then raises inside Tcl. Every periodic
        job checks this first.
        """
        try:
            return bool(self.winfo_exists())
        except Exception:
            return False

    def _save_settings(self):
        """
        Persist the choices worth remembering across launches.

        The functions to do this existed but nothing ever called them, so every
        launch reset the user's channel, provider and profile back to defaults.
        Only deliberate choices are marked as manual, which is what stops the
        ISP detector and the speed test from overruling them next time.
        """
        try:
            dns_manager.save_config({
                "version": 1,
                "adapter": self.selected_adapter,
                "channel": self.active_channel,
                "channel_manual": self._channel_user_chosen,
                "dns_preset": self.current_preset,
                "dns_preset_manual": self._preset_user_chosen,
                "dpi_profile": self.selected_profile,
                "auto_restore_on_exit": bool(self.auto_restore_on_exit.get()),
                "auto_connect_on_start": bool(self.auto_connect_var.get()),
            })
        except Exception as e:
            self.log(f"Ayarlar kaydedilemedi: {e}")

    def toggle_autostart(self):
        """Add or remove the app from Windows startup."""
        enable = bool(self.autostart_var.get())
        ok, message = dns_manager.set_autostart(enable)
        self.log(("🚀 " if ok and enable else "") + message)
        if not ok:
            self.autostart_var.set(dns_manager.is_autostart_enabled())
        self._save_settings()

    def toggle_auto_connect(self):
        """Whether protection should come up by itself when the app starts."""
        self._save_settings()
        if self.auto_connect_var.get():
            self.log("Açılışta otomatik bağlanma açık — uygulama başlar başlamaz korur.")
        else:
            self.log("Açılışta otomatik bağlanma kapalı.")

    def _maybe_auto_connect(self):
        """
        Connect on launch when the user asked for it.

        Waits for ISP detection and the speed test to finish first, so the
        automatic connection uses the same settings the user would have seen.
        """
        if not self._alive() or not self.auto_connect_var.get():
            return
        if not self.is_admin_user or self.connection_state != "disconnected":
            return
        self.log("⚡ Açılışta otomatik bağlanma başlatılıyor…")
        self.toggle_dns()

    def _display_scaling(self) -> float:
        """
        The factor CustomTkinter applies to every widget on this display.

        Everything that computes a size has to agree on it, so it is read in one
        place. Reading it separately in the dialog code silently fell back to 1.0
        and produced a window taller than the screen.
        """
        try:
            scaling = ctk.ScalingTracker.get_window_scaling(self)
        except Exception:
            scaling = None
        return float(scaling) if scaling else 1.0

    def _fit_window(self):
        """
        Size and centre the window against the actual screen and the actual
        content, in the same units the widgets use.

        CustomTkinter scales every widget by the display's DPI factor, so a
        hard-coded pixel size means something different on each machine. Asking
        the built layout how wide it wants to be, then clamping that to the
        screen, gives a window that fits everywhere: nothing is cut off on a
        laptop, and nothing is needlessly cramped on a desktop.
        """
        self.update_idletasks()
        scaling = self._display_scaling()

        screen_w = self.winfo_screenwidth() / scaling
        screen_h = self.winfo_screenheight() / scaling

        try:
            # +40 leaves room for the scrollbar and the frame's own padding
            wanted_w = self._root_frame.winfo_reqwidth() / scaling + 40
        except Exception:
            wanted_w = 900

        width = int(max(780, min(wanted_w, screen_w * 0.95)))
        height = int(min(980, screen_h * 0.88))
        x = int(max(0, (screen_w - width) / 2))
        y = int(max(0, (screen_h - height) / 2 - 20))

        self.geometry(f"{width}x{height}+{x}+{y}")
        self.minsize(int(min(760, screen_w * 0.9)), int(min(620, screen_h * 0.5)))

    def _ui(self, callback, *args):
        """
        Marshal a call onto the UI thread from a worker.

        Tk refuses to be touched from another thread unless its main loop is
        running, so a background job that finishes during startup or while the
        window is being torn down would otherwise raise and kill that thread.
        The work is best-effort by nature: if there is no UI left to update,
        there is nothing to do.
        """
        try:
            self.after(0, callback, *args)
        except (RuntimeError, tk.TclError):
            pass

    def _is_protection_up(self) -> bool:
        """True when anything of ours is currently applied to the system."""
        return bool(
            self.user_dns_enabled and (
                (self.dns_state and not self.dns_state.get("is_dhcp")) or
                dpi_bypass.is_dpi_bypass_running() or
                doh_proxy.is_running()
            )
        )

    def _sync_action_button(self):
        # Never fight the state machine mid-transition, and do not quietly paper
        # over an error state — if the connection came up but the block was not
        # beaten, the button must keep saying so until the user acts.
        if self.connection_state in ("connecting", "disconnecting"):
            return
        if self.connection_state == "error" and self._is_protection_up():
            return
        self._set_connection_state("connected" if self._is_protection_up() else "disconnected")

    def toggle_dns(self):
        if self.connection_state in ("connecting", "disconnecting"):
            return

        if not self.is_admin_user:
            messagebox.showwarning("Yönetici Gerekli",
                                   "DNS ve DPI tüneli değiştirmek için uygulamayı Yönetici olarak çalıştırın.")
            self.elevate_admin()
            return

        is_managed = self._is_protection_up()
        self.action_btn.configure(state="disabled")
        threading.Thread(target=self._do_toggle, args=(is_managed,), daemon=True).start()

    def _do_toggle(self, is_managed):
        if is_managed:
            self._do_disconnect()
        else:
            self._do_connect()

    # ── connect ─────────────────────────────────────────────────────────────────

    def _do_connect(self):
        """
        Bring protection up and *prove* it works before reporting success.

        A VPN client that says "connected" while the traffic is still blocked is
        worse than useless, so this applies the settings, then opens real TLS
        connections to the targets. If they are still refused, it walks the
        profile ladder until something measurably works, and only then reports a
        connection.
        """
        self._set_connection_state("connecting")
        self._ui(self.log, "⏳ Bağlanılıyor…")

        use_doh = ("Kanal 2" in self.active_channel
                   or "Kanal 3" in self.active_channel
                   or self.doh_enabled_var.get())
        messages = []

        # 1) DNS layer
        if use_doh:
            doh_ok, doh_msg = doh_proxy.start(self.current_preset)
            messages.append(doh_msg)
            if doh_ok:
                _, dns_msg = dns_manager.set_local_resolver_dns(self.selected_adapter)
                messages.append(dns_msg)
            else:
                # Being offline is worse than being unencrypted
                _, dns_msg = dns_manager.set_preset_dns(self.selected_adapter, self.current_preset)
                messages.append(f"↪ Şifresiz {self.current_preset} DNS'e geçildi.\n{dns_msg}")
        else:
            _, dns_msg = dns_manager.set_preset_dns(self.selected_adapter, self.current_preset)
            messages.append(dns_msg)

        # 2) DPI layer
        engine_wanted = "Kanal 3" in self.active_channel
        if engine_wanted:
            mode = self.selected_profile or dpi_bypass.resolve_mode(self.isp_info)
            engine_ok, engine_msg = dpi_bypass.start_dpi_bypass(mode=mode)
            messages.append(engine_msg)
            if not engine_ok:
                self._ui(self._on_connect_done, False, "\n".join(messages),
                           "Motor başlatılamadı")
                return

        # 3) Verify — the part that makes "connected" mean something
        self._ui(self.log, "\n".join(messages))
        self._ui(self.log, "🔍 Bağlantı doğrulanıyor…")
        self._set_progress("Hedeflere gerçek bağlantı deneniyor…")
        results = [strategy_finder.probe_host(host) for host in strategy_finder.DEFAULT_TARGETS]
        blocked = [r for r in results if not r.ok]

        for result in results:
            self._ui(self.log,
                       f"    {result.host}: {'✓ açık' if result.ok else '✗ ' + result.diagnosis}")

        if not blocked:
            self._ui(self._on_connect_done, True, "", "Bağlandı ve doğrulandı")
            return

        # 4) Still blocked → find a profile that measurably works
        if engine_wanted:
            self._ui(self.log,
                       f"⚠ {len(blocked)} hedef hâlâ kapalı — çalışan strateji aranıyor…")
            report = strategy_finder.find_best_strategy(
                targets=tuple(r.host for r in blocked),
                on_progress=lambda line: (self._ui(self.log, line),
                                          self._set_progress(line.strip())),
            )
            if report.best is not None:
                applied_ok, applied_msg = strategy_finder.apply_report(report)
                self.selected_profile = report.best.profile
                self._ui(self.log, applied_msg)
                if applied_ok:
                    self._ui(self._on_connect_done, True, "",
                               f"Bağlandı — {report.best.label} profili ile")
                    return
            verdict = diagnostics.classify_block(blocked[0].host)
            self._ui(self.log, f"🔎 {verdict.get('message')}")
            for item in verdict.get("evidence", []):
                self._ui(self.log, f"    · {item}")
            self._ui(self._on_connect_done, False, "",
                       "Bağlanıldı ama engel aşılamadı")
            return

        self._ui(self._on_connect_done, True, "",
                   f"Bağlandı ({len(blocked)} hedef hâlâ kapalı — Kanal 3'ü deneyin)")

    def _on_connect_done(self, ok, message, label):
        if message:
            self.log(message)
        self.log(f"{'✅' if ok else '⚠'}  {label}")
        self.user_dns_enabled = True
        self._set_connection_state("connected" if ok else "error")
        if self._guard:
            self._guard.is_dns_active = True
        self.action_btn.configure(state="normal")
        self.refresh_status()

    # ── disconnect ──────────────────────────────────────────────────────────────

    def _do_disconnect(self):
        """
        Take protection down and *verify* the machine is back to normal — the
        adapter on the user's own DNS servers, both engines stopped, nothing of
        ours left listening.
        """
        self._set_connection_state("disconnecting")
        self._ui(self.log, "⏳ Bağlantı kesiliyor…")

        _, engine_msg = dpi_bypass.stop_dpi_bypass()
        _, doh_msg = doh_proxy.stop()
        dns_msg = self._restore_original_dns()

        problems = []
        if dpi_bypass.is_dpi_bypass_running():
            problems.append("DPI motoru hâlâ çalışıyor")
        if doh_proxy.is_running():
            problems.append("DoH çözümleyici hâlâ çalışıyor")

        state = dns_manager.get_current_dns(self.selected_adapter)
        if state.get("is_local_doh"):
            problems.append("DNS hâlâ 127.0.0.1'e bakıyor")

        restored = ", ".join(state.get("ipv4") or []) or "Otomatik (DHCP)"
        self._ui(self._on_disconnect_done, problems,
                   f"{dns_msg}\n{engine_msg}\n{doh_msg}", restored)

    def _on_disconnect_done(self, problems, message, restored):
        self.log(message)
        if problems:
            self.log("⚠ Kapatma eksik kaldı: " + ", ".join(problems))
            self._set_connection_state("error")
        else:
            self.log(f"🔌 Bağlantı kesildi. DNS geri yüklendi → {restored}")
            self._set_connection_state("disconnected")
        self.user_dns_enabled = False
        self.dns_active_start_time = None
        self._last_block_kind = None
        if self._guard:
            self._guard.is_dns_active = False
        self.action_btn.configure(state="normal")
        self.refresh_status()

    # ── state machine ───────────────────────────────────────────────────────────

    def _set_connection_state(self, state: str):
        """Drive the button and the status text from one place, like a VPN client."""
        self.connection_state = state
        appearance = {
            "disconnected":  ("⚡  BAĞLAN", BLURPLE, BLURPLE_DIM, "normal"),
            "connecting":    ("⏳  BAĞLANILIYOR…", GOLD, GOLD, "disabled"),
            "connected":     ("⏹  BAĞLANTIYI KES", RED, RED_DIM, "normal"),
            "disconnecting": ("⏳  KAPATILIYOR…", GOLD, GOLD, "disabled"),
            "error":         ("⏹  BAĞLANTIYI KES (sorun var)", RED, RED_DIM, "normal"),
        }[state]
        text, colour, hover, button_state = appearance

        banner = {
            "disconnected":  ("BAĞLI DEĞİL", TEXT_MUTED, TEXT_FAINT,
                              "Sistem ayarlarınıza dokunulmadı"),
            "connecting":    ("BAĞLANILIYOR…", GOLD, GOLD,
                              "Ayarlar uygulanıyor ve doğrulanıyor"),
            "connected":     ("BAĞLI", GREEN, GREEN,
                              "Erişim gerçek bağlantıyla doğrulandı"),
            "disconnecting": ("KAPATILIYOR…", GOLD, GOLD,
                              "Motorlar durduruluyor, DNS geri yükleniyor"),
            "error":         ("BAĞLI — ENGEL AŞILAMADI", RED, RED,
                              "Ayrıntı için günlüğe bakın"),
        }[state]
        label, label_colour, led_colour, detail = banner

        def apply():
            self.action_btn.configure(text=text, fg_color=colour,
                                      hover_color=hover, state=button_state)
            self.conn_state_lbl.configure(text=label, text_color=label_colour)
            self.conn_led.configure(text_color=led_colour)
            self.conn_detail_lbl.configure(text=detail)
        self._ui(apply)

    # ═══════════════════════════════════════════════════════════════════════════════
    #  STATUS REFRESH
    # ═══════════════════════════════════════════════════════════════════════════════

    def refresh_status(self):
        if not self._alive():
            return
        self.bar_led.configure(text_color=GOLD)
        self.bar_text.configure(text="Güncelleniyor...")
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def _do_refresh(self):
        dns  = dns_manager.get_current_dns(self.selected_adapter)
        disc = discord_checker.check_discord_connection()
        self._ui(self._apply_refresh, dns, disc)

    def _apply_refresh(self, dns, disc):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.dns_state = dns
        self._watchdog_check(dns)
        self._refresh_tray_tooltip()
        self._explain_failure_if_needed(disc)

        v4 = ", ".join(dns.get("ipv4", [])) or "Otomatik (DHCP)"
        v6 = ", ".join(dns.get("ipv6", [])) or "Otomatik (DHCP)"
        self.v4_lbl.configure(text=f"IPv4:  {v4}")
        self.v6_lbl.configure(text=f"IPv6:  {v6}")

        preset = dns.get("preset_name", "DHCP")

        # DNS card
        if dns.get("is_cloudflare"):
            self.dns_card.configure(fg_color="#0D1F15", border_color="#1A4D2E")
            self.dns_icon_lbl.configure(text="⚡")
            self.dns_title_lbl.configure(text="Cloudflare DNS", text_color=GREEN)
            self.dns_desc_lbl.configure(text="1.1.1.1 · 1.0.0.1  (IPv4+IPv6)")
        elif dns.get("is_google"):
            self.dns_card.configure(fg_color="#0D1428", border_color="#1A3060")
            self.dns_icon_lbl.configure(text="🔵")
            self.dns_title_lbl.configure(text="Google DNS", text_color="#60A5FA")
            self.dns_desc_lbl.configure(text="8.8.8.8 · 8.8.4.4  (IPv4+IPv6)")
        elif dns.get("is_quad9"):
            self.dns_card.configure(fg_color=PURPLE_BG, border_color="#2E1F60")
            self.dns_icon_lbl.configure(text="🛡")
            self.dns_title_lbl.configure(text="Quad9 DNS", text_color=PURPLE)
            self.dns_desc_lbl.configure(text="9.9.9.9 · 149.112.112.112")
        elif dns.get("is_dhcp"):
            self.dns_card.configure(fg_color=PANEL, border_color=BORDER)
            self.dns_icon_lbl.configure(text="🌐")
            self.dns_title_lbl.configure(text="Varsayılan (DHCP)", text_color=TEXT_MUTED)
            self.dns_desc_lbl.configure(text="İSS varsayılan DNS")
        else:
            self.dns_card.configure(fg_color=PANEL, border_color=BORDER)
            self.dns_icon_lbl.configure(text="🔧")
            self.dns_title_lbl.configure(text="Özel DNS", text_color=GOLD)
            self.dns_desc_lbl.configure(text=v4[:35])

        # Discord card
        if disc.get("accessible"):
            ping = disc.get("ping_ms", -1)
            self.disc_card.configure(fg_color="#0D1F15", border_color="#1A4D2E")
            self.disc_icon_lbl.configure(text="💬")
            self.disc_title_lbl.configure(text=f"Erişilebilir  ·  {ping}ms", text_color=GREEN)
            self.disc_desc_lbl.configure(text="Discord sunucularıyla bağlantı başarılı.")
            self.bar_led.configure(text_color=GREEN)
            disc_short = f"OK ({ping}ms)"
        else:
            self.disc_card.configure(fg_color=RED_BG, border_color="#4D1A1A")
            self.disc_icon_lbl.configure(text="🚫")
            self.disc_title_lbl.configure(text="Erişilemiyor", text_color=RED)
            self.disc_desc_lbl.configure(text="DNS değiştirip tekrar deneyin.")
            self.bar_led.configure(text_color=RED)
            disc_short = "Kapalı"

        self.bar_text.configure(
            text=f"{preset}  ·  Discord {disc_short}  ·  {self.selected_adapter}  ·  {self._engine_summary()}  ·  {now}"
        )
        self._sync_action_button()

    def _engine_summary(self) -> str:
        """One-line live state of the bypass engines for the status bar."""
        parts = []

        engine = dpi_bypass.active_engine()
        if engine == dpi_bypass.ENGINE_NATIVE:
            st = dpi_bypass.engine_stats()
            parts.append(f"⚡ Yerel motor {st.get('packets_rewritten', 0)} paket")
        elif engine == dpi_bypass.ENGINE_GOODBYEDPI:
            parts.append("⚡ Yedek motor (goodbyedpi)")

        if doh_proxy.is_running():
            st = doh_proxy.stats()
            parts.append(f"🔒 DoH {st.get('queries', 0)} sorgu")

        return "  ·  ".join(parts) if parts else "Motor kapalı"

    def _schedule_auto_refresh(self):
        if not self._alive():
            return
        self.refresh_status()
        self.after(30_000, self._schedule_auto_refresh)

    def _tick_active_timer(self):
        if not self._alive():
            return
        is_managed = self.user_dns_enabled and self.dns_state and not self.dns_state.get("is_dhcp")

        if is_managed:
            if self.dns_active_start_time is None:
                self.dns_active_start_time = time.time()
            elapsed = int(time.time() - self.dns_active_start_time)
            hrs = elapsed // 3600
            mins = (elapsed % 3600) // 60
            secs = elapsed % 60

            h_str = f"{hrs:02d}"
            m_str = f"{mins:02d}"
            s_str = f"{secs:02d}"

            self.lbl_hours.configure(text=h_str, text_color=CYAN)
            self.lbl_mins.configure(text=m_str, text_color=CYAN)
            self.lbl_secs.configure(text=s_str, text_color=CYAN)

            # Pulsing colon effect (blinks every second)
            sep_color = CYAN if (elapsed % 2 == 0) else BORDER
            self.lbl_sep1.configure(text_color=sep_color)
            self.lbl_sep2.configure(text_color=sep_color)

            self.dns_timer_lbl.configure(
                text=f"⏱  Aktif Süre: {h_str}:{m_str}:{s_str}",
                text_color=CYAN
            )

            preset_name = self.dns_state.get("preset_name", "DNS") if self.dns_state else "DNS"
            self.timer_frame.configure(fg_color="#0D1F15", border_color="#1A4D2E")
            self.timer_status_badge.configure(
                text=f"🟢 {preset_name.upper()} AKTİF KORUMA",
                fg_color=GREEN_BG, text_color=GREEN
            )
        else:
            self.dns_active_start_time = None
            self.lbl_hours.configure(text="00", text_color=TEXT_FAINT)
            self.lbl_mins.configure(text="00", text_color=TEXT_FAINT)
            self.lbl_secs.configure(text="00", text_color=TEXT_FAINT)
            self.lbl_sep1.configure(text_color=TEXT_FAINT)
            self.lbl_sep2.configure(text_color=TEXT_FAINT)

            self.dns_timer_lbl.configure(
                text="⏱  Aktif Süre: Pasif",
                text_color=TEXT_MUTED
            )

            self.timer_frame.configure(fg_color=PANEL, border_color=BORDER)
            self.timer_status_badge.configure(
                text="⚪ PASİF — DNS KAPALI",
                fg_color=SURFACE, text_color=TEXT_MUTED
            )

        self.after(1000, self._tick_active_timer)

    # ═══════════════════════════════════════════════════════════════════════════════
    #  MISC
    # ═══════════════════════════════════════════════════════════════════════════════

    def show_info_dialog(self):
        """Open a detailed, dark-themed information & user guide window."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("ℹ Discord DNS v3.6 — Bilgi & Kullanım Rehberi")
        # Clamp to the screen in the same units the widgets use, so the guide
        # does not open taller than the desktop on a scaled display.
        scaling = self._display_scaling()
        dlg_w = 720
        dlg_h = int(min(700, (self.winfo_screenheight() / scaling) * 0.82))
        dialog.geometry(f"{dlg_w}x{dlg_h}")
        dialog.configure(fg_color="#0F111A")
        dialog.transient(self)
        dialog.grab_set()

        # Center dialog relative to main window
        try:
            dialog.update_idletasks()
            x = self.winfo_x() + (self.winfo_width() // 2) - (dlg_w // 2)
            y = self.winfo_y() + (self.winfo_height() // 2) - (dlg_h // 2)
            dialog.geometry(f"{dlg_w}x{dlg_h}+{max(0, x)}+{max(0, y)}")
        except Exception:
            pass

        # Title bar header frame
        hdr = ctk.CTkFrame(dialog, fg_color="#181B28", corner_radius=12)
        hdr.pack(fill="x", padx=16, pady=(16, 8))

        ctk.CTkLabel(
            hdr, text="⚡ Discord DNS v3.6 — Uygulama Rehberi & Bilgi",
            font=ctk.CTkFont(family="Segoe UI Variable Display", size=16, weight="bold"),
            text_color="#FFFFFF"
        ).pack(side="left", padx=16, pady=12)

        # Scrollable Content Body
        body = ctk.CTkScrollableFrame(dialog, fg_color="#121520", corner_radius=12)
        body.pack(fill="both", expand=True, padx=16, pady=8)

        text_sections = [
            ("⚡ 3 Adımda Başla",
             "1. Uygulamayı Yönetici olarak açın (başlıkta sarı 'Yönetici Yap' düğmesi görünüyorsa henüz değilsiniz).\n"
             "2. Kanal, İSS'nize göre zaten otomatik seçilidir — dokunmanıza gerek yok.\n"
             "3. ⚡ BAĞLAN'a basın. Uygulama ayarları uygular, sonra gerçek bir bağlantı kurup çalıştığını doğrular "
             "ve ancak o zaman 'BAĞLI' yazar.\n\n"
             "Hepsi bu. İşiniz bitince ⏹ BAĞLANTIYI KES deyin; DNS ayarlarınız kendi orijinal sunucularınıza geri döner."),

            ("🔌 'BAĞLAN' ve 'BAĞLANTIYI KES' tam olarak ne yapar?",
             "BAĞLAN yalnızca ayar uygulamaz — uyguladıktan sonra Discord sunucularına gerçek bir şifreli bağlantı açıp sınar. "
             "Hâlâ engelliyse çalışan bir yöntem bulana kadar stratejileri tek tek dener ve ancak ölçtüğü bir başarıdan sonra "
             "'BAĞLI' der. Bulamazsa nedenini günlüğe yazar, butonu 'ENGEL AŞILAMADI' durumunda bırakır; size asla sahte bir "
             "'bağlandı' göstermez.\n\n"
             "BAĞLANTIYI KES motorları durdurur, DNS'inizi geri yükler ve sonra kontrol eder: motor gerçekten durdu mu, "
             "şifreli çözümleyici kapandı mı, ağ kartı hâlâ uygulamaya mı bakıyor. Eksik kalan olursa size söyler."),

            ("🔀 Hangi kanal? (emin değilseniz otomatik seçime güvenin)",
             "🟢 Kanal 1 — Standart DNS\n"
             "    İSS'niz engelleme yapmıyorsa en hızlısı. Yalnızca DNS sunucunuzu değiştirir.\n\n"
             "🔒 Kanal 2 — Şifreli DNS (DoH)\n"
             "    İSS'niz DNS yanıtlarını değiştiriyorsa (discord.com'u engel sunucusuna yönlendiriyorsa) bunu çözer. "
             "Uygulama kendi çözümleyicisini bilgisayarınızda çalıştırır; tüm sorgular 443/TLS üzerinden şifreli gider.\n\n"
             "⚡ Kanal 3 — DPI Bypass\n"
             "    İSS'niz bağlantının içindeki alan adını görüp bağlantıyı kesiyorsa gereken budur. Uygulamanın kendi paket "
             "motoru devreye girer, şifreli DNS de birlikte açılır. Türk Telekom / Avea ve Superonline için önerilen kanal budur."),

            ("🎯 Çalışmadıysa: uygulama size nedenini söyler",
             "Bağlantı kurulamadığında günlükte '🔎 Erişim sorunu teşhisi:' satırını arayın:\n\n"
             "• 'SNI ENGELİ ... RST paketiyle kesiyor'  →  Kanal 3'e geçin, sonra 🎯 Strateji Bul'a basın.\n"
             "• 'DNS KAÇIRMA ... engel sunucusuna'  →  Kanal 2 yeterlidir.\n"
             "• 'TCP bağlantısı hiç kurulamıyor'  →  IP seviyesinde engel; bu araç aşamaz, VPN gerekir.\n"
             "• 'Şifreli DNS sunucularına ulaşılamıyor'  →  İnternet bağlantınızı kontrol edin.\n\n"
             "🔬 Test & Kanıtla düğmesi tüm kontrolleri tek seferde yapıp paylaşılabilir bir rapor üretir; genel IP'niz "
             "maskelenir. Sorun bildirirken bu raporu ekleyin."),

            ("🧠 Gelişmiş kullanım",
             "• 🎯 Strateji Bul: Profilleri en hafiften en agresife doğru dener ve hattınızda gerçekten çalışanı ölçerek "
             "seçer. Bir şey çalışmıyorsa ilk başvuracağınız düğme budur.\n\n"
             "• DPI Profili menüsü: 'Otomatik' bırakabilir ya da elle seçebilirsiniz. Türk Telekom / Avea hattında ölçümle "
             "doğrulanan yöntem 'Durum Takipli DPI' profilidir.\n\n"
             "• Yalnızca Discord'a dokunsun: %APPDATA%\\DiscordDNS\\blacklist.txt dosyasına satır satır alan adı yazarsanız "
             "motor sadece onlara dokunur, diğer trafiğinize hiç karışmaz.\n\n"
             "• Otomatik toparlama: Bağlıyken İSS davranışını değiştirirse uygulama kendi kendine çalışan yeni bir strateji "
             "arar ve ona geçer; sizin bir şey yapmanız gerekmez."),

            ("🔔 Pencereyi kapatmak uygulamayı kapatmaz",
             "X düğmesi uygulamayı sistem tepsisine küçültür, koruma çalışmaya devam eder. Tamamen çıkmak için tepsi "
             "simgesine sağ tıklayıp Çıkış'ı seçin.\n\n"
             "Windows 11 yeni tepsi simgelerini gizli alana (görev çubuğundaki ^ oku) koyar. Simgeyi oradan sürükleyip görev "
             "çubuğuna bırakırsanız kalıcı görünür olur. Simgenin üzerine geldiğinizde koruma durumu yazar."),

            ("🛡 Ayarlarınıza ne oluyor?",
             "Uygulama açılışta hiçbir şeye dokunmaz. BAĞLAN dediğinizde mevcut DNS ayarlarınız yedeklenir; BAĞLANTIYI KES "
             "veya çıkış yaptığınızda tam olarak o ayarlara dönülür — DHCP'ye değil, kendi sunucularınıza.\n\n"
             "Uygulama zorla kapatılırsa diye iki güvenlik ağı vardır: ikincil DNS olarak Cloudflare yazılır, böylece "
             "internetiniz kesilmez; ve uygulama bir sonraki açılışında yedekten geri yükler. Ağ sürücüsü, son bağlantı "
             "kapandığında Windows tarafından kaldırılır."),

            ("📜 Lisans & Telif Bilgisi",
             "Geliştirici: Berk Elmalı (https://github.com/berkelmali/Discord-DNS)\n"
             "Bu proje açık kaynak kodludur. Kodları kullanan veya yeniden dağıtan herkes geliştirici atıf şartını "
             "korumakla yükümlüdür.")
        ]

        for title, desc in text_sections:
            sec_frame = ctk.CTkFrame(body, fg_color="#1A1D2C", corner_radius=10)
            sec_frame.pack(fill="x", padx=8, pady=6)

            ctk.CTkLabel(
                sec_frame, text=title,
                font=ctk.CTkFont(family="Segoe UI Variable", size=13, weight="bold"),
                text_color="#5865F2"
            ).pack(anchor="w", padx=14, pady=(10, 4))

            ctk.CTkLabel(
                sec_frame, text=desc,
                font=ctk.CTkFont(family="Segoe UI Variable", size=11),
                text_color="#DCDDDE", justify="left", wraplength=545
            ).pack(anchor="w", padx=14, pady=(0, 10))

        # Close Button
        ctk.CTkButton(
            dialog, text="Anladım, Kapat",
            font=ctk.CTkFont(family="Segoe UI Variable", size=12, weight="bold"),
            fg_color="#5865F2", hover_color="#4752C4",
            height=38, corner_radius=8,
            command=dialog.destroy
        ).pack(fill="x", padx=16, pady=12)

    def manual_flush_dns(self):
        self.log("DNS önbelleği temizleniyor...")
        threading.Thread(target=lambda: self._ui(self.log, dns_manager.flush_dns_cache()), daemon=True).start()

    def clear_logs(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
        self.log("Günlük temizlendi.")

    def save_logs_to_file(self):
        """Export system log console text to a .log file."""
        try:
            from tkinter import filedialog
            content = self.log_box.get("1.0", "end").strip()
            if not content:
                messagebox.showinfo("Bilgi", "Kaydedilecek günlük verisi bulunamadı.")
                return
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            file_path = filedialog.asksaveasfilename(
                initialdir=desktop,
                initialfile="discord_dns_system.log",
                defaultextension=".log",
                filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            if file_path:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)
                self.log(f"💾 Sistem günlüğü kaydedildi: {file_path}")
                messagebox.showinfo("Başarılı", f"Sistem günlüğü başarıyla kaydedildi:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Hata", f"Günlük kaydedilemedi: {e}")

    def log(self, text):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}]  {text}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def elevate_admin(self):
        self.log("Yönetici izni talep ediliyor...")
        if not admin_utils.run_as_admin():
            messagebox.showerror("Yönetici Gerekli",
                                  "DNS değiştirmek için Yönetici olarak çalıştırın.")

    # ═══════════════════════════════════════════════════════════════════════════════
    #  DIAGNOSTICS & AUTOMATIC STRATEGY
    # ═══════════════════════════════════════════════════════════════════════════════

    def _explain_failure_if_needed(self, disc):
        """
        When Discord goes unreachable, say *why* instead of just showing a red
        card. The check runs off the UI thread and only when the state actually
        changes, so a persistent outage does not spam the log every 30 seconds.
        """
        if disc.get("accessible"):
            if self._last_block_kind not in (None, "ok"):
                self.log("✓ Bağlantı düzeldi.")
            self._last_block_kind = "ok"
            return

        if self._last_block_kind not in (None, "ok"):
            return                      # already explained this outage

        self._last_block_kind = "checking"

        def worker():
            try:
                verdict = diagnostics.classify_block("discord.com")
            except Exception as e:
                self._ui(self.log, f"Teşhis çalıştırılamadı: {e}")
                self._ui(setattr, self, "_last_block_kind", None)
                return
            self._ui(self._show_block_verdict, verdict)

        threading.Thread(target=worker, daemon=True).start()

    def _show_block_verdict(self, verdict):
        self._last_block_kind = verdict.get("kind")
        self.log(f"🔎 Erişim sorunu teşhisi: {verdict.get('message')}")
        for item in verdict.get("evidence", []):
            self.log(f"    · {item}")

        kind = verdict.get("kind")
        if kind in ("sni_rst", "sni_timeout") and "Kanal 3" not in self.active_channel:
            self.log("↪ Öneri: Kanal 3 (DPI Bypass) veya 🎯 Strateji Bul.")
        elif kind in ("dns_hijack", "mitm") and "Kanal 2" not in self.active_channel:
            self.log("↪ Öneri: Kanal 2 (şifreli DNS).")

    def open_blacklist_editor(self):
        """
        Edit the domain list from inside the app.

        The engine has always been able to restrict itself to a list of domains,
        but the only way to write that list was to create a file by hand in
        %APPDATA% — so in practice nobody used it.
        """
        path = os.path.join(dns_manager._get_backup_dir(), "blacklist.txt")

        window = ctk.CTkToplevel(self)
        window.title("📝 Alan Adı Listesi")
        window.geometry("560x520")
        window.configure(fg_color=BG)
        window.transient(self)

        ctk.CTkLabel(
            window,
            text=("Motor yalnızca buradaki alan adlarına dokunur.\n"
                  "Liste boş bırakılırsa tüm trafiğe uygulanır."),
            font=ctk.CTkFont(family="Segoe UI Variable", size=12),
            text_color=TEXT_DIM, justify="left"
        ).pack(anchor="w", padx=18, pady=(16, 6))

        box = ctk.CTkTextbox(
            window, fg_color=CONSOLE_BG, text_color=CYAN,
            font=ctk.CTkFont(family="Cascadia Code", size=12),
            corner_radius=10, border_width=1, border_color=BORDER
        )
        box.pack(fill="both", expand=True, padx=18, pady=(0, 8))

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                box.insert("end", handle.read())
        except FileNotFoundError:
            box.insert("end", "# Satır başına bir alan adı, # ile yorum\n")

        status = ctk.CTkLabel(
            window, text=f"Dosya: {path}",
            font=ctk.CTkFont(family="Segoe UI Variable", size=10),
            text_color=TEXT_FAINT
        )
        status.pack(anchor="w", padx=18)

        bar = ctk.CTkFrame(window, fg_color="transparent")
        bar.pack(fill="x", padx=18, pady=(6, 16))

        def fill_discord():
            box.delete("1.0", "end")
            listed = "\n".join(dpi_engine.PRESETS["discord_only"].hostnames)
            box.insert("end", "# Yalnızca Discord\n" + listed + "\n")

        def save():
            try:
                with open(path, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(box.get("1.0", "end").strip() + "\n")
            except Exception as e:
                status.configure(text=f"Kaydedilemedi: {e}", text_color=RED)
                return
            listed = dpi_engine.load_hostname_list(path)
            status.configure(
                text=(f"Kaydedildi — {len(listed)} alan adı" if listed
                      else "Kaydedildi — liste boş, motor tüm trafiğe uygulanır"),
                text_color=GREEN
            )
            self.log(f"📝 Alan adı listesi kaydedildi: {len(listed)} kayıt.")
            if self.connection_state == "connected":
                self.log("↪ Değişikliğin geçerli olması için bağlantıyı kesip yeniden bağlanın.")

        ctk.CTkButton(bar, text="💾 Kaydet", command=save,
                      fg_color=BLURPLE, hover_color=BLURPLE_DIM,
                      height=32, corner_radius=8).pack(side="left")
        ctk.CTkButton(bar, text="Discord alan adlarını doldur", command=fill_discord,
                      fg_color=SURFACE, hover_color=BORDER, text_color=TEXT_MUTED,
                      height=32, corner_radius=8).pack(side="left", padx=8)
        ctk.CTkButton(bar, text="Kapat", command=window.destroy,
                      fg_color=SURFACE, hover_color=BORDER, text_color=TEXT_MUTED,
                      height=32, width=80, corner_radius=8).pack(side="right")

    def open_diagnostics(self):
        """Collect a shareable diagnostic report and show it in its own window."""
        window = ctk.CTkToplevel(self)
        window.title("🔬 Test & Kanıtla — Tanılama Raporu")
        window.geometry("760x620")
        window.configure(fg_color=BG)
        window.transient(self)

        box = ctk.CTkTextbox(
            window, fg_color=CONSOLE_BG, text_color=CYAN,
            font=ctk.CTkFont(family="Cascadia Code", size=11),
            corner_radius=10, border_width=1, border_color=BORDER
        )
        box.pack(fill="both", expand=True, padx=16, pady=(16, 8))
        box.insert("end", "Tanılama çalışıyor, lütfen bekleyin…\n\n")

        bar = ctk.CTkFrame(window, fg_color="transparent")
        bar.pack(fill="x", padx=16, pady=(0, 16))

        def copy_report():
            self.clipboard_clear()
            self.clipboard_append(box.get("1.0", "end").strip())
            self.log("📋 Tanılama raporu panoya kopyalandı.")

        ctk.CTkButton(bar, text="📋 Panoya Kopyala", command=copy_report,
                      fg_color=BLURPLE, hover_color=BLURPLE_DIM,
                      height=32, corner_radius=8).pack(side="left")
        ctk.CTkButton(bar, text="Kapat", command=window.destroy,
                      fg_color=SURFACE, hover_color=BORDER, text_color=TEXT_MUTED,
                      height=32, width=90, corner_radius=8).pack(side="right")

        def worker():
            def progress(message):
                self._ui(lambda: box.insert("end", f"  … {message}\n"))
            try:
                report = diagnostics.collect_report(on_progress=progress)
            except Exception as e:
                report = f"Tanılama başarısız: {e}"
            self._ui(lambda: (box.delete("1.0", "end"), box.insert("end", report)))

        threading.Thread(target=worker, daemon=True).start()

    def run_strategy_finder(self):
        """Measure which bypass profile actually works on this line, then apply it."""
        if not self.is_admin_user:
            messagebox.showwarning(
                "Yönetici Gerekli",
                "Strateji taraması motoru açıp kapattığı için Yönetici yetkisi ister."
            )
            return

        if not messagebox.askyesno(
            "Otomatik Strateji Bulucu",
            "Uygulama, engel aşma profillerini tek tek deneyip bu hatta gerçekten "
            "çalışanı bulacak.\n\nTarama sırasında bağlantınız birkaç kez kesilip "
            "yeniden kurulabilir (yaklaşık 1-2 dakika).\n\nDevam edilsin mi?"
        ):
            return

        self.log("🎯 Otomatik strateji taraması başlatıldı…")
        threading.Thread(target=self._do_strategy_scan, daemon=True).start()

    def _set_progress(self, text: str):
        """Show what a long operation is doing, next to the connection state."""
        def apply():
            try:
                self.conn_detail_lbl.configure(text=text[:70])
            except Exception:
                pass
        self._ui(apply)

    def _do_strategy_scan(self):
        def progress(message):
            self._ui(self.log, message)
            self._set_progress(message.strip())

        try:
            report = strategy_finder.find_best_strategy(on_progress=progress)
        except Exception as e:
            self._ui(self.log, f"✗ Strateji taraması başarısız: {e}")
            return

        self._ui(self.log, f"🎯 {report.summary()}")

        if report.best is not None:
            ok, message = strategy_finder.apply_report(report)
            self._ui(self.log, message)
            if ok:
                self._ui(self.channel_seg.set, "⚡ Kanal 3: DPI Bypass")
                self.active_channel = "Kanal 3: DPI Bypass"
        elif report.dns_hijack_suspected:
            self._ui(self.channel_seg.set, "🔒 Kanal 2: DoH Şifreli")
            self.active_channel = "Kanal 2: DoH Şifreli"
            self._ui(self.log, "↪ Kanal 2 (şifreli DNS) seçildi — engel DNS katmanında.")

        self._ui(self.refresh_status)

    # ═══════════════════════════════════════════════════════════════════════════════
    #  SHUTDOWN & CRASH SAFETY
    # ═══════════════════════════════════════════════════════════════════════════════

    def _register_emergency_cleanup(self):
        """
        Make sure DNS is never left pointing at a resolver that is no longer
        running. Closing the window is the happy path; Ctrl+C, a SIGTERM or an
        unhandled exception used to skip cleanup entirely and leave the machine
        with 127.0.0.1 and nothing listening on it — i.e. no DNS at all.
        """
        atexit.register(self._emergency_cleanup)
        for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGBREAK", signal.SIGTERM)):
            try:
                signal.signal(sig, self._on_termination_signal)
            except (ValueError, OSError):
                pass    # not the main thread, or unsupported on this platform

        # Closing the console window (running `python main.py`) does not raise
        # KeyboardInterrupt and skips atexit, so hook the Windows console events
        # directly — this is the path that used to leave DNS pointing at a dead
        # resolver.
        if sys.platform == "win32":
            try:
                import ctypes
                handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)

                def _console_handler(event):
                    if event in (0, 1, 2, 5, 6):   # C, BREAK, CLOSE, LOGOFF, SHUTDOWN
                        self._emergency_cleanup()
                    return False                   # let Windows continue closing

                self._console_handler = handler_type(_console_handler)
                ctypes.windll.kernel32.SetConsoleCtrlHandler(self._console_handler, True)
            except Exception:
                pass

    def _on_termination_signal(self, signum, frame):
        self._emergency_cleanup()
        os._exit(0)

    def _emergency_cleanup(self):
        """Idempotent teardown, safe to call from a signal handler or atexit."""
        if self._cleanup_done:
            return
        self._cleanup_done = True

        for stop in (doh_proxy.stop, dpi_bypass.stop_dpi_bypass):
            try:
                stop()
            except Exception:
                pass

        if not self.is_admin_user:
            return
        try:
            self._restore_original_dns()
        except Exception:
            pass

    def _restore_original_dns(self) -> str:
        """
        Hand DNS back exactly as we found it — the user's own servers, not DHCP.

        The backup written when protection was switched on knows which adapter it
        came from and whether that adapter was on DHCP, so restoring it returns
        the machine to its real previous state. Anything still pointing at our
        local resolver afterwards was ours too, and goes back to automatic.
        """
        messages = []

        if os.path.exists(dns_manager.BACKUP_FILE):
            ok, message = dns_manager.restore_original_dns()
            messages.append(message)

        for adapter in (self.adapters or ["Wi-Fi", "Ethernet"]):
            state = dns_manager.get_current_dns(adapter)
            if state.get("is_local_doh"):
                _, message = dns_manager.reset_dns_to_dhcp(adapter)
                messages.append(message)

        return "\n".join(messages) or "DNS zaten orijinal durumdaydı."

    def _watchdog_check(self, dns_state):
        """
        Called on every status refresh: if the adapter still points at the local
        resolver while the resolver is gone, put DNS back before the user
        notices they have no internet.
        """
        if not dns_state.get("is_local_doh") or doh_proxy.is_running():
            return
        self.log("⚠ Yerel DoH çözümleyici çalışmıyor ama DNS hâlâ 127.0.0.1'e bakıyor — geri alınıyor.")
        if self.is_admin_user:
            ok, msg = dns_manager.reset_dns_to_dhcp(self.selected_adapter)
            self.log(msg)
            self.user_dns_enabled = False

    def on_app_close(self):
        """Full application shutdown — restores DNS, stops the engines, exits."""
        self._save_settings()

        # Stop heartbeat guard
        if self._guard:
            self._guard.stop()

        # Stops both engines and restores DNS (idempotent with the signal path)
        self._emergency_cleanup()

        # Stop tray icon
        if self._tray_icon:
            try:
                self._tray_icon.stop()
            except Exception:
                pass

        self.destroy()
        sys.exit(0)


# ─── Entry ────────────────────────────────────────────────────────────────────────

def main():
    app = DiscordDNSApp()
    app.mainloop()

if __name__ == "__main__":
    main()
