"""
Discord DNS v3.0 — Premium GUI
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
    from PIL import Image, ImageDraw, ImageTk
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

# ─── App Modules ─────────────────────────────────────────────────────────────────

import dns_manager
import discord_checker
import admin_utils
import heartbeat_guard
import dns_benchmark
import dpi_bypass

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
        self.title("Discord DNS v3.0")
        self.geometry("820x980")
        self.minsize(780, 880)
        self.configure(fg_color=BG)

        if os.path.exists(ICO_PATH):
            try:
                self.iconbitmap(ICO_PATH)
            except Exception:
                pass

        # State
        self.is_admin_user        = admin_utils.is_admin()
        self.adapters             = dns_manager.get_network_adapters()
        self.selected_adapter     = self.adapters[0] if self.adapters else "Wi-Fi"
        self.current_preset       = "Cloudflare"
        self.dns_state            = None
        self.user_dns_enabled     = False
        self.auto_restore_on_exit = tk.BooleanVar(value=True)
        self.dns_active_start_time = None
        self.doh_enabled_var       = tk.BooleanVar(value=False)
        self._autopilot_last_adapter = self.selected_adapter
        self.active_channel        = "Kanal 1: Standart"
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

        row = 0
        row = self._build_header(root, row)
        row = self._build_dns_banner(root, row)
        row = self._build_status_cards(root, row)
        row = self._build_timer_card(root, row)
        row = self._build_benchmark_panel(root, row)
        row = self._build_controls(root, row)
        row = self._build_heartbeat_panel(root, row)
        row = self._build_voice_matrix(root, row)
        row = self._build_log_console(root, row)

        self._build_status_bar()

        # Initial log
        self.log("Discord DNS v3.0 başlatıldı.")
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
                logo_lbl = ctk.CTkLabel(frame, image=self._logo_image, text="")
                logo_lbl.grid(row=0, column=0, rowspan=2, padx=(22, 12), pady=16, sticky="w")
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
            title_frame, text="v3.0",
            font=ctk.CTkFont(family="Segoe UI Variable", size=11, weight="bold"),
            fg_color=BLURPLE, text_color="#FFFFFF",
            corner_radius=6, padx=8, pady=2
        )
        version_badge.pack(side="left", padx=(10, 0), pady=(6, 0))

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
            self.after(0, self._apply_isp_info, info)
        threading.Thread(target=_job, daemon=True).start()

    def _apply_isp_info(self, info):
        self.isp_info = info
        isp_name = info.get("isp", "Bilinmiyor")
        recom = info.get("recommendation_text", "")
        self.isp_lbl.configure(text=f"🌐 İSS: {isp_name}")
        self.isp_recom_lbl.configure(text=recom)
        self.log(f"🌐 İSS Algılandı: {isp_name} ({info.get('recommended_channel', 'Standart')})")

        # Auto select recommended channel
        if info.get("is_superonline") or info.get("is_ttnet"):
            self.channel_seg.set("⚡ Kanal 3: DPI Bypass")
            self.active_channel = "Kanal 3: DPI Bypass"
        elif info.get("is_vodafone"):
            self.channel_seg.set("🔒 Kanal 2: DoH Şifreli")
            self.active_channel = "Kanal 2: DoH Şifreli"

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

        # Big Action Button
        self.action_btn = ctk.CTkButton(
            frame,
            text="⚡  CLOUDFLARE DNS ETKİNLEŞTİR",
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
            text="🔒 DoH (DNS-over-HTTPS) Şifrelemeyi Etkinleştir (Windows 11)",
            variable=self.doh_enabled_var,
            font=ctk.CTkFont(family="Segoe UI Variable", size=11),
            text_color=CYAN,
            fg_color=BLURPLE, hover_color=BLURPLE_DIM,
            checkmark_color="#FFF", border_color=BORDER,
            corner_radius=6
        )
        self.doh_chk.pack(anchor="w", padx=22, pady=(4, 2))

        self.auto_chk = ctk.CTkCheckBox(
            frame,
            text="Çıkışta orijinal DNS'e otomatik geri dön",
            variable=self.auto_restore_on_exit,
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
            TrayItem("Discord DNS v3.0", lambda: None, enabled=False),
            pystray.Menu.SEPARATOR,
            TrayItem("Pencereyi Aç / Göster",  self._tray_show_window),
            TrayItem("DNS Durumunu Yenile",    lambda i, item: self.after(0, self.refresh_status)),
            TrayItem("DNS Önbelleğini Temizle", lambda i, item: self.after(0, self.manual_flush_dns)),
            pystray.Menu.SEPARATOR,
            TrayItem("Çıkış",                  self._tray_exit),
        )
        self._tray_icon = pystray.Icon("DiscordDNS", img, "Discord DNS v3.0 — Çalışıyor", menu)
        threading.Thread(target=self._tray_icon.run, daemon=True).start()

    def _minimize_to_tray(self):
        """Called when user clicks X — hides window but keeps app running in tray."""
        self.withdraw()  # Hide window
        # Tray is already running, no need to restart it

    def _tray_show_window(self, icon=None, item=None):
        """Restore the main window from tray."""
        self.after(0, self._do_show_window)

    def _do_show_window(self):
        """Bring window back to foreground."""
        self.deiconify()
        self.lift()
        self.focus_force()

    def _tray_exit(self, icon=None, item=None):
        """Full quit from tray menu — stops tray, restores DNS, destroys window."""
        self.after(0, self.on_app_close)

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
        self.after(0, self._apply_hb, event, data)

    def _apply_hb(self, event, data):
        if event == "heartbeat":
            ok       = data.get("ok", True)
            ping_ms  = data.get("ping_ms", -1)
            failures = data.get("consecutive_failures", 0)
            preset   = data.get("preset", "—")

            self.hb_ping.configure(text=f"Ping: {ping_ms}ms" if ping_ms >= 0 else "Ping: —")
            self.hb_fails.configure(text=f"Hata: {failures}")
            self.hb_preset.configure(text=preset)

            if ok:
                self.hb_led.configure(text="●  Aktif", text_color=GREEN)
            else:
                self.hb_led.configure(text=f"●  Hata ({failures}x)", text_color=RED)

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
        self.after(0, self._apply_regions, results)

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
        self.bench_btn.configure(text="Taranıyor...", state="disabled")
        for w in self._bench_widgets.values():
            w["lbl"].configure(text="…", text_color=TEXT_FAINT)
            w["card"].configure(fg_color=SURFACE, border_color=BORDER)
        self.log("⚡ Multi-DNS Hız Testi başlatıldı (6 sağlayıcı taranıyor)...")
        threading.Thread(target=self._do_dns_benchmark, daemon=True).start()

    def _do_dns_benchmark(self):
        res = dns_benchmark.benchmark_all_providers()
        fastest_name, fastest_ms, _ = dns_benchmark.find_fastest_provider()
        self.after(0, self._apply_benchmark_results, res, fastest_name)

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
            self.current_preset = fastest_name
            self.preset_dropdown.set(fastest_name)
            self.log(f"⚡ EN HIZLI DNS TESPİT EDİLDİ: {fastest_name} ({results[fastest_name]['ms']} ms)")
            self._sync_action_button()

    def _start_adapter_autopilot(self):
        def _loop():
            while True:
                time.sleep(12)
                try:
                    adapters = dns_manager.get_network_adapters()
                    if adapters and adapters[0] != self._autopilot_last_adapter:
                        new_adapter = adapters[0]
                        self._autopilot_last_adapter = new_adapter
                        self.after(0, self._on_adapter_auto_switched, new_adapter)
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
        if self._guard:
            self._guard.adapter_name = choice
        self.log(f"Ağ kartı: {choice}")
        self.refresh_status()

    def on_preset_change(self, choice):
        self.current_preset = choice
        if self._guard:
            self._guard.sync_preset(self.current_preset)
        self.log(f"Profil: {self.current_preset}")
        self._sync_action_button()

    def on_channel_change(self, choice):
        self.active_channel = choice
        if "Kanal 1" in choice:
            self.chan_desc_lbl.configure(text="🟢 Kanal 1: TürkNet ve engelsiz İSS'ler için hızlı Cloudflare DNS.")
        elif "Kanal 2" in choice:
            self.chan_desc_lbl.configure(text="🔒 Kanal 2: DoH (DNS-over-HTTPS) -- İSS DNS hijacking müdahalelerini 443/TLS ile aşar.")
        elif "Kanal 3" in choice:
            self.chan_desc_lbl.configure(text="⚡ Kanal 3: Superonline & Türk Telekom DPI Bypass -- GoodbyeDPI tüneli ile SNI engellerini aşar.")
        self.log(f"Kanal Değişti: {choice}")
        self._sync_action_button()

    def _sync_action_button(self):
        is_managed = self.user_dns_enabled and (
            (self.dns_state and not self.dns_state.get("is_dhcp")) or
            dpi_bypass.is_dpi_bypass_running()
        )
        if is_managed:
            self.action_btn.configure(
                text="↩  ORİJİNAL DNS'E GERİ DÖN & TÜNELİ KAPAT",
                fg_color=RED, hover_color=RED_DIM
            )
        else:
            self.action_btn.configure(
                text=f"⚡  {self.current_preset.upper()} DNS & KANAL ETKİNLEŞTİR",
                fg_color=BLURPLE, hover_color=BLURPLE_DIM
            )

    def toggle_dns(self):
        if not self.is_admin_user:
            messagebox.showwarning("Yönetici Gerekli",
                                   "DNS ve DPI tüneli değiştirmek için uygulamayı Yönetici olarak çalıştırın.")
            self.elevate_admin()
            return

        is_managed = self.user_dns_enabled and (
            (self.dns_state and not self.dns_state.get("is_dhcp")) or
            dpi_bypass.is_dpi_bypass_running()
        )
        self.action_btn.configure(state="disabled", text="⏳  İşlem yapılıyor...")
        threading.Thread(target=self._do_toggle, args=(bool(is_managed),), daemon=True).start()

    def _do_toggle(self, is_managed):
        if is_managed:
            ok, msg = dns_manager.restore_original_dns(self.selected_adapter)
            dpi_bypass.stop_dpi_bypass()
            label = "Orijinal DNS geri yüklendi ve DPI Tüneli kapatıldı"
            is_enabling = False
        else:
            enable_doh = "Kanal 2" in self.active_channel or self.doh_enabled_var.get()
            ok, msg = dns_manager.set_preset_dns(
                self.selected_adapter,
                self.current_preset,
                enable_doh=enable_doh
            )

            # If Kanal 3 (DPI Bypass) selected, also launch GoodbyeDPI engine
            if "Kanal 3" in self.active_channel:
                mode = "superonline" if self.isp_info.get("is_superonline") else ("ttnet" if self.isp_info.get("is_ttnet") else "general")
                dpi_ok, dpi_msg = dpi_bypass.start_dpi_bypass(mode=mode)
                msg += f"\n{dpi_msg}"

            label = f"{self.current_preset} DNS ({self.active_channel}) etkinleştirildi"
            is_enabling = True
        self.after(0, self._on_toggle_done, ok, msg, is_enabling, label)

    def _on_toggle_done(self, ok, msg, is_enabling, label):
        self.action_btn.configure(state="normal")
        self.log(msg)
        self.log(f"{'✓' if ok else '✗'}  {label}")
        if ok:
            self.user_dns_enabled = is_enabling
            if self._guard:
                self._guard.is_dns_active = self.user_dns_enabled
        self.refresh_status()

    # ═══════════════════════════════════════════════════════════════════════════════
    #  STATUS REFRESH
    # ═══════════════════════════════════════════════════════════════════════════════

    def refresh_status(self):
        self.bar_led.configure(text_color=GOLD)
        self.bar_text.configure(text="Güncelleniyor...")
        threading.Thread(target=self._do_refresh, daemon=True).start()

    def _do_refresh(self):
        dns  = dns_manager.get_current_dns(self.selected_adapter)
        disc = discord_checker.check_discord_connection()
        self.after(0, self._apply_refresh, dns, disc)

    def _apply_refresh(self, dns, disc):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.dns_state = dns

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

        self.bar_text.configure(text=f"{preset}  ·  Discord {disc_short}  ·  {self.selected_adapter}  ·  {now}")
        self._sync_action_button()

    def _schedule_auto_refresh(self):
        self.refresh_status()
        self.after(30_000, self._schedule_auto_refresh)

    def _tick_active_timer(self):
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

    def manual_flush_dns(self):
        self.log("DNS önbelleği temizleniyor...")
        threading.Thread(target=lambda: self.after(0, self.log, dns_manager.flush_dns_cache()), daemon=True).start()

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

    def on_app_close(self):
        """Full application shutdown — restores DNS, stops DPI tunnel, and terminates app."""
        # Stop heartbeat guard
        if self._guard:
            self._guard.stop()

        # Stop DPI Bypass engine & WinDivert driver
        dpi_bypass.stop_dpi_bypass()

        # Restore DNS if custom DNS was enabled or active
        if self.is_admin_user:
            dns_manager.restore_original_dns(self.selected_adapter)

        # Stop tray icon
        if self._tray_icon:
            try:
                self._tray_icon.stop()
            except Exception:
                pass

        self.destroy()


# ─── Entry ────────────────────────────────────────────────────────────────────────

def main():
    app = DiscordDNSApp()
    app.mainloop()

if __name__ == "__main__":
    main()
