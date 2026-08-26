"""Tkinter desktop UI -- terminal/console aesthetic.

Tkinter rather than a web dashboard because the tool has to invoke netsh on the
local machine, so the UI has to live there too. It is also in the standard
library, which keeps the project dependency-free.

Threading model: every scan runs on a worker thread and reports back through a
queue that the UI drains on a timer. Tk is not thread-safe -- no worker ever
touches a widget -- and sqlite3 connections cannot cross threads, so each
worker opens its own Store against the same file.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from typing import Callable

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__, baseline as baseline_mod, distance, scanner
from .analyze import enrich_all
from .compare import diff_snapshots
from .config import Config, DEFAULT_CONFIG_NAME
from .detections import RULES, SEVERITY_ORDER, DetectionEngine
from .models import Observation, signal_percent_to_dbm, utcnow
from .oui import OuiLookup
from .store import Store

# The synthetic attacker's MAC in a simulation: locally-administered (02:) so
# it looks exactly like a software-generated rogue, which is what a real evil
# twin uses. Nothing is ever transmitted -- this row only ever exists inside a
# throwaway database to illustrate what a detection looks like.
SIM_ROGUE_BSSID = "02:00:5e:1d:0a:11"

# Console/hacker palette: near-black ground, phosphor green, amber and red for
# escalation. Chosen so a screenshot reads as "security tooling" at a glance.
BG = "#0a0e14"
PANEL = "#0d1522"
FG = "#00ff9c"          # phosphor green -- primary text
DIM = "#3f7d68"         # muted green
MUTED = "#5a6b7b"
BORDER = "#16324a"
CYAN = "#38bdf8"

BAND_COLORS = {
    "CRITICAL": ("#3a0d0d", "#ff5c5c"),
    "HIGH": ("#3a220a", "#ffb454"),
    "MEDIUM": ("#33320f", "#ffe14d"),
    "LOW": ("#0d1522", DIM),
}
SEVERITY_COLORS = {
    "critical": BAND_COLORS["CRITICAL"],
    "high": BAND_COLORS["HIGH"],
    "medium": BAND_COLORS["MEDIUM"],
    "low": ("#0d1522", CYAN),
}

MONO = ("Consolas", 10)
MONO_BOLD = ("Consolas", 10, "bold")

BANNER = (
    "  ██╗    ██╗██╗███████╗██╗    ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗\n"
    "  ██║    ██║██║██╔════╝██║    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝\n"
    "  ██║ █╗ ██║██║█████╗  ██║    ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ \n"
    "  ██║███╗██║██║██╔══╝  ██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  \n"
    "  ╚███╔███╔╝██║██║     ██║    ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   \n"
    "   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   "
)


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)) \
        .replace(microsecond=0).isoformat().replace("+00:00", "Z")


class WifiSentryApp:
    def __init__(self, root: tk.Tk, db: str, config_path: str,
                 oui_file: str | None, interface: str | None) -> None:
        self.root = root
        self.db = db
        self.live_db = db  # self.db is swapped while demo mode is on
        self.demo = False
        self.config_path = config_path
        self.oui_file = oui_file
        self.oui = OuiLookup.from_file(oui_file)
        self.interface = interface

        self.queue: queue.Queue = queue.Queue()
        self.busy = False
        self.watching = False
        self._watch_after: str | None = None
        self._alert_details: dict[str, str] = {}

        root.title("wifi-sentry {} :: rogue AP monitor".format(__version__))
        root.geometry("1200x780")
        root.minsize(1000, 640)
        root.configure(bg=BG)

        self._build_style()
        self._build_banner()
        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()

        self._refresh_baseline_label()
        self._load_alerts_from_store()
        self._refresh_dashboard()
        self._refresh_history()
        self._refresh_snapshot_lists()
        self.root.after(120, self._drain_queue)

    # ------------------------------------------------------------- chrome

    def _build_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")  # 'clam' honours bg colours; native themes do not
        style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL,
                        bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                        font=MONO)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG, font=MONO)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=MONO)
        style.configure("Status.TLabel", background=PANEL, foreground=DIM,
                        padding=6, font=MONO)
        style.configure("TButton", background=PANEL, foreground=FG, borderwidth=1,
                        focusthickness=0, padding=(10, 6), font=MONO)
        style.map("TButton", background=[("active", BORDER), ("disabled", BG)],
                  foreground=[("disabled", MUTED)])
        style.configure("Accent.TButton", background="#0f3d2e", foreground=FG)
        style.map("Accent.TButton",
                  background=[("active", "#155c44"), ("disabled", BORDER)],
                  foreground=[("disabled", MUTED)])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG, foreground=MUTED,
                        padding=(16, 8), borderwidth=0, font=MONO_BOLD)
        style.map("TNotebook.Tab", background=[("selected", PANEL)],
                  foreground=[("selected", FG)])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=FG, rowheight=26, borderwidth=0, font=MONO)
        style.configure("Treeview.Heading", background=BORDER, foreground=FG,
                        relief="flat", padding=6, font=MONO_BOLD)
        style.map("Treeview", background=[("selected", "#10233a")],
                  foreground=[("selected", FG)])
        style.configure("TSpinbox", fieldbackground=PANEL, foreground=FG, arrowcolor=FG)
        style.configure("TCombobox", fieldbackground=PANEL, foreground=FG,
                        background=PANEL, arrowcolor=FG)

    def _build_banner(self) -> None:
        banner = tk.Label(self.root, text=BANNER, bg=BG, fg=FG,
                          font=("Consolas", 6), justify="left", anchor="w")
        banner.pack(fill="x", padx=12, pady=(8, 0))
        tk.Label(self.root,
                 text="  passive rogue access-point monitor  ::  "
                      "baseline -> detect -> triage  ::  MITRE ATT&CK mapped",
                 bg=BG, fg=DIM, font=("Consolas", 9), anchor="w").pack(fill="x", padx=12)

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(12, 10))
        bar.pack(fill="x")

        self.btn_baseline = ttk.Button(bar, text="[ TAKE BASELINE ]",
                                       command=self.on_baseline)
        self.btn_baseline.pack(side="left")
        self.btn_scan = ttk.Button(bar, text="[ SCAN NOW ]", style="Accent.TButton",
                                   command=self.on_scan)
        self.btn_scan.pack(side="left", padx=(8, 0))
        self.btn_watch = ttk.Button(bar, text="[ START WATCH ]",
                                    command=self.on_toggle_watch)
        self.btn_watch.pack(side="left", padx=(8, 0))

        ttk.Label(bar, text="every", style="Muted.TLabel").pack(side="left", padx=(16, 4))
        self.interval = tk.IntVar(value=60)
        ttk.Spinbox(bar, from_=15, to=3600, increment=15, width=5,
                    textvariable=self.interval).pack(side="left")
        ttk.Label(bar, text="s", style="Muted.TLabel").pack(side="left", padx=(4, 0))

        ttk.Button(bar, text="Export JSONL", command=self.on_export).pack(side="right")
        ttk.Button(bar, text="Wipe all data",
                   command=self.on_wipe_data).pack(side="right", padx=(0, 8))
        ttk.Button(bar, text="Clear alerts",
                   command=self.on_clear_alerts).pack(side="right", padx=(0, 8))
        self.btn_demo = ttk.Button(bar, text="[ SIMULATE ATTACK ]",
                                   command=self.on_toggle_demo)
        self.btn_demo.pack(side="right", padx=(0, 8))

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")

    def _build_tabs(self) -> None:
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(4, 8))
        self.tabs.add(self._build_dashboard_tab(), text="  DASHBOARD  ")
        self.tabs.add(self._build_networks_tab(), text="  RADAR  ")
        self.tabs.add(self._build_history_tab(), text="  HISTORY  ")
        self.tabs.add(self._build_compare_tab(), text="  COMPARE  ")
        self.tabs.add(self._build_alerts_tab(), text="  ALERTS  ")
        self.tabs.add(self._build_rules_tab(), text="  RULES  ")

    def _build_dashboard_tab(self) -> ttk.Frame:
        frame = ttk.Frame(self.tabs, padding=14)
        self._caption(frame, "Overview. Start here: take a baseline, then scan. "
                             "Red numbers mean something needs attention.")

        self.stat_cards: dict[str, tk.Label] = {}
        row = tk.Frame(frame, bg=BG)
        row.pack(fill="x")
        for key, title in (("networks", "NETWORKS SEEN"), ("alerts", "ACTIVE ALERTS"),
                           ("new", "NEW (24H)"), ("toprisk", "TOP RISK")):
            card = tk.Frame(row, bg=PANEL, padx=18, pady=14,
                            highlightbackground=BORDER, highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=6)
            value = tk.Label(card, text="--", bg=PANEL, fg=FG,
                             font=("Consolas", 22, "bold"))
            value.pack(anchor="w")
            tk.Label(card, text=title, bg=PANEL, fg=MUTED,
                     font=("Consolas", 9)).pack(anchor="w")
            self.stat_cards[key] = value

        tk.Label(frame, text="  TOP RISK TARGETS", bg=BG, fg=CYAN,
                 font=MONO_BOLD, anchor="w").pack(fill="x", pady=(18, 4))
        self.dash_box = tk.Text(frame, bg=PANEL, fg=FG, insertbackground=FG,
                                relief="flat", padx=14, pady=12, height=14,
                                font=MONO, wrap="none")
        self.dash_box.pack(fill="both", expand=True)
        self.dash_box.configure(state="disabled")
        return frame

    def _build_networks_tab(self) -> ttk.Frame:
        frame = ttk.Frame(self.tabs, padding=8)
        self._caption(frame, "Every network in range, most suspicious first. "
                             "NEW = not in your baseline. Click a row for details.")
        cols = ("risk", "status", "ssid", "bssid", "type", "proximity", "signal", "auth")
        self.net_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, text, width in (
            ("risk", "RISK", 110), ("status", "", 55), ("ssid", "SSID", 180),
            ("bssid", "BSSID", 150), ("type", "DEVICE TYPE", 230),
            ("proximity", "PROXIMITY", 110), ("signal", "SIGNAL", 130),
            ("auth", "AUTH", 130),
        ):
            self.net_tree.heading(col, text=text)
            self.net_tree.column(col, width=width, anchor="w")
        for band, (bg, fg) in BAND_COLORS.items():
            self.net_tree.tag_configure(band, background=bg, foreground=fg)
        self.net_tree.tag_configure("new_marker", foreground="#ffb454")

        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.net_tree.yview)
        self.net_tree.configure(yscrollcommand=scroll.set)
        self.net_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.net_tree.bind("<<TreeviewSelect>>", self._show_network_detail)

        self._net_details: dict[str, str] = {}
        return frame

    def _build_history_tab(self) -> ttk.Frame:
        frame = ttk.Frame(self.tabs, padding=8)
        top = tk.Frame(frame, bg=BG)
        top.pack(fill="x", pady=(0, 6))
        tk.Label(top, text="Devices observed over time. NEW = first seen in last 24h.",
                 bg=BG, fg=MUTED, font=MONO).pack(side="left")
        ttk.Button(top, text="Refresh", command=self._refresh_history).pack(side="right")

        cols = ("status", "ssid", "bssid", "sightings", "first", "last")
        self.hist_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, text, width in (
            ("status", "", 60), ("ssid", "SSID", 200), ("bssid", "BSSID", 150),
            ("sightings", "SEEN", 70), ("first", "FIRST SEEN", 200),
            ("last", "LAST SEEN", 200),
        ):
            self.hist_tree.heading(col, text=text)
            self.hist_tree.column(col, width=width, anchor="w")
        self.hist_tree.tag_configure("new", background="#22160a", foreground="#ffb454")

        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=scroll.set)
        self.hist_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return frame

    def _build_compare_tab(self) -> ttk.Frame:
        frame = ttk.Frame(self.tabs, padding=10)
        info = tk.Label(
            frame, bg=BG, fg=MUTED, justify="left", anchor="w", font=MONO,
            text=("Baseline your home, then capture a cafe or airport, and diff "
                  "them.\nNetworks unique to the untrusted location are where a "
                  "rogue AP hides."))
        info.pack(fill="x", pady=(0, 8))

        controls = tk.Frame(frame, bg=BG)
        controls.pack(fill="x", pady=(0, 8))
        tk.Label(controls, text="Capture here as:", bg=BG, fg=FG,
                 font=MONO).pack(side="left")
        self.snap_name = tk.StringVar()
        tk.Entry(controls, textvariable=self.snap_name, width=16, bg=PANEL, fg=FG,
                 insertbackground=FG, relief="flat", font=MONO).pack(side="left", padx=6)
        ttk.Button(controls, text="Capture location",
                   command=self.on_capture_snapshot).pack(side="left")

        pick = tk.Frame(frame, bg=BG)
        pick.pack(fill="x", pady=(0, 8))
        tk.Label(pick, text="Compare A:", bg=BG, fg=FG, font=MONO).pack(side="left")
        self.cmp_a = ttk.Combobox(pick, width=16, state="readonly")
        self.cmp_a.pack(side="left", padx=6)
        tk.Label(pick, text="vs B:", bg=BG, fg=FG, font=MONO).pack(side="left")
        self.cmp_b = ttk.Combobox(pick, width=16, state="readonly")
        self.cmp_b.pack(side="left", padx=6)
        ttk.Button(pick, text="Compare", command=self.on_compare).pack(side="left", padx=6)

        cols = ("where", "ssid", "bssid", "signal", "auth")
        self.cmp_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col, text, width in (
            ("where", "PRESENT IN", 120), ("ssid", "SSID", 200),
            ("bssid", "BSSID", 150), ("signal", "SIGNAL", 110), ("auth", "AUTH", 140),
        ):
            self.cmp_tree.heading(col, text=text)
            self.cmp_tree.column(col, width=width, anchor="w")
        self.cmp_tree.tag_configure("only_b", background="#22160a", foreground="#ffb454")
        self.cmp_tree.tag_configure("open", background="#3a0d0d", foreground="#ff5c5c")
        self.cmp_tree.pack(fill="both", expand=True)
        return frame

    def _build_alerts_tab(self) -> ttk.Frame:
        frame = ttk.Frame(self.tabs, padding=8)
        self._caption(frame, "Confirmed detections. Empty is good. "
                             "Click a red row to see the full evidence.")
        cols = ("severity", "rule", "ssid", "bssid", "technique", "seen")
        self.alerts_tree = ttk.Treeview(frame, columns=cols, show="headings",
                                        selectmode="browse")
        for col, text, width in (
            ("severity", "SEVERITY", 90), ("rule", "RULE", 300),
            ("ssid", "SSID", 150), ("bssid", "BSSID", 150),
            ("technique", "ATT&CK", 100), ("seen", "HITS / LAST SEEN", 220),
        ):
            self.alerts_tree.heading(col, text=text)
            self.alerts_tree.column(col, width=width, anchor="w")
        for severity, (bg, fg) in SEVERITY_COLORS.items():
            self.alerts_tree.tag_configure(severity, background=bg, foreground=fg)

        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=scroll.set)
        self.alerts_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.alerts_tree.bind("<<TreeviewSelect>>", self._show_alert_detail)
        self.alerts_tree.bind("<Double-1>", self._show_alert_detail)
        return frame

    def _build_rules_tab(self) -> ttk.Frame:
        frame = ttk.Frame(self.tabs, padding=8)
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text="Untick a rule to disable it. Saved to {}."
                  .format(os.path.basename(self.config_path)),
                  style="Muted.TLabel").pack(side="left")
        ttk.Button(header, text="Save", command=self.on_save_rules).pack(side="right")

        body = tk.Frame(frame, bg=BG)
        body.pack(fill="both", expand=True)
        canvas = tk.Canvas(body, bg=BG, highlightthickness=0)
        inner = ttk.Frame(canvas)
        scroll = ttk.Scrollbar(body, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        window = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner(_e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", _on_inner)
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
        self._bind_mousewheel(canvas)

        cfg = Config.load(self.config_path)
        self.rule_vars: dict[str, tk.BooleanVar] = {}
        for rule in RULES.values():
            var = tk.BooleanVar(value=cfg.is_enabled(rule.rule_id))
            self.rule_vars[rule.rule_id] = var
            card = tk.Frame(inner, bg=PANEL, padx=14, pady=12,
                            highlightbackground=BORDER, highlightthickness=1)
            card.pack(fill="x", pady=6, padx=2)
            top = tk.Frame(card, bg=PANEL)
            top.pack(fill="x")
            tk.Checkbutton(top, variable=var, bg=PANEL, activebackground=PANEL,
                           selectcolor=BORDER, bd=0, highlightthickness=0).pack(side="left")
            tk.Label(top, text="{}  {}".format(rule.rule_id, rule.name), bg=PANEL,
                     fg=FG, font=MONO_BOLD).pack(side="left", padx=(6, 10))
            bg, fg = SEVERITY_COLORS[rule.severity]
            tk.Label(top, text=" {} ".format(rule.severity.upper()), bg=bg, fg=fg,
                     font=("Consolas", 8, "bold"), padx=6).pack(side="left")
            tk.Label(top, text="ATT&CK {}".format(rule.technique), bg=PANEL, fg=MUTED,
                     font=MONO).pack(side="right")
            for label, body in (("Fires when", rule.rationale),
                                ("False positives", rule.false_positives)):
                r = tk.Frame(card, bg=PANEL)
                r.pack(fill="x", pady=(6, 0))
                tk.Label(r, text=label, bg=PANEL, fg=MUTED, width=16, anchor="nw",
                         font=MONO).pack(side="left")
                tk.Label(r, text=body, bg=PANEL, fg=FG, anchor="w", justify="left",
                         wraplength=760, font=MONO).pack(side="left", fill="x", expand=True)
        return frame

    def _caption(self, parent, text: str) -> None:
        """A one-line explainer at the top of a tab, so no tab is a mystery."""
        tk.Label(parent, text="  " + text, bg=BG, fg=CYAN, anchor="w",
                 font=("Consolas", 9)).pack(fill="x", pady=(0, 6))

    def _bind_mousewheel(self, canvas: tk.Canvas) -> None:
        """Make the wheel scroll a Canvas.

        Tk only delivers wheel events to the widget under the pointer, and a
        Canvas does not scroll on the wheel by itself. Binding on Enter/Leave
        (rather than globally) means the wheel drives whichever scroll region
        the pointer is actually over, not all of them at once.
        """
        def on_wheel(event):
            canvas.yview_scroll(int(-event.delta / 120), "units")

        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", on_wheel))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, style="Panel.TFrame")
        bar.pack(fill="x", side="bottom")
        self.status = ttk.Label(bar, text="> ready", style="Status.TLabel")
        self.status.pack(side="left")
        self.baseline_label = ttk.Label(bar, text="", style="Status.TLabel")
        self.baseline_label.pack(side="right")

    # ------------------------------------------------------------ helpers

    def _set_status(self, text: str) -> None:
        self.status.configure(text="> " + text)

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.btn_baseline.configure(state=state)
        self.btn_scan.configure(state=state)
        if busy:
            self.progress.pack(fill="x", padx=12)
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def _refresh_baseline_label(self) -> None:
        with Store(self.db) as store:
            if not store.has_baseline():
                self.baseline_label.configure(text="NO BASELINE :: take one first")
                self.btn_scan.configure(state="disabled")
                self.btn_watch.configure(state="disabled")
                return
            rows = list(store.load_baseline().values())
            meta = store.baseline_meta()
        self.btn_scan.configure(state="normal")
        self.btn_watch.configure(state="normal")
        self.baseline_label.configure(text="BASELINE :: {} ({} sweeps)".format(
            baseline_mod.summarize(rows), meta.get("sweeps", "?")))

    def _run_async(self, work: Callable[[], dict]) -> None:
        if self.busy:
            return
        self._set_busy(True)

        def target() -> None:
            try:
                self.queue.put(work())
            except Exception as exc:
                self.queue.put({"kind": "error", "message": str(exc),
                                "trace": traceback.format_exc()})

        threading.Thread(target=target, daemon=True).start()

    def _drain_queue(self) -> None:
        try:
            while True:
                self._handle(self.queue.get_nowait())
        except queue.Empty:
            pass
        self.root.after(120, self._drain_queue)

    def _handle(self, msg: dict) -> None:
        kind = msg.get("kind")
        if kind == "progress":
            self._set_status(msg["message"])
            return

        self._set_busy(False)

        if kind == "error":
            self._set_status("failed: {}".format(msg["message"]))
            messagebox.showerror("wifi-sentry", msg["message"])
            return

        if kind == "baseline":
            self._refresh_baseline_label()
            self._populate_networks(msg["observations"], msg["baseline"])
            self._refresh_history()
            self._refresh_dashboard(alerts_count=0)
            self.tabs.select(1)
            # A status line, not a modal popup: the RADAR tab it jumps to
            # already shows exactly what was learned, so a dialog to dismiss
            # is just friction.
            self._set_status("baseline saved :: {} :: these are now your trusted "
                             "networks -- anything else will alert".format(msg["summary"]))
            return

        if kind == "scan":
            enriched = self._populate_networks(msg["observations"], msg["baseline"])
            self._load_alerts_from_store()
            self._refresh_history()
            self._refresh_dashboard(enriched, len(msg["events"]))
            new, repeats = msg["new_events"], msg["repeat_count"]
            if not msg["events"]:
                self._set_status("{} :: {} :: no deviations".format(
                    msg["timestamp"], msg["summary"]))
            else:
                self._set_status("{} :: {} new alert(s), {} ongoing".format(
                    msg["timestamp"], len(new), repeats))
                if new:
                    self.tabs.select(4)

        if kind == "snapshot":
            self._refresh_snapshot_lists()
            self._set_status("captured location '{}' :: {}".format(
                msg["name"], msg["summary"]))

    # ------------------------------------------------------------ commands

    def on_baseline(self) -> None:
        with Store(self.db) as store:
            existing = store.has_baseline()
        if existing and not messagebox.askyesno(
            "Replace baseline?",
            "A baseline already exists.\n\nReplace it only when you know the "
            "change was yours -- a new router, a new access point, a "
            "deliberate reconfiguration.\n\nReplace it now?"):
            return

        sweeps, delay = 3, 5
        db, iface, oui = self.db, self.interface, self.oui
        post = self.queue.put

        def work() -> dict:
            scans = []
            for i in range(sweeps):
                if i:
                    time.sleep(delay)
                post({"kind": "progress",
                      "message": "sampling the air, sweep {}/{}...".format(i + 1, sweeps)})
                scans.append(scanner.scan(iface))
            if not any(scans):
                raise scanner.ScanError("No access points seen. Is the Wi-Fi radio on?")
            rows = baseline_mod.build_rows(scans, oui)
            with Store(db) as store:
                for obs in scans:
                    store.record_scan(obs)
                store.replace_baseline(rows, {"created_at": utcnow(),
                                              "sweeps": str(len(scans)),
                                              "version": __version__})
                baseline = store.load_baseline()
            seen: dict = {}
            for obs in scans:
                for o in obs:
                    seen[(o.ssid, o.bssid)] = o
            return {"kind": "baseline", "summary": baseline_mod.summarize(rows),
                    "observations": list(seen.values()), "baseline": baseline}

        self._run_async(work)

    def on_scan(self) -> None:
        db, iface, oui, config_path = self.db, self.interface, self.oui, self.config_path
        post = self.queue.put

        def work() -> dict:
            post({"kind": "progress", "message": "scanning..."})
            obs = scanner.scan(iface)
            cfg = Config.load(config_path)
            with Store(db) as store:
                store.record_scan(obs)
                baseline = store.load_baseline()
                events = DetectionEngine(baseline, cfg, oui).run(obs)
                new = [e for e in events if store.upsert_alert(e)]
            return {"kind": "scan", "timestamp": utcnow(),
                    "summary": scanner.summarize(obs), "observations": obs,
                    "baseline": baseline, "events": events, "new_events": new,
                    "repeat_count": len(events) - len(new)}

        self._run_async(work)

    def on_capture_snapshot(self) -> None:
        name = self.snap_name.get().strip()
        if not name:
            messagebox.showwarning("wifi-sentry", "Enter a location name first.")
            return
        db, iface, oui = self.db, self.interface, self.oui
        post = self.queue.put

        def work() -> dict:
            post({"kind": "progress", "message": "capturing '{}'...".format(name)})
            obs = scanner.scan(iface)
            aps = [{"ssid": o.ssid, "bssid": o.bssid, "vendor": oui.vendor(o.bssid),
                    "channel": o.channel, "signal_dbm": o.signal_dbm,
                    "authentication": o.authentication} for o in obs]
            with Store(db) as store:
                store.record_scan(obs)
                store.save_snapshot(name, aps)
            return {"kind": "snapshot", "name": name,
                    "summary": scanner.summarize(obs)}

        self._run_async(work)

    def on_compare(self) -> None:
        a, b = self.cmp_a.get(), self.cmp_b.get()
        if not a or not b:
            messagebox.showwarning("wifi-sentry", "Pick two saved locations.")
            return
        with Store(self.db) as store:
            snap_a, snap_b = store.latest_snapshot(a), store.latest_snapshot(b)
        if not snap_a or not snap_b:
            messagebox.showerror("wifi-sentry", "One of those snapshots is missing.")
            return
        diff = diff_snapshots(snap_a["aps"], snap_b["aps"])

        self.cmp_tree.delete(*self.cmp_tree.get_children())
        for ap in sorted(diff.only_in_b, key=lambda x: x.get("signal_dbm", -100),
                         reverse=True):
            is_open = ap.get("authentication", "").lower() == "open"
            self.cmp_tree.insert("", "end", values=(
                "ONLY IN " + b, ap.get("ssid") or "<hidden>", ap["bssid"],
                "{} dBm".format(ap.get("signal_dbm", "?")),
                ap.get("authentication", "")),
                tags=("open" if is_open else "only_b",))
        for ap in diff.in_both:
            self.cmp_tree.insert("", "end", values=(
                "both", ap.get("ssid") or "<hidden>", ap["bssid"],
                "{} dBm".format(ap.get("signal_dbm", "?")),
                ap.get("authentication", "")))
        self._set_status("compare {} vs {} :: {}".format(a, b, diff.summary()))

    def on_toggle_watch(self) -> None:
        self.watching = not self.watching
        if self.watching:
            self.btn_watch.configure(text="[ STOP WATCH ]")
            self._watch_tick()
        else:
            self.btn_watch.configure(text="[ START WATCH ]")
            if self._watch_after is not None:
                self.root.after_cancel(self._watch_after)
                self._watch_after = None
            self._set_status("watch stopped")

    def _watch_tick(self) -> None:
        if not self.watching:
            return
        if not self.busy:
            self.on_scan()
        self._watch_after = self.root.after(
            max(15, self.interval.get()) * 1000, self._watch_tick)

    def on_clear_alerts(self) -> None:
        if not messagebox.askyesno(
            "Clear alerts?",
            "This clears the suppression state too, so anything still on the "
            "air will alert again on the next scan.\n\nClear?"):
            return
        with Store(self.db) as store:
            count = store.clear_alerts()
        self._load_alerts_from_store()
        self._refresh_dashboard(alerts_count=0)
        self._set_status("cleared {} alert(s)".format(count))

    def on_wipe_data(self) -> None:
        """Delete everything the tool has stored: baseline, scan history,
        alerts, and saved location snapshots. One click, no file hunting.

        Deletes the whole SQLite file rather than emptying tables, so nothing
        is left behind -- not even in free pages a DELETE would leave allocated.
        """
        if self.demo:
            messagebox.showinfo("wifi-sentry", "Stop the simulation first.")
            return
        with Store(self.live_db) as store:
            devices = len(store.device_history())
            alerts = len(store.list_alerts(limit=100000))
        if not messagebox.askyesno(
            "Wipe all data?",
            "This permanently deletes everything wifi-sentry has stored on this "
            "computer:\n\n"
            "  - your baseline (trusted networks)\n"
            "  - {} device sighting record(s)\n"
            "  - {} alert(s)\n"
            "  - all saved location snapshots\n\n"
            "Nothing is stored anywhere else, so this cannot be undone.\n\n"
            "Wipe it all now?".format(devices, alerts)):
            return

        # Drop the connection before removing the file (Windows locks open files).
        self.oui  # noqa -- keep reference; nothing to close here
        try:
            if os.path.exists(self.live_db):
                os.remove(self.live_db)
            for suffix in ("-wal", "-shm"):  # SQLite sidecar files, if any
                side = self.live_db + suffix
                if os.path.exists(side):
                    os.remove(side)
        except OSError as exc:
            messagebox.showerror(
                "wifi-sentry",
                "Could not delete the data file:\n{}\n\nClose any other window "
                "using it and try again.".format(exc))
            return

        # A fresh empty database is recreated on next access, so the app keeps
        # working -- it just knows nothing now.
        with Store(self.live_db):
            pass
        self.db = self.live_db
        self.net_tree.delete(*self.net_tree.get_children())
        self.cmp_tree.delete(*self.cmp_tree.get_children())
        self._refresh_baseline_label()
        self._load_alerts_from_store()
        self._refresh_history()
        self._refresh_snapshot_lists()
        self._refresh_dashboard()
        self.tabs.select(0)
        self._set_status("all data wiped :: the tool now knows nothing :: "
                         "take a baseline to start over")

    def on_export(self) -> None:
        with Store(self.db) as store:
            rows = store.list_alerts(limit=10000)
        if not rows:
            messagebox.showinfo("wifi-sentry", "No alerts to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".jsonl", initialfile="wifi-sentry.events.jsonl",
            filetypes=[("JSON Lines", "*.jsonl"), ("All files", "*.*")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(row["event_json"] + "\n")
        self._set_status("exported {} event(s)".format(len(rows)))

    def on_save_rules(self) -> None:
        cfg = Config.load(self.config_path)
        cfg.disabled_rules = [rid for rid, var in self.rule_vars.items() if not var.get()]
        cfg.save(self.config_path)
        self._set_status("saved :: {} rule(s) disabled".format(len(cfg.disabled_rules)))

    # Simulation mode. It builds an evil twin of YOUR OWN strongest network
    # from your real baseline -- no invented "Starbucks"/"TrustedNet" networks -- and
    # runs the detections against a throwaway database so your live data is
    # never touched. Nothing is transmitted; the rogue row exists only in that
    # temporary DB. This is how you see a detection without a real attacker.
    def _sim_source_baseline(self) -> dict:
        """The baseline to clone from: the user's real one, or the demo
        fixtures as a fallback when they have not baselined yet."""
        with Store(self.live_db) as store:
            if store.has_baseline():
                return store.load_baseline()
        fixture = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "tests", "fixtures", "netsh_baseline.txt")
        obs = scanner.scan_from_file(fixture)
        return {(r["ssid"], r["bssid"]): r
                for r in baseline_mod.build_rows([obs], self.oui)}

    @staticmethod
    def _obs_from_baseline_row(row: dict) -> Observation:
        pct = max(0, min(100, (row["max_signal_dbm"] + 100) * 2))
        channel = row["channels"][0] if row["channels"] else 0
        return Observation(row["ssid"], row["bssid"], channel, pct,
                           row["authentication"], row["encryption"])

    def on_toggle_demo(self) -> None:
        if self.demo:
            self._exit_demo()
            return

        source = self._sim_source_baseline()
        named = [r for (ssid, _b), r in source.items() if ssid]
        if not named:
            messagebox.showinfo(
                "wifi-sentry",
                "Take a baseline first -- the simulation clones an evil twin of "
                "your own strongest network, so it needs to know what that is.")
            return

        # Clone the loudest named network the user actually has: an open twin
        # from a software-generated MAC, broadcasting louder than the original.
        target = max(named, key=lambda r: r["max_signal_dbm"])
        twin = Observation(
            ssid=target["ssid"], bssid=SIM_ROGUE_BSSID,
            channel=target["channels"][0] if target["channels"] else 6,
            signal_percent=99, authentication="Open", encryption="None",
            radio_type="802.11n", band="2.4 GHz")
        real_obs = [self._obs_from_baseline_row(r) for r in source.values()]
        attack_obs = real_obs + [twin]

        demo_db = os.path.join(os.path.dirname(os.path.abspath(self.db)) or ".",
                               "wifi-sentry.sim.db")
        if os.path.exists(demo_db):
            os.remove(demo_db)
        with Store(demo_db) as store:
            for o in real_obs:
                store.record_scan([o])
            store.replace_baseline(list(source.values()),
                                   {"created_at": utcnow(), "sweeps": "sim",
                                    "version": __version__})
            store.record_scan(attack_obs)
            baseline = store.load_baseline()
            events = DetectionEngine(baseline, Config(), self.oui).run(attack_obs)
            for event in events:
                store.upsert_alert(event)

        self.demo = True
        self.db = demo_db
        self.btn_demo.configure(text="[ STOP SIMULATION ]")
        self.root.title("wifi-sentry :: SIMULATION -- synthetic evil twin of "
                        "your own network")
        for btn in (self.btn_baseline, self.btn_scan, self.btn_watch):
            btn.configure(state="disabled")
        enriched = self._populate_networks(attack_obs, baseline)
        self._load_alerts_from_store()
        self._refresh_dashboard(enriched, len(events))
        self.baseline_label.configure(text="SIMULATION :: not live")
        self._set_status(
            "simulation :: a fake open twin of YOUR network '{}' :: {} alerts :: "
            "click a red row".format(target["ssid"], len(events)))
        self.tabs.select(4)

    def _exit_demo(self) -> None:
        self.demo = False
        self.db = self.live_db
        self.btn_demo.configure(text="[ SIMULATE ATTACK ]")
        self.root.title("wifi-sentry {} :: rogue AP monitor".format(__version__))
        self.btn_baseline.configure(state="normal")
        self.net_tree.delete(*self.net_tree.get_children())
        self._refresh_baseline_label()
        self._load_alerts_from_store()
        self._refresh_dashboard()
        self._refresh_history()
        self._set_status("back to live data")

    # -------------------------------------------------------------- render

    def _populate_networks(self, observations, baseline) -> list:
        enriched = enrich_all(observations, self.oui, baseline)
        self.net_tree.delete(*self.net_tree.get_children())
        self._net_details.clear()
        for e in enriched:
            o = e.obs
            item = self.net_tree.insert("", "end", values=(
                "{:>3} {}".format(e.risk.score, e.risk.band),
                "NEW" if e.is_new else "",
                o.ssid or "<hidden>", o.bssid, e.device.device_type, e.proximity,
                "{:>3}% {}".format(o.signal_percent, distance.bars(o.signal_percent)),
                o.authentication or "-"),
                tags=(e.risk.band,))
            self._net_details[item] = self._network_detail_text(e)
        return enriched

    @staticmethod
    def _network_detail_text(e) -> str:
        o = e.obs
        lines = [
            "{}  ({})".format(o.ssid or "<hidden>", o.bssid),
            "",
            "Risk score   {}/100  [{}]".format(e.risk.score, e.risk.band),
            "Device type  {}  (confidence: {})".format(e.device.device_type,
                                                        e.device.confidence),
            "Vendor       {}".format(e.vendor),
            "Proximity    {}  (~{} m, {} dBm) -- estimate".format(
                e.proximity, distance.estimate_distance_m(o.signal_dbm), o.signal_dbm),
            "Channel      {}   Band {}   Radio {}".format(
                o.channel, o.band or "?", o.radio_type or "?"),
            "Auth         {} / {}".format(o.authentication or "-", o.encryption or "-"),
            "In baseline  {}".format("no -- NEW device" if e.is_new else "yes"),
            "",
            "Why this device type:",
        ]
        lines += ["  - " + r for r in e.device.reasons]
        lines += ["", "Risk factors:"]
        lines += ["  " + f for f in e.risk.factors]
        return "\n".join(lines)

    def _show_network_detail(self, _event=None) -> None:
        sel = self.net_tree.selection()
        if sel:
            self._detail_window("Network detail", self._net_details.get(sel[0], ""))

    def _refresh_history(self) -> None:
        cutoff = _iso_days_ago(1)
        with Store(self.db) as store:
            rows = store.device_history()
        self.hist_tree.delete(*self.hist_tree.get_children())
        for r in rows:
            is_new = r["first_seen"] >= cutoff
            self.hist_tree.insert("", "end", values=(
                "NEW" if is_new else "", r["ssid"] or "<hidden>", r["bssid"],
                r["sightings"], r["first_seen"], r["last_seen"]),
                tags=("new",) if is_new else ())

    def _refresh_snapshot_lists(self) -> None:
        with Store(self.db) as store:
            names = [r["name"] for r in store.list_snapshots()]
        # De-dupe while preserving most-recent-first order.
        seen, unique = set(), []
        for n in names:
            if n not in seen:
                seen.add(n)
                unique.append(n)
        self.cmp_a["values"] = unique
        self.cmp_b["values"] = unique

    def _refresh_dashboard(self, enriched=None, alerts_count=None) -> None:
        with Store(self.db) as store:
            history = store.device_history()
            if alerts_count is None:
                alerts_count = len(store.list_alerts(limit=10000))
        cutoff = _iso_days_ago(1)
        new_count = sum(1 for r in history if r["first_seen"] >= cutoff)

        self.stat_cards["networks"].configure(text=str(len(history)))
        self.stat_cards["alerts"].configure(
            text=str(alerts_count),
            fg="#ff5c5c" if alerts_count else FG)
        self.stat_cards["new"].configure(text=str(new_count))

        top = ""
        if enriched:
            top = "{} {}".format(enriched[0].risk.score, enriched[0].risk.band)
        self.stat_cards["toprisk"].configure(
            text=top or "--",
            fg="#ff5c5c" if enriched and enriched[0].risk.score >= 75 else FG)

        self.dash_box.configure(state="normal")
        self.dash_box.delete("1.0", "end")
        if not enriched:
            with Store(self.db) as store:
                has_base = store.has_baseline()
            if not has_base:
                self.dash_box.insert("1.0",
                    "  GETTING STARTED\n"
                    "  " + "-" * 60 + "\n\n"
                    "  1.  Click [ TAKE BASELINE ]  -- learn the networks that are\n"
                    "      normally around you (sit still, ~15 seconds).\n\n"
                    "  2.  Click [ SCAN NOW ]       -- check for anything new or\n"
                    "      suspicious. Findings appear on the ALERTS tab.\n\n"
                    "  Curious first?  Click [ SIMULATE ATTACK ] to see what a\n"
                    "  rogue clone of your own network would look like.")
            else:
                self.dash_box.insert("1.0",
                    "  Baseline is set. Click [ SCAN NOW ] to check for deviations,\n"
                    "  or [ SIMULATE ATTACK ] to preview a detection.")
        else:
            self.dash_box.insert("1.0", "  {:>4}  {:<9} {:<20} {:<18} {}\n".format(
                "RISK", "BAND", "SSID", "BSSID", "DEVICE TYPE"))
            self.dash_box.insert("end", "  " + "-" * 78 + "\n")
            for e in enriched[:10]:
                self.dash_box.insert("end", "  {:>4}  {:<9} {:<20} {:<18} {}\n".format(
                    e.risk.score, e.risk.band, (e.obs.ssid or "<hidden>")[:20],
                    e.obs.bssid, e.device.device_type))
        self.dash_box.configure(state="disabled")

    def _load_alerts_from_store(self) -> None:
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        self._alert_details.clear()
        with Store(self.db) as store:
            rows = store.list_alerts(limit=500)
        rows = sorted(rows, key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9),
                                           r["rule_id"]))
        for row in rows:
            data = json.loads(row["event_json"])
            item = self.alerts_tree.insert("", "end", values=(
                row["severity"].upper(),
                "{}  {}".format(row["rule_id"], data.get("rule_name", "")),
                row["ssid"] or "<hidden>", row["bssid"] or "-",
                data.get("technique", ""),
                "{}x  last {}".format(row["hit_count"], row["last_seen"])),
                tags=(row["severity"],))
            self._alert_details[item] = self._alert_detail_text(data, row)

    @staticmethod
    def _alert_detail_text(data: dict, row) -> str:
        lines = [
            "{}  {}".format(data.get("rule_id"), data.get("rule_name")), "",
            data.get("message", ""), "",
            "Severity     {}".format(data.get("severity")),
            "ATT&CK       {} - {}".format(data.get("technique"),
                                          data.get("technique_name")),
            "SSID         {}".format(data.get("ssid") or "<hidden>"),
            "BSSID        {}".format(data.get("bssid") or "-"),
            "First seen   {}".format(row["first_seen"]),
            "Last seen    {}".format(row["last_seen"]),
            "Hit count    {}".format(row["hit_count"]), "", "Evidence",
        ]
        for key, value in sorted(data.get("details", {}).items()):
            lines.append("  {:<22} {}".format(key, json.dumps(value)))
        rule = RULES.get(data.get("rule_id", ""))
        if rule:
            lines += ["", "Known false positives", "  " + rule.false_positives]
        return "\n".join(lines)

    def _show_alert_detail(self, _event=None) -> None:
        sel = self.alerts_tree.selection()
        if sel:
            self._detail_window("Alert detail", self._alert_details.get(sel[0], ""))

    def _detail_window(self, title: str, text: str) -> None:
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=BG)
        win.geometry("760x560")
        box = tk.Text(win, bg=PANEL, fg=FG, insertbackground=FG, wrap="word",
                      relief="flat", padx=16, pady=14, font=MONO)
        box.pack(fill="both", expand=True, padx=12, pady=12)
        box.insert("1.0", text)
        box.configure(state="disabled")
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=(0, 12))


def launch(db: str, config_path: str = DEFAULT_CONFIG_NAME,
           oui_file: str | None = None, interface: str | None = None) -> int:
    root = tk.Tk()
    WifiSentryApp(root, db, config_path, oui_file, interface)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch("wifi-sentry.db"))
