"""Command line interface.

    python -m wifisentry baseline      learn what is normally on the air
    python -m wifisentry scan          one sweep, evaluate rules, alert
    python -m wifisentry watch         scan on an interval
    python -m wifisentry alerts        show stored alert state
    python -m wifisentry rules         list rules and ATT&CK coverage
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Sequence

from . import __version__, baseline as baseline_mod, emit, scanner
from .config import Config, DEFAULT_CONFIG_NAME
from .detections import RULES, SEVERITY_ORDER, DetectionEngine
from .models import Observation, utcnow
from .oui import OuiLookup
from .store import Store

DEFAULT_DB = "wifi-sentry.db"
DEFAULT_JSONL = "wifi-sentry.events.jsonl"


# ----------------------------------------------------------------- collection


def _collect(args: argparse.Namespace, sweeps: int, delay: int) -> list[list[Observation]]:
    """Run `sweeps` scans, or replay saved netsh captures instead.

    Replay exists so the detections can be developed and tested without a
    radio, and so a demo is reproducible -- you cannot screenshot an evil twin
    for a portfolio if you have to conjure one on demand.
    """
    if args.replay:
        return [scanner.scan_from_file(p) for p in args.replay]

    scans: list[list[Observation]] = []
    for i in range(sweeps):
        if i:
            time.sleep(delay)
        obs = scanner.scan(args.interface)
        print("  sweep {}/{}: {}".format(i + 1, sweeps, scanner.summarize(obs)))
        scans.append(obs)
    return scans


def _engine(args: argparse.Namespace, store: Store) -> DetectionEngine:
    return DetectionEngine(
        baseline=store.load_baseline(),
        config=Config.load(args.config),
        oui=OuiLookup.from_file(args.oui_file),
    )


# ------------------------------------------------------------------- commands


def cmd_baseline(args: argparse.Namespace) -> int:
    oui = OuiLookup.from_file(args.oui_file)

    with Store(args.db) as store:
        if store.has_baseline() and not args.force:
            print("A baseline already exists. Re-run with --force to replace it.",
                  file=sys.stderr)
            print("Do that only when you know the change was yours -- a new "
                  "router, a new AP, a deliberate reconfiguration.", file=sys.stderr)
            return 1

        print("Sampling the air {} times, {}s apart ...".format(args.sweeps, args.delay))
        scans = _collect(args, args.sweeps, args.delay)
        if not any(scans):
            print("No access points seen. Is the Wi-Fi radio on?", file=sys.stderr)
            return 1

        for obs in scans:
            store.record_scan(obs)

        rows = baseline_mod.build_rows(scans, oui)
        store.replace_baseline(rows, {
            "created_at": utcnow(),
            "sweeps": str(len(scans)),
            "version": __version__,
        })

    print("\nBaseline saved to {}: {}".format(args.db, baseline_mod.summarize(rows)))
    print("Anything that deviates from this is what the rules will alert on.")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    with Store(args.db) as store:
        if not store.has_baseline():
            print("No baseline yet. Run 'baseline' first.", file=sys.stderr)
            return 1

        scans = _collect(args, 1, 0)
        obs = scans[0]
        store.record_scan(obs)

        events = _engine(args, store).run(obs)

        # Split before printing: repeats are counted, not shown, so a rogue AP
        # left running does not produce a fresh wall of alerts every sweep.
        new = [e for e in events if store.upsert_alert(e)]
        repeats = len(events) - len(new)

    print("\n{} -- {}".format(utcnow(), scanner.summarize(obs)))

    if not events:
        print("No deviations from baseline.")
        return 0

    if new:
        print()
        emit.print_events(new)
        if args.jsonl:
            emit.write_jsonl(new, args.jsonl)
            print("\n{} event(s) appended to {}".format(len(new), args.jsonl))
    if repeats:
        print("\n{} ongoing alert(s) suppressed (already known; see 'alerts')."
              .format(repeats))

    worst = min(SEVERITY_ORDER.get(e.severity, 9) for e in events)
    return 2 if worst <= 1 else 0  # non-zero exit lets Task Scheduler notice


def cmd_watch(args: argparse.Namespace) -> int:
    print("Watching every {}s. Ctrl-C to stop.".format(args.interval))
    try:
        while True:
            cmd_scan(args)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    with Store(args.db) as store:
        if args.clear:
            print("Cleared {} alert(s).".format(store.clear_alerts()))
            return 0
        rows = store.list_alerts(args.limit)

    if not rows:
        print("No alerts recorded.")
        return 0

    print("{:<10} {:<9} {:<18} {:<6} {}".format(
        "RULE", "SEVERITY", "BSSID", "HITS", "SSID"))
    for r in rows:
        print("{:<10} {:<9} {:<18} {:<6} {}".format(
            r["rule_id"], r["severity"], r["bssid"] or "-", r["hit_count"],
            r["ssid"] or "<hidden>"))
        print("     first {}   last {}".format(r["first_seen"], r["last_seen"]))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    cfg = Config.load(args.config)
    for rule in RULES.values():
        state = "enabled" if cfg.is_enabled(rule.rule_id) else "DISABLED"
        print("{}  {}  [{}]  ({})".format(
            rule.rule_id, rule.name, rule.severity, state))
        print("  ATT&CK        {} - {}".format(rule.technique, rule.technique_name))
        print("  Fires when    {}".format(rule.rationale))
        print("  False pos.    {}".format(rule.false_positives))
        print()
    techniques = sorted({r.technique for r in RULES.values()})
    print("{} rules covering {} ATT&CK techniques: {}".format(
        len(RULES), len(techniques), ", ".join(techniques)))
    return 0


def cmd_init_config(args: argparse.Namespace) -> int:
    path = args.config or DEFAULT_CONFIG_NAME
    if os.path.exists(path) and not args.force:
        print("{} already exists. Use --force to overwrite.".format(path),
              file=sys.stderr)
        return 1
    Config().save(path)
    print("Wrote {}. Tune allowlists there rather than deleting rules."
          .format(path))
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    from datetime import datetime, timedelta, timezone

    since = None
    if args.days:
        since = (datetime.now(timezone.utc) - timedelta(days=args.days)) \
            .replace(microsecond=0).isoformat().replace("+00:00", "Z")

    with Store(args.db) as store:
        if args.new:
            if not since:
                since = (datetime.now(timezone.utc) - timedelta(days=7)) \
                    .replace(microsecond=0).isoformat().replace("+00:00", "Z")
            rows = store.new_devices_since(since)
            print("Devices first seen since {}:\n".format(since))
        else:
            rows = store.device_history(since)

    if not rows:
        print("No matching device history.")
        return 0

    print("{:<24} {:<18} {:<8} {}".format("SSID", "BSSID", "SEEN", "FIRST -> LAST"))
    for r in rows:
        print("{:<24} {:<18} {:<8} {} -> {}".format(
            (r["ssid"] or "<hidden>")[:24], r["bssid"], r["sightings"],
            r["first_seen"], r["last_seen"]))
    print("\n{} device(s).".format(len(rows)))
    return 0


def _scan_to_aps(obs, oui) -> list[dict]:
    return [
        {"ssid": o.ssid, "bssid": o.bssid, "vendor": oui.vendor(o.bssid),
         "channel": o.channel, "signal_dbm": o.signal_dbm,
         "authentication": o.authentication}
        for o in obs
    ]


def cmd_snapshot(args: argparse.Namespace) -> int:
    oui = OuiLookup.from_file(args.oui_file)
    with Store(args.db) as store:
        if args.list:
            rows = store.list_snapshots()
            if not rows:
                print("No snapshots saved.")
                return 0
            import json
            for r in rows:
                print("{:<16} {}  ({} APs)".format(
                    r["name"], r["created_at"], len(json.loads(r["ap_json"]))))
            return 0

        print("Capturing location '{}' ...".format(args.name))
        obs = _collect(args, 1, 0)[0]
        store.record_scan(obs)
        store.save_snapshot(args.name, _scan_to_aps(obs, oui))
    print("Saved snapshot '{}': {}".format(args.name, scanner.summarize(obs)))
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    from .compare import diff_snapshots
    from .risk import score_observation

    with Store(args.db) as store:
        snap_a = store.latest_snapshot(args.location_a)
        snap_b = store.latest_snapshot(args.location_b)
    if snap_a is None:
        print("No snapshot named '{}'. Run: snapshot {}".format(
            args.location_a, args.location_a), file=sys.stderr)
        return 1
    if snap_b is None:
        print("No snapshot named '{}'. Run: snapshot {}".format(
            args.location_b, args.location_b), file=sys.stderr)
        return 1

    diff = diff_snapshots(snap_a["aps"], snap_b["aps"])
    print("Comparing A='{}' ({}) vs B='{}' ({})\n{}\n".format(
        args.location_a, snap_a["created_at"], args.location_b,
        snap_b["created_at"], diff.summary()))

    if diff.only_in_b:
        print("Networks present at '{}' but NOT at '{}' "
              "(where a rogue AP would hide):".format(args.location_b, args.location_a))
        for ap in sorted(diff.only_in_b, key=lambda a: a.get("signal_dbm", -100),
                         reverse=True):
            flag = "  <-- OPEN" if ap.get("authentication", "").lower() == "open" else ""
            print("  {:<24} {:<18} {:>4} dBm  {}{}".format(
                (ap.get("ssid") or "<hidden>")[:24], ap["bssid"],
                ap.get("signal_dbm", "?"), ap.get("authentication", ""), flag))
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    # Imported lazily: Tkinter is absent from some slim Python builds, and the
    # CLI must keep working there.
    try:
        from .gui import launch
    except ImportError as exc:
        print("Tkinter is unavailable in this Python install ({}). "
              "The command-line interface still works.".format(exc), file=sys.stderr)
        return 1
    return launch(args.db, args.config, args.oui_file, args.interface)


def cmd_capture(args: argparse.Namespace) -> int:
    """Save raw netsh output -- useful for test fixtures and offline debugging."""
    text = scanner.run_netsh(args.interface)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(text)
    obs = scanner.parse_netsh_output(text)
    print("Wrote {} ({})".format(args.output, scanner.summarize(obs)))
    return 0


# --------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wifisentry",
        description="Rogue access point monitor. Passive; never transmits.",
    )
    p.add_argument("--version", action="version", version="wifi-sentry " + __version__)
    p.add_argument("--db", default=DEFAULT_DB, help="SQLite database path")
    p.add_argument("--config", default=DEFAULT_CONFIG_NAME, help="tuning/allowlist JSON")
    p.add_argument("--oui-file", default=None,
                   help="IEEE oui.txt for full vendor coverage")
    p.add_argument("--interface", default=None, help="WLAN interface name")
    # append rather than nargs="+", otherwise a greedy file list swallows the
    # subcommand name: `--replay a.txt scan` would read "scan" as a filename.
    p.add_argument("--replay", action="append", metavar="FILE", default=None,
                   help="parse saved netsh output instead of scanning; "
                        "repeat the flag to supply several sweeps")

    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("baseline", help="learn the normal RF environment")
    b.add_argument("--sweeps", type=int, default=3)
    b.add_argument("--delay", type=int, default=5, help="seconds between sweeps")
    b.add_argument("--force", action="store_true", help="replace an existing baseline")
    b.set_defaults(func=cmd_baseline)

    s = sub.add_parser("scan", help="one sweep, evaluate rules")
    s.add_argument("--jsonl", nargs="?", const=DEFAULT_JSONL, default=None,
                   help="append new events to this JSONL file")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="scan repeatedly")
    w.add_argument("--interval", type=int, default=60, help="seconds between scans")
    w.add_argument("--jsonl", nargs="?", const=DEFAULT_JSONL, default=None)
    w.set_defaults(func=cmd_watch)

    a = sub.add_parser("alerts", help="show recorded alert state")
    a.add_argument("--limit", type=int, default=50)
    a.add_argument("--clear", action="store_true")
    a.set_defaults(func=cmd_alerts)

    r = sub.add_parser("rules", help="list detection rules and ATT&CK coverage")
    r.set_defaults(func=cmd_rules)

    c = sub.add_parser("init-config", help="write a default tuning config")
    c.add_argument("--force", action="store_true")
    c.set_defaults(func=cmd_init_config)

    h = sub.add_parser("history", help="devices seen over time")
    h.add_argument("--days", type=int, default=None, help="limit to the last N days")
    h.add_argument("--new", action="store_true",
                   help="only devices first seen in the window (default 7 days)")
    h.set_defaults(func=cmd_history)

    sn = sub.add_parser("snapshot", help="capture a named location for later comparison")
    sn.add_argument("name", nargs="?", default=None, help="location name, e.g. home")
    sn.add_argument("--list", action="store_true", help="list saved snapshots")
    sn.set_defaults(func=cmd_snapshot)

    cmp = sub.add_parser("compare", help="diff two location snapshots")
    cmp.add_argument("location_a")
    cmp.add_argument("location_b")
    cmp.set_defaults(func=cmd_compare)

    g = sub.add_parser("gui", help="open the desktop interface")
    g.set_defaults(func=cmd_gui)

    cap = sub.add_parser("capture", help="save raw netsh output to a file")
    cap.add_argument("output")
    cap.set_defaults(func=cmd_capture)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except scanner.ScanError as exc:
        print("Scan failed: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
