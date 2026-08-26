"""Build the 'what normal looks like' snapshot the detections compare against.

A baseline taken from a single scan is a bad baseline: signal strength swings
several dB between sweeps, band-steering APs come and go, and a neighbour's
phone hotspot may be up for one scan only. Sampling over several sweeps and
recording a signal *range* rather than a point value is what keeps the
signal-anomaly and evil-twin rules from screaming on day two.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from .models import Observation, utcnow
from .oui import OuiLookup


def build_rows(
    scans: Sequence[Sequence[Observation]], oui: OuiLookup
) -> list[dict]:
    """Aggregate several scans into one baseline row per (SSID, BSSID)."""
    acc: dict[tuple[str, str], dict] = {}

    for observations in scans:
        for o in observations:
            key = (o.ssid, o.bssid)
            row = acc.get(key)
            if row is None:
                acc[key] = {
                    "ssid": o.ssid,
                    "bssid": o.bssid,
                    "vendor": oui.vendor(o.bssid),
                    "channels": {o.channel},
                    "authentication": o.authentication,
                    "encryption": o.encryption,
                    "min_signal_dbm": o.signal_dbm,
                    "max_signal_dbm": o.signal_dbm,
                    "sample_count": 1,
                    "created_at": utcnow(),
                }
                continue

            row["channels"].add(o.channel)
            row["min_signal_dbm"] = min(row["min_signal_dbm"], o.signal_dbm)
            row["max_signal_dbm"] = max(row["max_signal_dbm"], o.signal_dbm)
            row["sample_count"] += 1

    for row in acc.values():
        row["channels"] = sorted(row["channels"])
    return list(acc.values())


def summarize(rows: Iterable[dict]) -> str:
    rows = list(rows)
    ssids = {r["ssid"] for r in rows if r["ssid"]}
    hidden = sum(1 for r in rows if not r["ssid"])
    return (
        f"{len(rows)} access points, {len(ssids)} named SSIDs"
        + (f", {hidden} hidden" if hidden else "")
    )


def index_by_ssid(baseline: dict[tuple[str, str], dict]) -> dict[str, list[dict]]:
    """Group baseline rows by SSID -- the evil-twin rule's primary lookup."""
    out: dict[str, list[dict]] = {}
    for (ssid, _bssid), row in baseline.items():
        out.setdefault(ssid, []).append(row)
    return out


def index_by_bssid(baseline: dict[tuple[str, str], dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for (_ssid, bssid), row in baseline.items():
        out.setdefault(bssid, []).append(row)
    return out
