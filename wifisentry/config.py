"""Tuning knobs and allowlists -- the false-positive control surface.

Everything here exists because a rule that cannot be tuned gets muted, and a
muted rule detects nothing. The defaults are deliberately conservative for a
home network; a mesh or enterprise WLAN needs the allowlists populated.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any

DEFAULT_CONFIG_NAME = "wifi-sentry.config.json"


@dataclass
class Config:
    # SSIDs to ignore entirely (neighbours, guest networks you don't own).
    ignore_ssids: list[str] = field(default_factory=list)

    # BSSIDs known to be legitimate even though a rule would flag them.
    # Populate this with your mesh nodes and band-steering radios.
    allow_bssids: list[str] = field(default_factory=list)

    # SSIDs that legitimately run many BSSIDs (mesh, enterprise controllers).
    # Evil-twin severity drops to 'low' for these instead of firing 'critical'.
    multi_ap_ssids: list[str] = field(default_factory=list)

    # Signal must move more than this many dB outside the baseline range
    # before WIFI-005 fires. 12 dB is roughly "moved to another room".
    signal_delta_db: int = 12

    # WIFI-006 fires when a single scan introduces more than this many
    # previously-unseen SSIDs at once.
    beacon_flood_threshold: int = 8

    # Rules to disable outright, e.g. ["WIFI-005"].
    disabled_rules: list[str] = field(default_factory=list)

    def is_ignored_ssid(self, ssid: str) -> bool:
        return ssid.lower() in {s.lower() for s in self.ignore_ssids}

    def is_allowed_bssid(self, bssid: str) -> bool:
        return bssid.lower() in {b.lower() for b in self.allow_bssids}

    def is_multi_ap(self, ssid: str) -> bool:
        return ssid.lower() in {s.lower() for s in self.multi_ap_ssids}

    def is_enabled(self, rule_id: str) -> bool:
        return rule_id not in self.disabled_rules

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def load(cls, path: str | None) -> "Config":
        """Load config, falling back to defaults when the file is absent."""
        if not path or not os.path.exists(path):
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        known = {f for f in cls().to_dict()}
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
            fh.write("\n")
