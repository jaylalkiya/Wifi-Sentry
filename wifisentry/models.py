"""Core data structures shared by the scanner, store, and detection engine."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def utcnow() -> str:
    """ISO-8601 UTC timestamp, second precision, always suffixed with Z."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def signal_percent_to_dbm(percent: int) -> int:
    """Windows reports signal quality as 0-100%. Convert to approximate dBm.

    The mapping Microsoft documents is linear across -100 dBm (0%) to -50 dBm
    (100%), so dBm = percent/2 - 100. It is an approximation, not a measurement,
    but it is monotonic -- which is all the signal-anomaly rule needs.
    """
    return int(percent / 2) - 100


@dataclass
class Observation:
    """One access point seen in one scan.

    An SSID broadcasting from three radios produces three Observations: the
    BSSID (the radio's MAC) is the real identity, the SSID is just a label
    anyone can copy. Every detection in this project rests on that distinction.
    """

    ssid: str
    bssid: str
    channel: int
    signal_percent: int
    authentication: str
    encryption: str
    radio_type: str = ""
    band: str = ""
    seen_at: str = field(default_factory=utcnow)

    @property
    def signal_dbm(self) -> int:
        return signal_percent_to_dbm(self.signal_percent)

    @property
    def is_hidden(self) -> bool:
        return self.ssid == ""

    @property
    def is_open(self) -> bool:
        return self.authentication.strip().lower() == "open"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["signal_dbm"] = self.signal_dbm
        return d


@dataclass
class Event:
    """A normalized detection event.

    Field names deliberately follow the ECS-style shape most SIEMs expect, so
    the JSONL output can be ingested without a bespoke parser: rule_id,
    severity, technique (MITRE ATT&CK), entity, and a details bag.
    """

    rule_id: str
    rule_name: str
    severity: str  # low | medium | high | critical
    technique: str  # MITRE ATT&CK technique ID, e.g. T1557
    technique_name: str
    message: str
    ssid: str = ""
    bssid: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utcnow)
    source: str = "wifi-sentry"

    @property
    def dedupe_key(self) -> str:
        """Stable identity for suppression: same rule + same AP = same alert.

        Excludes the timestamp and any volatile detail (signal, channel) on
        purpose. Without this, a rogue AP that stays powered on would re-alert
        on every single scan and bury the analyst -- the classic reason a noisy
        detection gets switched off entirely.
        """
        raw = f"{self.rule_id}|{self.ssid}|{self.bssid}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["dedupe_key"] = self.dedupe_key
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)
