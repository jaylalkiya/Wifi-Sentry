"""Detection rules.

Each rule is a small function over (this scan, the baseline, config) that
returns zero or more Events. They are written as separate functions rather than
one big loop so that each can be tested, tuned, and disabled independently --
the same reason a SIEM keeps rules out of the parser.

Every rule carries a MITRE ATT&CK technique so alerts land somewhere on a
coverage map instead of being free-floating strings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from .baseline import index_by_ssid
from .config import Config
from .models import Event, Observation
from .oui import OuiLookup, is_locally_administered

# Ordered weakest -> strongest. Used only for relative comparison, so the exact
# numbers do not matter; the ordering does.
_AUTH_STRENGTH = [
    ("open", 0),
    ("wep", 1),
    ("shared", 1),
    ("wpa-personal", 2),
    ("wpa-enterprise", 3),
    ("wpa2-personal", 4),
    ("wpa2-enterprise", 5),
    ("wpa3-personal", 6),
    ("wpa3-sae", 6),
    ("wpa3-enterprise", 7),
]


def auth_strength(auth: str) -> int:
    """Rank an authentication string. Unknown values return -1 (never compared)."""
    a = auth.strip().lower()
    for name, score in _AUTH_STRENGTH:
        if a == name:
            return score
    for name, score in _AUTH_STRENGTH:  # tolerate 'WPA2-Personal (PSK)' etc.
        if a.startswith(name):
            return score
    return -1


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    name: str
    severity: str
    technique: str
    technique_name: str
    rationale: str
    false_positives: str


RULES: dict[str, RuleMeta] = {
    "WIFI-001": RuleMeta(
        "WIFI-001", "Evil twin: known SSID on an unknown BSSID", "critical",
        "T1557.004", "Adversary-in-the-Middle: Evil Twin",
        "An SSID from the baseline is being broadcast by a radio that was not "
        "present when the baseline was taken.",
        "Mesh nodes, band-steering radios, and a genuinely new AP all look "
        "identical to this rule. Add legitimate SSIDs to multi_ap_ssids and "
        "new radios to allow_bssids, then re-baseline.",
    ),
    "WIFI-002": RuleMeta(
        "WIFI-002", "Encryption downgrade on a known SSID", "critical",
        "T1557", "Adversary-in-the-Middle",
        "A baselined SSID is now advertising weaker authentication than it did "
        "before -- classically an open clone of a WPA2 network.",
        "A deliberate router reconfiguration or an added guest network reusing "
        "the SSID. Re-baseline after any intentional change.",
    ),
    "WIFI-003": RuleMeta(
        "WIFI-003", "Unexpected radio vendor for a known SSID", "high",
        "T1557.004", "Adversary-in-the-Middle: Evil Twin",
        "The BSSID's OUI belongs to a different manufacturer than the rest of "
        "that SSID's radios, or is locally-administered (software-generated).",
        "Hardware replaced with a different brand; a mixed-vendor WLAN. The "
        "built-in OUI table is small -- load IEEE oui.txt to cut noise.",
    ),
    "WIFI-004": RuleMeta(
        "WIFI-004", "Known BSSID changed channel", "medium",
        "T1557", "Adversary-in-the-Middle",
        "A baselined radio appeared on a channel outside its baseline set.",
        "Auto-channel selection and DFS radar avoidance move APs legitimately. "
        "This rule is corroborating evidence, not a standalone alert.",
    ),
    "WIFI-005": RuleMeta(
        "WIFI-005", "Signal strength anomaly for a known BSSID", "medium",
        "T1557.004", "Adversary-in-the-Middle: Evil Twin",
        "A baselined radio is far louder or quieter than it has ever been, "
        "which can mean something closer is transmitting its BSSID.",
        "You moved the laptop. This rule is only meaningful from a fixed "
        "location; disable it on a machine that roams.",
    ),
    "WIFI-006": RuleMeta(
        "WIFI-006", "Beacon flood: many new SSIDs at once", "high",
        "T1498", "Network Denial of Service",
        "A single sweep introduced an implausible number of never-before-seen "
        "SSIDs, the signature of a beacon-flood tool.",
        "Walking into a dense area (airport, apartment block) with a laptop "
        "that has a stale baseline.",
    ),
    "WIFI-007": RuleMeta(
        "WIFI-007", "One BSSID broadcasting multiple SSIDs", "high",
        "T1557.004", "Adversary-in-the-Middle: Evil Twin",
        "Real multi-SSID access points assign each network its own BSSID. One "
        "radio answering to several SSIDs suggests a KARMA-style responder.",
        "Some cheap consumer APs and phone hotspots do reuse the same BSSID "
        "across bands. Allowlist them once confirmed.",
    ),
}


def _event(meta: RuleMeta, message: str, *, ssid: str = "", bssid: str = "",
           severity: str | None = None, **details: object) -> Event:
    return Event(
        rule_id=meta.rule_id,
        rule_name=meta.name,
        severity=severity or meta.severity,
        technique=meta.technique,
        technique_name=meta.technique_name,
        message=message,
        ssid=ssid,
        bssid=bssid,
        details=dict(details),
    )


def _label(ssid: str) -> str:
    return ssid if ssid else "<hidden>"


# --------------------------------------------------------------------- rules


def rule_evil_twin(obs: Sequence[Observation], baseline: dict, cfg: Config,
                   oui: OuiLookup) -> list[Event]:
    meta = RULES["WIFI-001"]
    by_ssid = index_by_ssid(baseline)
    events: list[Event] = []
    for o in obs:
        if not o.ssid or o.ssid not in by_ssid:
            continue  # hidden, or an SSID we never baselined -- not this rule's job
        if (o.ssid, o.bssid) in baseline:
            continue
        known = [r["bssid"] for r in by_ssid[o.ssid]]
        # A multi-AP SSID legitimately grows radios, so downgrade rather than
        # suppress: the analyst still sees it, it just does not page anyone.
        severity = "low" if cfg.is_multi_ap(o.ssid) else meta.severity
        events.append(_event(
            meta,
            "SSID '{}' is being broadcast by {} ({}), which was not in the "
            "baseline".format(o.ssid, o.bssid, oui.vendor(o.bssid)),
            ssid=o.ssid, bssid=o.bssid, severity=severity,
            vendor=oui.vendor(o.bssid), channel=o.channel,
            signal_dbm=o.signal_dbm, baseline_bssids=known,
            locally_administered=is_locally_administered(o.bssid),
        ))
    return events


def rule_encryption_downgrade(obs: Sequence[Observation], baseline: dict,
                              cfg: Config, oui: OuiLookup) -> list[Event]:
    meta = RULES["WIFI-002"]
    by_ssid = index_by_ssid(baseline)
    events: list[Event] = []
    for o in obs:
        if not o.ssid or o.ssid not in by_ssid:
            continue
        observed = auth_strength(o.authentication)
        if observed < 0:
            continue
        ranked = [auth_strength(r["authentication"]) for r in by_ssid[o.ssid]]
        ranked = [r for r in ranked if r >= 0]
        if not ranked:
            continue
        if observed >= max(ranked):
            continue
        best = max(by_ssid[o.ssid], key=lambda r: auth_strength(r["authentication"]))
        events.append(_event(
            meta,
            "SSID '{}' on {} now advertises '{}' but was baselined as "
            "'{}'".format(o.ssid, o.bssid, o.authentication, best["authentication"]),
            ssid=o.ssid, bssid=o.bssid,
            severity="critical" if o.is_open else "high",
            observed_auth=o.authentication, baseline_auth=best["authentication"],
            observed_encryption=o.encryption, vendor=oui.vendor(o.bssid),
        ))
    return events


def rule_vendor_mismatch(obs: Sequence[Observation], baseline: dict, cfg: Config,
                         oui: OuiLookup) -> list[Event]:
    meta = RULES["WIFI-003"]
    by_ssid = index_by_ssid(baseline)
    events: list[Event] = []
    for o in obs:
        if not o.ssid or o.ssid not in by_ssid:
            continue
        if (o.ssid, o.bssid) in baseline:
            continue
        vendor = oui.vendor(o.bssid)
        expected = {r["vendor"] for r in by_ssid[o.ssid]}
        local = is_locally_administered(o.bssid)
        if not local and vendor in expected:
            continue
        if local:
            reason = ("the BSSID is locally-administered, so it was generated "
                      "by software rather than assigned to hardware")
        else:
            reason = "vendor '{}' is not among the baselined vendors {}".format(
                vendor, sorted(expected))
        events.append(_event(
            meta,
            "SSID '{}' is being broadcast by {} and {}".format(o.ssid, o.bssid, reason),
            ssid=o.ssid, bssid=o.bssid,
            severity="critical" if local else meta.severity,
            vendor=vendor, expected_vendors=sorted(expected),
            locally_administered=local,
        ))
    return events


def rule_channel_change(obs: Sequence[Observation], baseline: dict, cfg: Config,
                        oui: OuiLookup) -> list[Event]:
    meta = RULES["WIFI-004"]
    events: list[Event] = []
    for o in obs:
        row = baseline.get((o.ssid, o.bssid))
        if row is None or o.channel in row["channels"]:
            continue
        events.append(_event(
            meta,
            "{} ('{}') is on channel {}, outside its baseline channels {}".format(
                o.bssid, _label(o.ssid), o.channel, row["channels"]),
            ssid=o.ssid, bssid=o.bssid,
            observed_channel=o.channel, baseline_channels=row["channels"],
        ))
    return events


def rule_signal_anomaly(obs: Sequence[Observation], baseline: dict, cfg: Config,
                        oui: OuiLookup) -> list[Event]:
    meta = RULES["WIFI-005"]
    events: list[Event] = []
    for o in obs:
        row = baseline.get((o.ssid, o.bssid))
        if row is None:
            continue
        low, high = row["min_signal_dbm"], row["max_signal_dbm"]
        if low - cfg.signal_delta_db <= o.signal_dbm <= high + cfg.signal_delta_db:
            continue
        stronger = o.signal_dbm > high
        direction = "stronger" if stronger else "weaker"
        delta = o.signal_dbm - high if stronger else low - o.signal_dbm
        events.append(_event(
            meta,
            "{} ('{}') is {} dB {} than its baseline range [{}, {}] dBm".format(
                o.bssid, _label(o.ssid), abs(delta), direction, low, high),
            ssid=o.ssid, bssid=o.bssid,
            observed_dbm=o.signal_dbm, baseline_min_dbm=low,
            baseline_max_dbm=high, delta_db=abs(delta), direction=direction,
        ))
    return events


def rule_beacon_flood(obs: Sequence[Observation], baseline: dict, cfg: Config,
                      oui: OuiLookup) -> list[Event]:
    meta = RULES["WIFI-006"]
    if not baseline:
        return []
    known = {ssid for (ssid, _b) in baseline if ssid}
    fresh = sorted({o.ssid for o in obs if o.ssid and o.ssid not in known})
    if len(fresh) <= cfg.beacon_flood_threshold:
        return []
    return [_event(
        meta,
        "{} previously-unseen SSIDs appeared in a single scan (threshold {})".format(
            len(fresh), cfg.beacon_flood_threshold),
        new_ssid_count=len(fresh), threshold=cfg.beacon_flood_threshold,
        sample_ssids=fresh[:20],
    )]


def rule_shared_bssid(obs: Sequence[Observation], baseline: dict, cfg: Config,
                      oui: OuiLookup) -> list[Event]:
    meta = RULES["WIFI-007"]
    by_bssid: dict[str, set[str]] = {}
    for o in obs:
        if o.ssid:
            by_bssid.setdefault(o.bssid, set()).add(o.ssid)
    events: list[Event] = []
    for bssid, ssids in sorted(by_bssid.items()):
        if len(ssids) < 2:
            continue
        events.append(_event(
            meta,
            "{} ({}) is broadcasting {} different SSIDs: {}".format(
                bssid, oui.vendor(bssid), len(ssids), sorted(ssids)),
            bssid=bssid, ssid=sorted(ssids)[0],
            ssids=sorted(ssids), vendor=oui.vendor(bssid),
        ))
    return events


RuleFn = Callable[[Sequence[Observation], dict, Config, OuiLookup], list[Event]]

RULE_FUNCTIONS: list[tuple[str, RuleFn]] = [
    ("WIFI-001", rule_evil_twin),
    ("WIFI-002", rule_encryption_downgrade),
    ("WIFI-003", rule_vendor_mismatch),
    ("WIFI-004", rule_channel_change),
    ("WIFI-005", rule_signal_anomaly),
    ("WIFI-006", rule_beacon_flood),
    ("WIFI-007", rule_shared_bssid),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class DetectionEngine:
    def __init__(self, baseline: dict, config: Config, oui: OuiLookup) -> None:
        self.baseline = baseline
        self.config = config
        self.oui = oui

    def run(self, observations: Sequence[Observation]) -> list[Event]:
        """Evaluate every enabled rule against one scan.

        Filtering happens once, up front: an ignored SSID or an allowlisted
        BSSID never reaches a rule, so no rule has to remember to check.
        """
        obs = [
            o for o in observations
            if not self.config.is_ignored_ssid(o.ssid)
            and not self.config.is_allowed_bssid(o.bssid)
        ]

        events: list[Event] = []
        for rule_id, fn in RULE_FUNCTIONS:
            if not self.config.is_enabled(rule_id):
                continue
            events.extend(fn(obs, self.baseline, self.config, self.oui))

        events.sort(key=lambda e: (SEVERITY_ORDER.get(e.severity, 9), e.rule_id, e.bssid))
        return events
