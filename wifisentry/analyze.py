"""Combine risk, fingerprint, and proximity into one enriched view per AP.

The GUI's Networks table and the CLI both need the same enriched picture, so it
lives here once rather than being reassembled in each. Keeping enrichment out
of detections.py is deliberate: rules decide "is this an alert?", enrichment
decides "how do I present this to a human?" -- different jobs, different module.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import distance
from .fingerprint import Fingerprint, fingerprint
from .models import Observation
from .oui import OuiLookup
from .risk import RiskScore, score_observation


@dataclass
class EnrichedAP:
    obs: Observation
    vendor: str
    risk: RiskScore
    device: Fingerprint
    proximity: str
    is_new: bool


def enrich(obs: Observation, oui: OuiLookup, baseline_keys: set,
           baseline_ssids: set) -> EnrichedAP:
    key = (obs.ssid, obs.bssid)
    in_baseline = key in baseline_keys
    known_ssid = bool(obs.ssid) and obs.ssid in baseline_ssids
    return EnrichedAP(
        obs=obs,
        vendor=oui.vendor(obs.bssid),
        risk=score_observation(obs, oui, in_baseline=in_baseline,
                               known_ssid=known_ssid),
        device=fingerprint(obs, oui),
        proximity=distance.proximity_label(obs.signal_dbm),
        is_new=not in_baseline,
    )


def enrich_all(observations: list[Observation], oui: OuiLookup,
               baseline: dict) -> list[EnrichedAP]:
    keys = set(baseline.keys())
    ssids = {ssid for (ssid, _b) in baseline if ssid}
    enriched = [enrich(o, oui, keys, ssids) for o in observations]
    # Highest risk first, then strongest signal -- the analyst's reading order.
    enriched.sort(key=lambda e: (-e.risk.score, e.obs.signal_dbm * -1))
    return enriched
