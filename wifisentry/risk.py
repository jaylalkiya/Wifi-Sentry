"""Score how suspicious each access point is, 0-100.

A single alert answers "did rule X fire?". A risk score answers the question an
analyst actually starts with: "of everything on the air, what should I look at
first?" It is a triage aid, not a verdict -- so it always ships the factors that
built it, never just the number. An analyst who cannot see WHY a score is 70
cannot trust it, and an unexplained score is the fastest way to get a tool
ignored.

The weights are transparent and additive on purpose. They are not a trained
model; they are a documented opinion you can argue with and tune.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Observation
from .oui import OuiLookup, is_locally_administered


@dataclass(frozen=True)
class RiskScore:
    score: int              # 0-100, capped
    band: str               # LOW | MEDIUM | HIGH | CRITICAL
    factors: tuple[str, ...]

    @property
    def is_notable(self) -> bool:
        return self.score >= 40


def _band(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def score_observation(obs: Observation, oui: OuiLookup, *,
                      in_baseline: bool = True, known_ssid: bool = True) -> RiskScore:
    """Weigh the risk factors visible in a single observation.

    `in_baseline` and `known_ssid` come from the caller's baseline lookup:
    a brand-new radio is more interesting than a familiar one, and a new radio
    wearing a *familiar name* is the evil-twin shape and scores highest.
    """
    score = 0
    factors: list[str] = []

    auth = obs.authentication.strip().lower()
    if obs.is_open:
        score += 30
        factors.append("+30 open network (no encryption)")
    elif auth.startswith("wep") or auth == "shared":
        score += 25
        factors.append("+25 WEP -- broken encryption")

    if is_locally_administered(obs.bssid):
        score += 20
        factors.append("+20 locally-administered MAC (software-generated)")

    vendor = oui.vendor(obs.bssid)
    if vendor.startswith("Unknown"):
        score += 8
        factors.append("+8 vendor not recognised")

    if not in_baseline:
        score += 15
        factors.append("+15 not seen in baseline")
        # A new radio using a name you already trust is the classic evil twin.
        if known_ssid:
            score += 20
            factors.append("+20 known SSID from a NEW radio (evil-twin shape)")
        # Loud + new = physically close and trying to win the client.
        if obs.signal_dbm >= -55:
            score += 10
            factors.append("+10 very strong signal for a new device (close by)")

    score = min(100, score)
    if not factors:
        factors.append("no risk factors -- baselined and encrypted")
    return RiskScore(score, _band(score), tuple(factors))
