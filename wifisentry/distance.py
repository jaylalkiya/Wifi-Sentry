"""Rough proximity estimate from signal strength.

This is an ESTIMATE, and the code says so everywhere it surfaces. Turning RSSI
into metres assumes a clean line of sight and a known transmit power; walls,
bodies, and antenna differences break both assumptions. What it IS good for is
the thing that matters for detection: an evil twin has to out-shout the real AP
to win the client, so "this rogue is physically closer than your router" is a
strong corroborating signal even when the absolute metres are wrong.
"""

from __future__ import annotations

# Log-distance path-loss model: RSSI = TxPower - 10 * n * log10(d).
# TxPower is the expected RSSI at 1 metre; n is the environment factor
# (2 = open air, 3-4 = walls and furniture). These indoor defaults are
# deliberately middle-of-the-road.
_TX_POWER_DBM = -45.0
_PATH_LOSS_N = 3.0


def estimate_distance_m(signal_dbm: int) -> float:
    exponent = (_TX_POWER_DBM - signal_dbm) / (10.0 * _PATH_LOSS_N)
    return round(10.0 ** exponent, 1)


def proximity_label(signal_dbm: int) -> str:
    """A coarse bucket -- more honest than a false-precision metre count."""
    if signal_dbm >= -50:
        return "IN THE ROOM"
    if signal_dbm >= -63:
        return "VERY CLOSE"
    if signal_dbm >= -72:
        return "NEARBY"
    if signal_dbm >= -82:
        return "FAR"
    return "DISTANT"


def bars(signal_percent: int) -> str:
    """A 5-block signal meter for the UI: filled vs empty."""
    filled = max(0, min(5, round(signal_percent / 20)))
    return "█" * filled + "░" * (5 - filled)
