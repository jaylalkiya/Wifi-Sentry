"""Diff two location snapshots.

The use case: baseline your home, walk into a cafe, and ask "what is different
here?" The answer -- which APs are unique to the untrusted location -- is where
a rogue AP would hide. A cafe legitimately has networks your home does not, so
this is a triage lens, not an alarm: it narrows where to look, and the risk
score ranks what it finds.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LocationDiff:
    only_in_a: list[dict]
    only_in_b: list[dict]
    in_both: list[dict]

    def summary(self) -> str:
        return ("{} only in A, {} only in B, {} shared"
                .format(len(self.only_in_a), len(self.only_in_b), len(self.in_both)))


def diff_snapshots(aps_a: list[dict], aps_b: list[dict]) -> LocationDiff:
    """Compare by BSSID -- the identity that cannot be spoofed away.

    Comparing by SSID would be worse than useless here: an evil twin shares the
    SSID by design, so an SSID-keyed diff would file the impostor under
    'shared' and hide the very thing you are looking for.
    """
    by_a = {ap["bssid"]: ap for ap in aps_a}
    by_b = {ap["bssid"]: ap for ap in aps_b}
    a_keys, b_keys = set(by_a), set(by_b)

    return LocationDiff(
        only_in_a=[by_a[k] for k in sorted(a_keys - b_keys)],
        only_in_b=[by_b[k] for k in sorted(b_keys - a_keys)],
        in_both=[by_b[k] for k in sorted(a_keys & b_keys)],
    )
