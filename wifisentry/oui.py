"""MAC vendor (OUI) lookup and MAC-shape heuristics.

Vendor identity matters here because an evil twin is usually a laptop or a
Raspberry Pi pretending to be an access point. The SSID it broadcasts is
free to copy; the radio's manufacturer prefix is not.
"""

from __future__ import annotations

import os
import re

# A small built-in table so the tool is useful with zero setup. It is not
# meant to be complete -- point --oui-file at IEEE's oui.txt for full coverage.
_BUILTIN: dict[str, str] = {
    "00:1a:2b": "Ayecom",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "PCS Systemtechnik (VirtualBox)",
    "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading",
    "d8:3a:dd": "Raspberry Pi Trading",
    "28:cd:c1": "Raspberry Pi Trading",
    "00:c0:ca": "Alfa Network",
    "00:13:37": "Netopia",
    "ac:71:2e": "Intel",
    "70:bc:48": "Cisco Meraki",
    "00:18:0a": "Cisco Meraki",
    "e0:cb:bc": "Cisco Meraki",
    "00:0b:86": "Aruba Networks",
    "6c:f3:7f": "Aruba Networks",
    "18:64:72": "Aruba Networks",
    "74:83:c2": "Ubiquiti",
    "fc:ec:da": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "24:5a:4c": "Ubiquiti",
    "b4:fb:e4": "Ubiquiti",
    "00:1d:aa": "D-Link",
    "1c:bd:b9": "D-Link",
    "50:c7:bf": "TP-Link",
    "a4:2b:b0": "TP-Link",
    "c4:e9:84": "TP-Link",
    "60:32:b1": "TP-Link",
    "00:26:5a": "D-Link",
    "2c:30:33": "Netgear",
    "a0:40:a0": "Netgear",
    "9c:3d:cf": "Netgear",
    "20:e5:2a": "Netgear",
    "00:23:69": "Cisco-Linksys",
    "48:f8:b3": "Cisco-Linksys",
    "f8:1a:67": "TP-Link",
    "34:08:04": "D-Link",
    "88:36:6c": "Arcadyan",
    "38:43:7d": "Arris",
    "00:1f:33": "Netgear",
}


class OuiLookup:
    """Prefix -> vendor resolver, optionally backed by IEEE's oui.txt."""

    def __init__(self, extra: dict[str, str] | None = None) -> None:
        self._table: dict[str, str] = dict(_BUILTIN)
        if extra:
            self._table.update({k.lower(): v for k, v in extra.items()})

    @classmethod
    def from_file(cls, path: str | None) -> "OuiLookup":
        """Load IEEE oui.txt if present; fall back to the built-in table.

        Expected lines look like:
            00-1A-2B   (hex)		AYECOM TECHNOLOGY CO., LTD.
        """
        if not path or not os.path.exists(path):
            return cls()

        extra: dict[str, str] = {}
        pattern = re.compile(r"^\s*([0-9A-Fa-f]{2}[-:]){2}[0-9A-Fa-f]{2}\s+\(hex\)\s+(.+?)\s*$")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = pattern.match(line)
                if not m:
                    continue
                prefix = re.sub(r"[^0-9A-Fa-f]", "", line.split()[0]).lower()
                if len(prefix) == 6:
                    extra[":".join(prefix[i : i + 2] for i in range(0, 6, 2))] = m.group(2)
        return cls(extra)

    def prefix(self, bssid: str) -> str:
        return bssid.lower()[:8]

    def vendor(self, bssid: str) -> str:
        """Vendor name, or 'Unknown (<prefix>)' when the OUI isn't in the table."""
        p = self.prefix(bssid)
        if is_locally_administered(bssid):
            return "Locally-administered/randomized"
        return self._table.get(p, f"Unknown ({p})")

    def known(self, bssid: str) -> bool:
        return self.prefix(bssid) in self._table


def is_locally_administered(bssid: str) -> bool:
    """True if bit 1 of the first octet is set.

    IEEE reserves that bit for addresses not assigned by a manufacturer. Real
    access points ship with a globally-unique (bit clear) address; software APs
    like hostapd, Windows Hosted Network, or a randomizing client often do not.
    A locally-administered BSSID claiming to be your corporate SSID is a strong
    evil-twin indicator.
    """
    try:
        first_octet = int(bssid.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0b10)
