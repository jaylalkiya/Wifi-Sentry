"""Guess what KIND of device an access point is.

Beacons do not announce "I am a phone" -- so this is inference, not fact, and
every result carries a confidence and the reasons behind it. The signal is
useful anyway: a network whose *name* says "router" but whose *fingerprint*
says "phone hotspot / software AP" is exactly the shape of an evil twin, and
that contradiction is worth surfacing even when no single rule fires.

Inputs are all things a passive scan already has: the OUI vendor, the radio
type, the band, the authentication, and the SSID text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Observation
from .oui import OuiLookup, is_locally_administered

ROUTER_VENDORS = {
    "TP-Link", "Netgear", "D-Link", "Cisco", "Cisco Meraki", "Cisco-Linksys",
    "Aruba Networks", "Ubiquiti", "Arris", "Arcadyan", "Netopia", "Ayecom",
}
VIRTUAL_VENDORS = {"VMware", "QEMU/KVM", "PCS Systemtechnik (VirtualBox)"}

# SSID text is a weak but sometimes decisive hint -- an "HP-Print-..." beacon
# is almost never anything but a printer.
_IOT_CAMERA = re.compile(r"\b(cam|ipc|ring|tapo|wyze|reolink|hikvision|cctv)\b", re.I)
# SSID text is normalised to spaces before matching, so keywords must not
# depend on the original punctuation (e.g. "HP-Print" arrives as "HP Print").
_PRINTER = re.compile(r"\b(print|printer|laserjet|deskjet|epson|canon|brother)\b", re.I)
_TV = re.compile(r"\b(tv|roku|chromecast|firetv|shield|bravia)\b", re.I)


@dataclass(frozen=True)
class Fingerprint:
    device_type: str
    confidence: str  # low | medium | high
    reasons: tuple[str, ...]


def fingerprint(obs: Observation, oui: OuiLookup) -> Fingerprint:
    vendor = oui.vendor(obs.bssid)
    ssid = obs.ssid or ""
    # Underscores and hyphens are word chars to regex, so "Tapo_Cam_A1" has no
    # boundary around "Cam". Split them to spaces first so \b matches.
    ssid_words = re.sub(r"[^A-Za-z0-9]+", " ", ssid)
    reasons: list[str] = []

    # SSID text wins when it is explicit -- highest-signal hint available.
    if _IOT_CAMERA.search(ssid_words):
        return Fingerprint("IoT camera", "medium",
                           ("SSID '{}' matches camera keywords".format(ssid),))
    if _PRINTER.search(ssid_words):
        return Fingerprint("Printer", "high",
                           ("SSID '{}' matches printer keywords".format(ssid),))
    if _TV.search(ssid_words):
        return Fingerprint("Smart TV / streamer", "medium",
                           ("SSID '{}' matches media-device keywords".format(ssid),))

    if vendor in VIRTUAL_VENDORS:
        return Fingerprint("Virtual / software AP", "high",
                           ("vendor '{}' is a hypervisor".format(vendor),))

    if "Raspberry Pi" in vendor:
        reasons.append("Raspberry Pi hardware -- common attack-tool platform")
        return Fingerprint("Single-board computer (possible rogue AP)", "medium",
                           tuple(reasons))

    local = is_locally_administered(obs.bssid)
    if local:
        reasons.append("locally-administered MAC (software-generated)")
        # Phones randomise their hotspot MAC; so do attack tools. Band and
        # radio type do not separate them, so this stays deliberately vague.
        return Fingerprint("Phone hotspot / software AP", "medium", tuple(reasons))

    if vendor in ROUTER_VENDORS:
        reasons.append("vendor '{}' makes networking hardware".format(vendor))
        conf = "high"
        if obs.radio_type:
            reasons.append("radio {}".format(obs.radio_type))
        if "wpa3" in obs.authentication.lower():
            reasons.append("WPA3 -- modern access point")
        return Fingerprint("Router / access point", conf, tuple(reasons))

    if vendor.startswith("Unknown"):
        reasons.append("OUI not in vendor table (load IEEE oui.txt for more)")
        return Fingerprint("Unknown device", "low", tuple(reasons))

    reasons.append("vendor '{}'".format(vendor))
    return Fingerprint("Consumer device", "low", tuple(reasons))
