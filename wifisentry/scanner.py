"""Collect nearby access points on Windows via `netsh wlan show networks`.

Why netsh and not monitor mode: capturing raw 802.11 frames on Windows needs
Npcap plus an adapter whose driver supports monitor mode, which most consumer
adapters do not. netsh needs neither, works on every Windows box, and still
exposes SSID, BSSID, channel, signal and cipher -- everything the detections in
this project actually consume. Deauth-flood and probe-request detection do need
monitor mode; those are deliberately out of scope, see README.
"""

from __future__ import annotations

import re
import subprocess
import time
from typing import Iterable

from .models import Observation

try:
    import ctypes
    from ctypes import wintypes

    _WLANAPI_AVAILABLE = hasattr(ctypes, "windll")
except (ImportError, ValueError):  # not Windows
    _WLANAPI_AVAILABLE = False

# MSDN: a WlanScan sweep completes within 4 seconds.
SCAN_SETTLE_SECONDS = 4.0

# Matched before the generic key/value pattern -- "SSID 1 : Foo" is also a
# valid "key : value" line, so ordering here is load-bearing.
_SSID_RE = re.compile(r"^\s*SSID\s+(\d+)\s*:\s?(.*?)\s*$", re.IGNORECASE)
_BSSID_RE = re.compile(r"^\s*BSSID\s+(\d+)\s*:\s*([0-9a-fA-F:.-]{11,})\s*$", re.IGNORECASE)
_KV_RE = re.compile(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$")
_INTERFACE_RE = re.compile(r"^\s*Interface name\s*:\s*(.+?)\s*$", re.IGNORECASE)


class ScanError(RuntimeError):
    """Raised when the WLAN service cannot produce a scan."""


def normalize_mac(mac: str) -> str:
    """Lowercase, colon-separated MAC. Returns '' if it isn't one."""
    hexdigits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexdigits) != 12:
        return ""
    hexdigits = hexdigits.lower()
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))


def _to_int(value: str, default: int = 0) -> int:
    m = re.search(r"-?\d+", value)
    return int(m.group()) if m else default


def parse_netsh_output(text: str) -> list[Observation]:
    """Turn raw `netsh wlan show networks mode=bssid` text into Observations.

    Note for non-English Windows: netsh localizes these field labels, so the
    key matching below would miss them. Run `netsh` under an English locale, or
    extend the label sets. Unrecognized keys are ignored rather than fatal, so
    a localized system degrades to fewer fields instead of crashing.
    """
    observations: list[Observation] = []

    current_ssid: str | None = None
    auth = ""
    enc = ""
    pending: dict[str, str] | None = None

    def flush() -> None:
        nonlocal pending
        if pending is None:
            return
        bssid = normalize_mac(pending.get("bssid", ""))
        if bssid:
            observations.append(
                Observation(
                    ssid=current_ssid or "",
                    bssid=bssid,
                    channel=_to_int(pending.get("channel", "0")),
                    signal_percent=_to_int(pending.get("signal", "0")),
                    authentication=auth,
                    encryption=enc,
                    radio_type=pending.get("radio type", ""),
                    band=pending.get("band", ""),
                )
            )
        pending = None

    for line in text.splitlines():
        if not line.strip():
            continue

        m = _SSID_RE.match(line)
        if m:
            flush()
            current_ssid = m.group(2)  # empty string == hidden network
            auth = enc = ""
            continue

        m = _BSSID_RE.match(line)
        if m:
            flush()
            pending = {"bssid": m.group(2)}
            continue

        m = _KV_RE.match(line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2)

        if pending is not None and key in ("signal", "radio type", "band", "channel"):
            pending[key] = value
        elif key == "authentication":
            auth = value
        elif key == "encryption":
            enc = value

    flush()
    return observations


def get_interface_name(text: str) -> str:
    for line in text.splitlines():
        m = _INTERFACE_RE.match(line)
        if m:
            return m.group(1)
    return ""


def run_netsh(interface: str | None = None, timeout: int = 30) -> str:
    """Shell out to netsh and return its stdout."""
    cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
    if interface:
        cmd.append(f"interface={interface}")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
    except FileNotFoundError as exc:  # not Windows, or netsh not on PATH
        raise ScanError("netsh not found -- this collector requires Windows") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"netsh timed out after {timeout}s") from exc

    if proc.returncode != 0:
        raise ScanError(f"netsh exited {proc.returncode}: {proc.stderr.strip()}")

    out = proc.stdout
    # netsh returns 0 with this text when the radio is off or the service is
    # stopped, so returncode alone is not enough to trust the result.
    if "wireless" in out.lower() and "not running" in out.lower():
        raise ScanError("The WLAN AutoConfig service is not running")
    return out


if _WLANAPI_AVAILABLE:

    class _GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class _WLAN_INTERFACE_INFO(ctypes.Structure):
        _fields_ = [
            ("InterfaceGuid", _GUID),
            ("strInterfaceDescription", ctypes.c_wchar * 256),
            ("isState", wintypes.DWORD),
        ]

    class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
        # InterfaceInfo is really a variable-length array; it is declared with
        # one element and re-cast below once dwNumberOfItems is known.
        _fields_ = [
            ("dwNumberOfItems", wintypes.DWORD),
            ("dwIndex", wintypes.DWORD),
            ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1),
        ]


def request_scan() -> int:
    """Ask every WLAN interface to sweep the band now. Returns how many did.

    This matters more than it looks. When Windows is connected and idle it
    stops sweeping to save power, and `netsh wlan show networks` happily
    returns the last cached result -- often just the network you are attached
    to. A detection tool reading that stale list would conclude the air is
    clean while an evil twin is broadcasting beside it.

    WlanScan (wlanapi.dll) forces a real sweep. Failure is not fatal: the
    caller falls back to whatever netsh has, which is what the tool did
    before.
    """
    if not _WLANAPI_AVAILABLE:
        return 0
    try:
        wlanapi = ctypes.windll.wlanapi
    except (AttributeError, OSError):
        return 0

    handle = wintypes.HANDLE()
    negotiated = wintypes.DWORD()
    if wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated),
                              ctypes.byref(handle)) != 0:
        return 0

    try:
        list_ptr = ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)()
        if wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(list_ptr)) != 0:
            return 0
        try:
            info_list = list_ptr.contents
            count = info_list.dwNumberOfItems
            if not count:
                return 0
            interfaces = ctypes.cast(
                ctypes.byref(info_list.InterfaceInfo),
                ctypes.POINTER(_WLAN_INTERFACE_INFO * count),
            ).contents
            # Scan every wireless interface: netsh names the connection
            # ("Wi-Fi") while this API reports the adapter description
            # ("Intel(R) Wi-Fi 6 AX201"), so the two cannot be matched up.
            return sum(
                1 for iface in interfaces
                if wlanapi.WlanScan(handle, ctypes.byref(iface.InterfaceGuid),
                                    None, None, None) == 0
            )
        finally:
            wlanapi.WlanFreeMemory(list_ptr)
    except OSError:
        return 0
    finally:
        wlanapi.WlanCloseHandle(handle, None)


def scan(interface: str | None = None, force: bool = True,
         settle: float = SCAN_SETTLE_SECONDS) -> list[Observation]:
    """Perform one live scan, forcing a fresh sweep first by default."""
    if force and request_scan():
        time.sleep(settle)
    return parse_netsh_output(run_netsh(interface))


def scan_from_file(path: str) -> list[Observation]:
    """Replay a saved netsh capture -- used by tests and for offline dev."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_netsh_output(fh.read())


def summarize(observations: Iterable[Observation]) -> str:
    obs = list(observations)
    ssids = {o.ssid for o in obs if o.ssid}
    return f"{len(obs)} BSSIDs across {len(ssids)} named SSIDs"
