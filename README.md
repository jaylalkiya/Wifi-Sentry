# wifi-sentry

A rogue access point monitor for Windows. It learns what the airwaves around
you normally look like, then alerts when something deviates — an evil twin of
your SSID, an encryption downgrade, a software-generated BSSID impersonating
your router.

It is a **detection** tool, not a scanning tool. Listing nearby networks is the
easy 10% that every tutorial stops at; deciding which of those networks is
*wrong* is the part worth building.

**Passive only.** wifi-sentry never transmits, never deauthenticates, and never
captures anyone's traffic. It reads the beacon metadata Windows already
collects.

---

## Screenshots

Every SSID and BSSID below is redacted by the app itself — the UI has a
redaction mode so screenshots and demos never leak real network identifiers.

**RADAR** — every network in range, most suspicious first:

![Radar tab](docs/screenshots/3.png)

**RULES** — each detection states what fires it and how it produces false
positives, mapped to MITRE ATT&CK:

![Rules tab](docs/screenshots/7.png)

**DASHBOARD** — counts, top risk targets, and the baseline status line:

![Dashboard tab](docs/screenshots/2.png)

More in [`docs/screenshots/`](docs/screenshots): history, location compare,
and the alerts triage view.

---

## Why it works without monitor mode

Capturing raw 802.11 frames on Windows needs Npcap plus an adapter whose driver
supports monitor mode — most consumer adapters do not, so most Windows WiFi
projects die there.

`netsh wlan show networks mode=bssid` sidesteps that entirely. Windows scans
continuously anyway to decide what to roam to, and netsh exposes the result:
SSID, **BSSID**, channel, signal, authentication, cipher, band. That is
everything the rules below need.

The tradeoff, stated plainly: deauth-flood detection, probe-request tracking,
and client-side analysis **do** need monitor mode and are out of scope. See
[Limitations](#limitations).

The key insight the whole project rests on:

> The **SSID** is a label anyone can copy in five seconds. The **BSSID** is the
> radio's MAC address. An attacker can clone your network name trivially — but
> the moment they do, they are broadcasting it from a MAC that was never there
> before, usually from a different vendor, often from a locally-administered
> address that no manufacturer ever assigned.

---

## Quick start

Python 3.10+. No dependencies — standard library only.

**Easiest:** double-click **`START.bat`** (or `WiFi-Sentry.pyw` for no console
window). The desktop UI opens straight away.

From a terminal:

```powershell
cd D:\Adani_CyberSecurity\projects\wifi-sentry

# 1. Learn what is normally on the air (do this somewhere you trust)
python -m wifisentry baseline

# 2. Check for deviations
python -m wifisentry scan

# 3. Or watch continuously
python -m wifisentry watch --interval 60 --jsonl wifi-sentry.events.jsonl
```

`scan` exits **2** when something at high or critical severity fires, so Task
Scheduler or a monitoring agent can act on the exit code.

### Desktop UI

```powershell
python -m wifisentry gui
```

Tkinter, so still no dependencies. Three tabs:

- **Alerts** — every finding, worst first, colour-coded by severity. Click one
  for the full evidence pane: ATT&CK technique, first/last seen, hit count, the
  rule-specific evidence bag, and that rule's known false positives.
- **Networks** — everything currently on the air, strongest first, with vendor
  resolved from the OUI. Anything not in the baseline is tagged `NEW`.
- **Rules** — the catalogue as cards with rationale and false positives, each
  with a toggle that writes straight to `disabled_rules` in your config.

Toolbar: take a baseline, scan once, or start watching on an interval. Scans run
on a worker thread and report back through a queue, so the window stays
responsive — and because sqlite3 connections cannot cross threads, each worker
opens its own `Store` against the same file.

`Export JSONL...` writes the stored alerts out in SIEM-ready form.

### Triage features

Beyond raw detection, each network is enriched to answer *"what should I look
at first?"* — the question an analyst actually starts with:

- **Risk score (0–100).** A transparent, additive score per network — open
  auth, locally-administered MAC, unknown vendor, not-in-baseline, known-SSID
  from a new radio, loud-and-new. It always ships the factors that built it;
  an unexplained score is the fastest way to get a tool ignored.
- **Device fingerprint.** Infers *what* each AP is — router, phone hotspot,
  single-board computer, IoT camera, printer — from vendor, radio type, and
  SSID text. A beacon whose name says "router" but whose fingerprint says
  "phone hotspot" is the evil-twin shape, surfaced even when no rule fires.
- **Proximity.** A coarse bucket (IN THE ROOM → DISTANT) from signal strength.
  Deliberately not false-precision metres. Useful because an evil twin has to
  out-shout the real AP, so "this rogue is closer than your router" is strong
  corroboration.
- **History.** `history` (CLI) and the HISTORY tab show every device ever seen
  with first/last-seen and sighting counts — "show me every device that
  appeared this week" is one query over the observations table.
- **Location compare.** `snapshot home`, then `snapshot cafe`, then
  `compare home cafe` — or the COMPARE tab. Diffs by BSSID (never SSID, or an
  evil twin would hide under "shared"); networks unique to the untrusted
  location are where a rogue AP lives.

```powershell
python -m wifisentry history --new --days 7      # devices new this week
python -m wifisentry snapshot home               # capture a location
python -m wifisentry snapshot cafe
python -m wifisentry compare home cafe           # what's different / suspicious
```

### See it catch something, right now

The repo ships two saved netsh captures so you can watch a detection fire
without waiting for a real attacker:

```powershell
python -m wifisentry --db demo.db --replay tests\fixtures\netsh_baseline.txt baseline
python -m wifisentry --db demo.db --replay tests\fixtures\netsh_attack.txt scan
```

```
[CRITICAL] WIFI-001 Evil twin: known SSID on an unknown BSSID
    SSID 'TrustedNet' is being broadcast by 02:11:22:33:44:55
    (Locally-administered/randomized), which was not in the baseline
    ATT&CK T1557.004 (Adversary-in-the-Middle: Evil Twin)

[CRITICAL] WIFI-002 Encryption downgrade on a known SSID
    SSID 'TrustedNet' on 02:11:22:33:44:55 now advertises 'Open' but was
    baselined as 'WPA2-Personal'
    ATT&CK T1557 (Adversary-in-the-Middle)

[CRITICAL] WIFI-003 Unexpected radio vendor for a known SSID
    SSID 'TrustedNet' is being broadcast by 02:11:22:33:44:55 and the BSSID is
    locally-administered, so it was generated by software rather than
    assigned to hardware
    ATT&CK T1557.004 (Adversary-in-the-Middle: Evil Twin)

[HIGH] WIFI-007 One BSSID broadcasting multiple SSIDs
    b8:27:eb:99:88:77 (Raspberry Pi Foundation) is broadcasting 2 different
    SSIDs: ['Free_Airport_WiFi', 'Starbucks']
    ATT&CK T1557.004 (Adversary-in-the-Middle: Evil Twin)
```

Three independent rules corroborate the same rogue AP. That is what a real
detection stack looks like: one signal is a guess, three agreeing is a finding.

---

## Detection rules

`python -m wifisentry rules` prints this catalogue with rationale and known
false positives for each.

| ID | Rule | Severity | ATT&CK |
|----|------|----------|--------|
| WIFI-001 | Evil twin: known SSID on an unknown BSSID | critical | T1557.004 |
| WIFI-002 | Encryption downgrade on a known SSID | critical | T1557 |
| WIFI-003 | Unexpected radio vendor for a known SSID | high | T1557.004 |
| WIFI-004 | Known BSSID changed channel | medium | T1557 |
| WIFI-005 | Signal strength anomaly for a known BSSID | medium | T1557.004 |
| WIFI-006 | Beacon flood: many new SSIDs at once | high | T1498 |
| WIFI-007 | One BSSID broadcasting multiple SSIDs | high | T1557.004 |

A note on **WIFI-003**: IEEE reserves bit 1 of a MAC's first octet for addresses
*not* assigned by a manufacturer. Real access points ship with a globally-unique
address; `hostapd`, Windows Hosted Network, and randomizing clients often do
not. A locally-administered BSSID claiming to be your corporate SSID is close to
a smoking gun, which is why that case escalates to critical.

A note on **WIFI-007**: legitimate multi-SSID access points assign each network
its own BSSID (usually by incrementing the MAC). One radio answering to several
unrelated SSIDs is the signature of a KARMA-style responder saying "yes" to
every probe it hears.

---

## False positive tuning

Every rule here can fire on something innocent, and a rule that cannot be tuned
gets muted — at which point it detects nothing. So tuning is a first-class
feature, not an afterthought.

```powershell
python -m wifisentry init-config     # writes wifi-sentry.config.json
```

```json
{
  "ignore_ssids": ["NeighboursWiFi"],
  "allow_bssids": ["74:83:c2:00:00:02"],
  "multi_ap_ssids": ["OfficeWLAN"],
  "signal_delta_db": 12,
  "beacon_flood_threshold": 8,
  "disabled_rules": []
}
```

| Knob | What it solves |
|------|----------------|
| `ignore_ssids` | Neighbours' networks you don't own and don't care about. |
| `allow_bssids` | A specific radio confirmed legitimate — a new mesh node you added yourself. |
| `multi_ap_ssids` | Mesh and enterprise SSIDs that legitimately grow radios. **Downgrades** WIFI-001 to `low` rather than hiding it, so the analyst still sees the change but nobody gets paged. |
| `signal_delta_db` | How far RSSI must move before WIFI-005 fires. 12 dB ≈ "moved to another room". |
| `beacon_flood_threshold` | New SSIDs in one sweep before WIFI-006 fires. Raise it if you commute. |
| `disabled_rules` | Last resort. Prefer the allowlists. |

Three further noise controls are built in rather than configured:

1. **Multi-sweep baselining.** `baseline` takes 3 sweeps by default and records
   a signal *range*, not a point value. RSSI swings several dB between sweeps;
   a single-sweep baseline makes WIFI-005 scream on day two.
2. **Alert deduplication.** Alerts are keyed on `(rule, SSID, BSSID)` —
   deliberately excluding the timestamp, signal, and channel. A rogue AP left
   powered on updates `hit_count` and `last_seen` instead of producing a fresh
   wall of alerts every 60 seconds.
3. **Pre-rule filtering.** Ignored SSIDs and allowlisted BSSIDs are stripped
   once, before any rule runs, so no individual rule has to remember to check.

---

## SIEM output

`--jsonl` appends one JSON object per line — the format every log shipper
(Filebeat, Fluent Bit, Vector, Splunk UF) ingests without configuration.

```json
{"bssid":"02:11:22:33:44:55","dedupe_key":"a3f1...","details":{"baseline_bssids":["70:bc:48:00:11:01","70:bc:48:00:11:02"],"channel":6,"locally_administered":true,"signal_dbm":-51,"vendor":"Locally-administered/randomized"},"message":"SSID 'TrustedNet' is being broadcast by 02:11:22:33:44:55 ...","rule_id":"WIFI-001","rule_name":"Evil twin: known SSID on an unknown BSSID","severity":"critical","source":"wifi-sentry","ssid":"TrustedNet","technique":"T1557.004","technique_name":"Adversary-in-the-Middle: Evil Twin","timestamp":"2026-08-25T09:00:43Z"}
```

Field names follow the ECS-ish shape most SIEMs expect: `rule_id`, `severity`,
`technique`, `ssid`/`bssid` as the entities, and a `details` bag for
rule-specific evidence.

---

## Commands

| Command | What it does |
|---------|--------------|
| `baseline` | Sample the air N times and store what normal looks like. `--sweeps`, `--delay`, `--force`. |
| `scan` | One sweep, evaluate all enabled rules, print and optionally append JSONL. |
| `watch` | `scan` on a loop. `--interval`. |
| `alerts` | Show recorded alert state with first/last seen and hit counts. `--clear`. |
| `rules` | Print the rule catalogue, rationale, false positives, ATT&CK coverage. |
| `init-config` | Write a default tuning config. |
| `history` | Devices seen over time. `--days N`, `--new`. |
| `snapshot NAME` | Capture the current location for later comparison. `--list`. |
| `compare A B` | Diff two location snapshots; flag networks unique to B. |
| `gui` | Open the Tkinter desktop interface. |
| `capture FILE` | Save raw netsh output — for fixtures and offline debugging. |

Global flags: `--db`, `--config`, `--interface`, `--oui-file`, `--replay`.

`--replay` parses a saved capture instead of touching the radio. Repeat the flag
for several sweeps. It exists so the detections are testable and the demo is
reproducible — you cannot screenshot an evil twin on demand.

### Better vendor coverage

The built-in OUI table covers common router and SBC vendors. For full coverage,
download IEEE's registry and point at it:

```powershell
curl -o oui.txt https://standards-oui.ieee.org/oui/oui.txt
python -m wifisentry --oui-file oui.txt scan
```

---

## Architecture

```
netsh  ──▶  scanner.py   ──▶  Observation (one per BSSID, per sweep)
                                   │
                     ┌─────────────┴─────────────┐
                     ▼                           ▼
              baseline.py                   detections.py
        (aggregate N sweeps into      (7 independent rule functions
         per-AP normal ranges)         over scan × baseline × config)
                     │                           │
                     ▼                           ▼
                 store.py                     Event
        (SQLite: scans, observations,            │
         baseline, alert dedupe state)  ┌────────┴────────┐
                                        ▼                 ▼
                                   emit.py console    emit.py JSONL
                                                      (→ SIEM)
```

Rules never touch netsh and never touch SQLite. They are pure functions of
`(observations, baseline, config, oui)` returning `Event` objects — which is why
all 7 are unit-testable without a radio, a database, or a rogue AP.

```
wifisentry/
  scanner.py      WlanScan sweep + netsh invocation and parsing
  models.py       Observation, Event, signal conversion
  oui.py          MAC vendor lookup, locally-administered detection
  baseline.py     multi-sweep aggregation
  detections.py   the 7 rules + engine
  config.py       tuning knobs and allowlists
  store.py        SQLite schema and access
  emit.py         console and JSONL output
  cli.py          argparse command surface
  analyze.py      risk + fingerprint + proximity, combined per AP
  distance.py     signal -> proximity estimate
  fingerprint.py  device-type inference
  risk.py         transparent 0-100 risk score
  compare.py      location snapshot diff
  gui.py          Tkinter desktop UI (threaded, queue-driven, 6 tabs)
tests/            97 tests, stdlib unittest, no radio required
```

---

## Tests

```powershell
python -m unittest discover -s tests -v
```

97 tests covering: netsh parsing (including hidden SSIDs, multi-BSSID SSIDs,
and malformed input), MAC normalization, every detection rule firing *and*
staying quiet, each tuning knob changing the outcome, alert deduplication,
config round-tripping, the full CLI flow end to end via `--replay`, and GUI
construction and rendering against real data (auto-skipped when Tk has no
display).

The one that matters most:

```python
def test_rescanning_the_baseline_is_silent(self):
    scan = load("netsh_baseline.txt")
    engine = DetectionEngine(make_baseline([scan]), Config(), OuiLookup())
    self.assertEqual(engine.run(scan), [])
```

A detection tool that alerts on normal traffic is worse than no detection tool,
because people switch it off.

---

## Limitations

Stated up front, because knowing what your tool *cannot* see is half of
detection engineering.

- **No monitor mode.** Deauthentication floods, probe-request harvesting, and
  client-side (rather than AP-side) attacks are invisible here. Those need
  Linux plus an adapter that supports monitor mode.
- **Windows only.** `netsh` is the collector. A Linux collector emitting the
  same `Observation` objects would drop straight into the rest of the pipeline —
  the parser is deliberately the only OS-specific module.
- **Windows throttles scanning, so the tool forces a sweep.** When connected
  and idle, Windows stops sweeping to save power and `netsh` returns a cached
  list — often only the network you are attached to. wifi-sentry calls
  `WlanScan` (wlanapi.dll, via ctypes) before every scan and waits 4 seconds
  for the sweep to land. On this developer's machine that took a scan from 1
  visible network to 13. If the call fails it falls back to the cached list
  rather than erroring.
- **English-locale field labels.** netsh localizes its output; the parser
  degrades to fewer fields on other locales rather than crashing.
- **Signal is approximate.** Windows reports 0–100% quality; dBm is derived
  linearly. Monotonic, which is all WIFI-005 needs, but not a measurement.
- **WIFI-005 assumes a fixed location.** Disable it on a laptop that roams.

---

## Scope and ethics

This tool observes broadcast beacon frames — the same information your phone
uses to populate its WiFi list. It transmits nothing, associates with nothing,
and captures no traffic.

That boundary is deliberate. Deauthentication, handshake capture, and cracking
are a different project with different legal exposure, and they are offensive
work, not detection work.

Baseline somewhere you control. Alerts are only meaningful against a baseline of
a network you actually know.
