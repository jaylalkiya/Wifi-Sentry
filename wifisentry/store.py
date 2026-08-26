"""SQLite persistence for scans, observations, the baseline, and alert state."""

from __future__ import annotations

import json
import sqlite3
from typing import Iterable, Sequence

from .models import Event, Observation, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    ap_count    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    seen_at         TEXT NOT NULL,
    ssid            TEXT NOT NULL,
    bssid           TEXT NOT NULL,
    channel         INTEGER NOT NULL,
    signal_percent  INTEGER NOT NULL,
    signal_dbm      INTEGER NOT NULL,
    authentication  TEXT NOT NULL,
    encryption      TEXT NOT NULL,
    radio_type      TEXT NOT NULL DEFAULT '',
    band            TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_obs_bssid ON observations(bssid);
CREATE INDEX IF NOT EXISTS idx_obs_ssid  ON observations(ssid);

-- One row per (SSID, BSSID) pair that was present when the baseline was taken.
CREATE TABLE IF NOT EXISTS baseline_ap (
    ssid            TEXT NOT NULL,
    bssid           TEXT NOT NULL,
    vendor          TEXT NOT NULL,
    channels        TEXT NOT NULL,   -- JSON list of ints
    authentication  TEXT NOT NULL,
    encryption      TEXT NOT NULL,
    min_signal_dbm  INTEGER NOT NULL,
    max_signal_dbm  INTEGER NOT NULL,
    sample_count    INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (ssid, bssid)
);

CREATE TABLE IF NOT EXISTS baseline_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- A named point-in-time capture of one location, so "home" and "cafe" can be
-- diffed later. Distinct from the baseline, which is the single trusted set.
CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    ap_json     TEXT NOT NULL   -- JSON list of {ssid,bssid,vendor,channel,signal_dbm,authentication}
);

-- Alert state, keyed by Event.dedupe_key, so a rogue AP that stays powered on
-- updates last_seen/count instead of firing a fresh alert every scan.
CREATE TABLE IF NOT EXISTS alerts (
    dedupe_key  TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    ssid        TEXT NOT NULL,
    bssid       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    hit_count   INTEGER NOT NULL,
    event_json  TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str) -> None:
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------------------------------------------------------------- scans

    def record_scan(self, observations: Sequence[Observation]) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (started_at, ap_count) VALUES (?, ?)",
            (utcnow(), len(observations)),
        )
        scan_id = int(cur.lastrowid)
        self.conn.executemany(
            """INSERT INTO observations
               (scan_id, seen_at, ssid, bssid, channel, signal_percent,
                signal_dbm, authentication, encryption, radio_type, band)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    scan_id, o.seen_at, o.ssid, o.bssid, o.channel,
                    o.signal_percent, o.signal_dbm, o.authentication,
                    o.encryption, o.radio_type, o.band,
                )
                for o in observations
            ],
        )
        self.conn.commit()
        return scan_id

    def scan_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0])

    def observations_for_scan(self, scan_id: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute("SELECT * FROM observations WHERE scan_id = ?", (scan_id,))
        )

    # ------------------------------------------------------------- baseline

    def replace_baseline(self, rows: Iterable[dict], meta: dict[str, str]) -> int:
        self.conn.execute("DELETE FROM baseline_ap")
        self.conn.execute("DELETE FROM baseline_meta")
        count = 0
        for r in rows:
            self.conn.execute(
                """INSERT INTO baseline_ap
                   (ssid, bssid, vendor, channels, authentication, encryption,
                    min_signal_dbm, max_signal_dbm, sample_count, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    r["ssid"], r["bssid"], r["vendor"], json.dumps(sorted(r["channels"])),
                    r["authentication"], r["encryption"], r["min_signal_dbm"],
                    r["max_signal_dbm"], r["sample_count"], r["created_at"],
                ),
            )
            count += 1
        self.conn.executemany(
            "INSERT INTO baseline_meta (key, value) VALUES (?, ?)",
            list(meta.items()),
        )
        self.conn.commit()
        return count

    def load_baseline(self) -> dict[tuple[str, str], dict]:
        out: dict[tuple[str, str], dict] = {}
        for row in self.conn.execute("SELECT * FROM baseline_ap"):
            d = dict(row)
            d["channels"] = json.loads(d["channels"])
            out[(d["ssid"], d["bssid"])] = d
        return out

    def baseline_meta(self) -> dict[str, str]:
        return {r["key"]: r["value"] for r in self.conn.execute("SELECT * FROM baseline_meta")}

    def has_baseline(self) -> bool:
        return bool(self.conn.execute("SELECT 1 FROM baseline_ap LIMIT 1").fetchone())

    # -------------------------------------------------------------- history

    def device_history(self, since: str | None = None) -> list[dict]:
        """Every distinct (SSID, BSSID) ever observed, with first/last seen.

        This is what makes "show me every device that appeared this week" a
        one-line query: the observations table already timestamps every sweep,
        so history is just an aggregate over it -- no separate bookkeeping.
        """
        params: list = []
        clause = ""
        if since:
            clause = "WHERE seen_at >= ?"
            params.append(since)
        rows = self.conn.execute(
            """SELECT ssid, bssid,
                      MIN(seen_at) AS first_seen,
                      MAX(seen_at) AS last_seen,
                      COUNT(*)     AS sightings
               FROM observations {}
               GROUP BY ssid, bssid
               ORDER BY first_seen DESC""".format(clause),
            params,
        )
        return [dict(r) for r in rows]

    def new_devices_since(self, since: str) -> list[dict]:
        """Devices whose FIRST-EVER sighting falls after `since`.

        A device merely seen this week is not news if it was also seen last
        month. Filtering in Python on the all-time first_seen -- rather than a
        windowed query -- is what makes "new" mean new, not just "present".
        """
        return [d for d in self.device_history() if d["first_seen"] >= since]

    # ------------------------------------------------------------ snapshots

    def save_snapshot(self, name: str, aps: list[dict]) -> int:
        cur = self.conn.execute(
            "INSERT INTO snapshots (name, created_at, ap_json) VALUES (?,?,?)",
            (name, utcnow(), json.dumps(aps)),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def list_snapshots(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT id, name, created_at, ap_json FROM snapshots ORDER BY created_at DESC"))

    def latest_snapshot(self, name: str) -> dict | None:
        row = self.conn.execute(
            "SELECT id, name, created_at, ap_json FROM snapshots "
            "WHERE name = ? ORDER BY created_at DESC LIMIT 1", (name,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["aps"] = json.loads(d["ap_json"])
        return d

    # --------------------------------------------------------------- alerts

    def upsert_alert(self, event: Event) -> bool:
        """Record an alert. Returns True if this is the first time we've seen it.

        Callers use the return value to decide whether to print/emit -- that is
        the suppression boundary. Repeat hits still update last_seen and
        hit_count so an analyst can see how persistent the rogue AP is.
        """
        key = event.dedupe_key
        row = self.conn.execute(
            "SELECT hit_count FROM alerts WHERE dedupe_key = ?", (key,)
        ).fetchone()
        if row is None:
            self.conn.execute(
                """INSERT INTO alerts
                   (dedupe_key, rule_id, ssid, bssid, severity,
                    first_seen, last_seen, hit_count, event_json)
                   VALUES (?,?,?,?,?,?,?,1,?)""",
                (
                    key, event.rule_id, event.ssid, event.bssid, event.severity,
                    event.timestamp, event.timestamp, event.to_json(),
                ),
            )
            self.conn.commit()
            return True

        self.conn.execute(
            "UPDATE alerts SET last_seen = ?, hit_count = hit_count + 1, event_json = ? "
            "WHERE dedupe_key = ?",
            (event.timestamp, event.to_json(), key),
        )
        self.conn.commit()
        return False

    def list_alerts(self, limit: int = 50) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM alerts ORDER BY last_seen DESC LIMIT ?", (limit,)
            )
        )

    def clear_alerts(self) -> int:
        cur = self.conn.execute("DELETE FROM alerts")
        self.conn.commit()
        return cur.rowcount
