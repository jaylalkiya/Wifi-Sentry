"""Tests for the phase-2 analysis modules: distance, fingerprint, risk,
history, and location compare. All pure logic -- no radio, no display."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifisentry import distance
from wifisentry.analyze import enrich_all
from wifisentry.baseline import build_rows
from wifisentry.compare import diff_snapshots
from wifisentry.fingerprint import fingerprint
from wifisentry.models import Observation, utcnow
from wifisentry.oui import OuiLookup
from wifisentry.risk import score_observation
from wifisentry.store import Store


def obs(ssid, bssid, signal=70, auth="WPA2-Personal", enc="CCMP", channel=6):
    return Observation(ssid, bssid, channel, signal, auth, enc)


class TestDistance(unittest.TestCase):
    def test_stronger_signal_means_closer(self):
        self.assertLess(distance.estimate_distance_m(-45),
                        distance.estimate_distance_m(-80))

    def test_proximity_buckets_are_ordered(self):
        self.assertEqual(distance.proximity_label(-45), "IN THE ROOM")
        self.assertEqual(distance.proximity_label(-90), "DISTANT")

    def test_bars_are_clamped(self):
        self.assertEqual(len(distance.bars(100)), 5)
        self.assertEqual(len(distance.bars(0)), 5)
        self.assertEqual(distance.bars(100).count("█"), 5)


class TestFingerprint(unittest.TestCase):
    def setUp(self):
        self.oui = OuiLookup()

    def test_known_vendor_is_a_router(self):
        f = fingerprint(obs("Home", "50:c7:bf:11:22:33"), self.oui)  # TP-Link
        self.assertEqual(f.device_type, "Router / access point")

    def test_locally_administered_is_phone_or_software(self):
        f = fingerprint(obs("SentryLab", "0a:30:bb:3c:7b:f7", auth="Open"), self.oui)
        self.assertIn("Phone", f.device_type)

    def test_raspberry_pi_is_flagged_as_possible_rogue(self):
        f = fingerprint(obs("Free_WiFi", "b8:27:eb:99:88:77", auth="Open"), self.oui)
        self.assertIn("rogue", f.device_type.lower())

    def test_ssid_keywords_detect_a_camera_even_with_underscores(self):
        f = fingerprint(obs("Tapo_Cam_A1", "aa:bb:cc:dd:ee:ff"), self.oui)
        self.assertEqual(f.device_type, "IoT camera")

    def test_printer_keyword(self):
        f = fingerprint(obs("HP-Print-42-LaserJet", "aa:bb:cc:11:22:33"), self.oui)
        self.assertEqual(f.device_type, "Printer")


class TestRisk(unittest.TestCase):
    def setUp(self):
        self.oui = OuiLookup()

    def test_open_new_known_ssid_scores_critical(self):
        r = score_observation(
            obs("TrustedNet", "02:11:22:33:44:55", signal=98, auth="Open", enc="None"),
            self.oui, in_baseline=False, known_ssid=True)
        self.assertGreaterEqual(r.score, 75)
        self.assertEqual(r.band, "CRITICAL")

    def test_baselined_encrypted_ap_scores_low(self):
        r = score_observation(obs("Home", "50:c7:bf:11:22:33"), self.oui,
                              in_baseline=True, known_ssid=True)
        self.assertLess(r.score, 25)
        self.assertEqual(r.band, "LOW")

    def test_score_is_capped_at_100(self):
        r = score_observation(
            obs("TrustedNet", "02:11:22:33:44:55", signal=99, auth="Open", enc="None"),
            self.oui, in_baseline=False, known_ssid=True)
        self.assertLessEqual(r.score, 100)

    def test_every_score_ships_its_factors(self):
        r = score_observation(obs("X", "70:bc:48:00:00:01"), self.oui)
        self.assertTrue(r.factors)


class TestEnrichAll(unittest.TestCase):
    def test_highest_risk_sorts_first(self):
        oui = OuiLookup()
        baseline_scan = [obs("TrustedNet", "70:bc:48:00:11:01")]
        baseline = {(r["ssid"], r["bssid"]): r
                    for r in build_rows([baseline_scan], oui)}
        current = [
            obs("TrustedNet", "70:bc:48:00:11:01"),                       # known, safe
            obs("TrustedNet", "02:11:22:33:44:55", signal=98, auth="Open", enc="None"),
        ]
        enriched = enrich_all(current, oui, baseline)
        self.assertEqual(enriched[0].obs.bssid, "02:11:22:33:44:55")
        self.assertTrue(enriched[0].is_new)
        self.assertFalse(enriched[-1].is_new)


class TestHistoryAndCompare(unittest.TestCase):
    def test_device_history_aggregates_across_scans(self):
        with tempfile.TemporaryDirectory() as tmp:
            with Store(os.path.join(tmp, "h.db")) as store:
                store.record_scan([obs("A", "70:bc:48:00:00:01")])
                store.record_scan([obs("A", "70:bc:48:00:00:01"),
                                   obs("B", "50:c7:bf:00:00:02")])
                hist = store.device_history()
        by_bssid = {h["bssid"]: h for h in hist}
        self.assertEqual(by_bssid["70:bc:48:00:00:01"]["sightings"], 2)
        self.assertEqual(by_bssid["50:c7:bf:00:00:02"]["sightings"], 1)

    def test_new_devices_since_uses_all_time_first_seen(self):
        with tempfile.TemporaryDirectory() as tmp:
            with Store(os.path.join(tmp, "h.db")) as store:
                store.record_scan([obs("A", "70:bc:48:00:00:01")])
                # Everything so far is "new" relative to the epoch.
                self.assertEqual(len(store.new_devices_since("2000-01-01T00:00:00Z")), 1)
                # ...and nothing is new relative to a future cutoff.
                self.assertEqual(len(store.new_devices_since("2999-01-01T00:00:00Z")), 0)

    def test_snapshot_round_trip_and_diff_by_bssid(self):
        with tempfile.TemporaryDirectory() as tmp:
            with Store(os.path.join(tmp, "s.db")) as store:
                store.save_snapshot("home", [{"bssid": "aa", "ssid": "Home"}])
                store.save_snapshot("cafe", [{"bssid": "aa", "ssid": "Home"},
                                             {"bssid": "bb", "ssid": "CafeGuest"}])
                home = store.latest_snapshot("home")["aps"]
                cafe = store.latest_snapshot("cafe")["aps"]
        diff = diff_snapshots(home, cafe)
        self.assertEqual([a["bssid"] for a in diff.only_in_b], ["bb"])
        self.assertEqual([a["bssid"] for a in diff.in_both], ["aa"])

    def test_evil_twin_is_not_hidden_as_shared_when_bssid_differs(self):
        # Same SSID, different BSSID -- an SSID-keyed diff would wrongly call
        # this "shared". BSSID keying keeps the impostor visible.
        home = [{"bssid": "aa", "ssid": "TrustedNet"}]
        cafe = [{"bssid": "zz", "ssid": "TrustedNet"}]
        diff = diff_snapshots(home, cafe)
        self.assertEqual([a["bssid"] for a in diff.only_in_b], ["zz"])
        self.assertEqual(diff.in_both, [])


if __name__ == "__main__":
    unittest.main()
