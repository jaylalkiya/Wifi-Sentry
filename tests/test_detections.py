import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifisentry import scanner
from wifisentry.baseline import build_rows
from wifisentry.config import Config
from wifisentry.detections import (
    RULES, DetectionEngine, auth_strength, rule_beacon_flood,
)
from wifisentry.models import Observation
from wifisentry.oui import OuiLookup, is_locally_administered

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def load(name):
    return scanner.scan_from_file(os.path.join(FIXTURES, name))


def make_baseline(scans, oui=None):
    oui = oui or OuiLookup()
    rows = build_rows(scans, oui)
    return {(r["ssid"], r["bssid"]): r for r in rows}


def obs(ssid, bssid, channel=6, signal=70, auth="WPA2-Personal", enc="CCMP"):
    return Observation(
        ssid=ssid, bssid=bssid, channel=channel, signal_percent=signal,
        authentication=auth, encryption=enc,
    )


class TestAuthStrength(unittest.TestCase):
    def test_relative_ordering(self):
        self.assertLess(auth_strength("Open"), auth_strength("WEP"))
        self.assertLess(auth_strength("WEP"), auth_strength("WPA2-Personal"))
        self.assertLess(auth_strength("WPA2-Personal"), auth_strength("WPA3-Personal"))

    def test_unknown_returns_negative_so_it_is_never_compared(self):
        self.assertEqual(auth_strength("Quantum-Encrypted"), -1)

    def test_suffixed_values_still_rank(self):
        self.assertEqual(auth_strength("WPA2-Personal (PSK)"), auth_strength("WPA2-Personal"))


class TestLocallyAdministered(unittest.TestCase):
    def test_detects_software_generated_mac(self):
        self.assertTrue(is_locally_administered("02:11:22:33:44:55"))
        self.assertTrue(is_locally_administered("06:aa:bb:cc:dd:ee"))

    def test_hardware_mac_is_global(self):
        self.assertFalse(is_locally_administered("70:bc:48:00:11:01"))

    def test_malformed_mac_is_not_flagged(self):
        self.assertFalse(is_locally_administered("nonsense"))


class TestEngineAgainstAttackFixture(unittest.TestCase):
    """The attack fixture is the demo scenario: an open evil twin of 'TrustedNet'
    from a software-generated MAC, plus one radio serving two SSIDs."""

    def setUp(self):
        self.baseline = make_baseline([load("netsh_baseline.txt")])
        self.engine = DetectionEngine(self.baseline, Config(), OuiLookup())
        self.events = self.engine.run(load("netsh_attack.txt"))
        self.fired = {e.rule_id for e in self.events}

    def test_evil_twin_fires(self):
        self.assertIn("WIFI-001", self.fired)
        e = [x for x in self.events if x.rule_id == "WIFI-001"][0]
        self.assertEqual(e.ssid, "TrustedNet")
        self.assertEqual(e.bssid, "02:11:22:33:44:55")
        self.assertEqual(e.severity, "critical")

    def test_encryption_downgrade_fires_critical_when_open(self):
        self.assertIn("WIFI-002", self.fired)
        e = [x for x in self.events if x.rule_id == "WIFI-002"][0]
        self.assertEqual(e.severity, "critical")
        self.assertEqual(e.details["baseline_auth"], "WPA2-Personal")

    def test_vendor_mismatch_flags_the_software_mac(self):
        self.assertIn("WIFI-003", self.fired)
        e = [x for x in self.events if x.rule_id == "WIFI-003"][0]
        self.assertTrue(e.details["locally_administered"])

    def test_shared_bssid_fires_for_the_karma_responder(self):
        self.assertIn("WIFI-007", self.fired)
        e = [x for x in self.events if x.rule_id == "WIFI-007"][0]
        self.assertEqual(e.details["ssids"], ["Free_Airport_WiFi", "Starbucks"])

    def test_unchanged_ap_produces_no_alert(self):
        for e in self.events:
            self.assertNotEqual(e.bssid, "50:c7:bf:11:22:33")

    def test_results_sorted_worst_first(self):
        self.assertEqual(self.events[0].severity, "critical")

    def test_every_event_carries_an_attack_technique(self):
        for e in self.events:
            self.assertTrue(e.technique.startswith("T1"))


class TestNoFalsePositivesOnCleanScan(unittest.TestCase):
    def test_rescanning_the_baseline_is_silent(self):
        scan = load("netsh_baseline.txt")
        engine = DetectionEngine(make_baseline([scan]), Config(), OuiLookup())
        self.assertEqual(engine.run(scan), [])


class TestChannelAndSignalRules(unittest.TestCase):
    def setUp(self):
        self.base = make_baseline([[obs("Net", "70:bc:48:00:00:01", channel=6, signal=70)]])

    def test_channel_change_fires(self):
        engine = DetectionEngine(self.base, Config(), OuiLookup())
        events = engine.run([obs("Net", "70:bc:48:00:00:01", channel=11, signal=70)])
        self.assertEqual([e.rule_id for e in events], ["WIFI-004"])

    def test_signal_within_tolerance_is_quiet(self):
        engine = DetectionEngine(self.base, Config(signal_delta_db=12), OuiLookup())
        # 70% -> -65 dBm baseline; 80% -> -60 dBm, a 5 dB move.
        self.assertEqual(engine.run([obs("Net", "70:bc:48:00:00:01", signal=80)]), [])

    def test_signal_beyond_tolerance_fires(self):
        engine = DetectionEngine(self.base, Config(signal_delta_db=12), OuiLookup())
        events = engine.run([obs("Net", "70:bc:48:00:00:01", signal=100)])
        self.assertEqual([e.rule_id for e in events], ["WIFI-005"])
        self.assertEqual(events[0].details["direction"], "stronger")

    def test_baseline_range_absorbs_normal_jitter(self):
        # Two sweeps 20% apart widen the range, so a mid-range reading is fine.
        wide = make_baseline([
            [obs("Net", "70:bc:48:00:00:01", signal=60)],
            [obs("Net", "70:bc:48:00:00:01", signal=90)],
        ])
        engine = DetectionEngine(wide, Config(signal_delta_db=12), OuiLookup())
        self.assertEqual(engine.run([obs("Net", "70:bc:48:00:00:01", signal=75)]), [])


class TestBeaconFlood(unittest.TestCase):
    def test_fires_above_threshold(self):
        base = make_baseline([[obs("Net", "70:bc:48:00:00:01")]])
        flood = [obs("SSID{}".format(i), "02:00:00:00:00:{:02x}".format(i))
                 for i in range(12)]
        events = rule_beacon_flood(flood, base, Config(beacon_flood_threshold=8), OuiLookup())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].details["new_ssid_count"], 12)

    def test_quiet_below_threshold(self):
        base = make_baseline([[obs("Net", "70:bc:48:00:00:01")]])
        few = [obs("SSID{}".format(i), "02:00:00:00:00:{:02x}".format(i))
               for i in range(3)]
        self.assertEqual(
            rule_beacon_flood(few, base, Config(beacon_flood_threshold=8), OuiLookup()), [])

    def test_no_baseline_means_no_flood_alert(self):
        # Everything is new before a baseline exists; alerting there is noise.
        self.assertEqual(rule_beacon_flood([obs("A", "02:00:00:00:00:01")], {},
                                           Config(), OuiLookup()), [])


class TestFalsePositiveTuning(unittest.TestCase):
    def setUp(self):
        self.base = make_baseline([load("netsh_baseline.txt")])
        self.attack = load("netsh_attack.txt")

    def test_allowlisted_bssid_is_fully_suppressed(self):
        cfg = Config(allow_bssids=["02:11:22:33:44:55"])
        events = DetectionEngine(self.base, cfg, OuiLookup()).run(self.attack)
        self.assertEqual([e for e in events if e.bssid == "02:11:22:33:44:55"], [])

    def test_ignored_ssid_is_fully_suppressed(self):
        cfg = Config(ignore_ssids=["TrustedNet"])
        events = DetectionEngine(self.base, cfg, OuiLookup()).run(self.attack)
        self.assertEqual([e for e in events if e.ssid == "TrustedNet"], [])

    def test_multi_ap_ssid_downgrades_rather_than_hides(self):
        # A mesh SSID gaining a radio should still be visible, just not paging.
        base = make_baseline([[obs("Mesh", "74:83:c2:00:00:01")]])
        cfg = Config(multi_ap_ssids=["Mesh"])
        events = DetectionEngine(base, cfg, OuiLookup()).run(
            [obs("Mesh", "74:83:c2:00:00:02")])
        twin = [e for e in events if e.rule_id == "WIFI-001"]
        self.assertEqual(len(twin), 1)
        self.assertEqual(twin[0].severity, "low")

    def test_disabled_rule_does_not_run(self):
        cfg = Config(disabled_rules=["WIFI-001", "WIFI-002", "WIFI-003"])
        fired = {e.rule_id for e in DetectionEngine(self.base, cfg, OuiLookup()).run(self.attack)}
        self.assertNotIn("WIFI-001", fired)
        self.assertNotIn("WIFI-002", fired)
        self.assertNotIn("WIFI-003", fired)

    def test_case_insensitive_matching(self):
        cfg = Config(ignore_ssids=["trustednet"], allow_bssids=["02:11:22:33:44:55"])
        self.assertTrue(cfg.is_ignored_ssid("TrustedNet"))
        self.assertTrue(cfg.is_allowed_bssid("02:11:22:33:44:55"))


class TestRuleCatalog(unittest.TestCase):
    def test_every_rule_documents_its_false_positives(self):
        for rule in RULES.values():
            self.assertTrue(rule.false_positives.strip(), rule.rule_id)
            self.assertTrue(rule.rationale.strip(), rule.rule_id)

    def test_severities_are_from_the_known_set(self):
        for rule in RULES.values():
            self.assertIn(rule.severity, ("low", "medium", "high", "critical"))


if __name__ == "__main__":
    unittest.main()
