import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifisentry import emit
from wifisentry.cli import main
from wifisentry.config import Config
from wifisentry.models import Event, Observation
from wifisentry.store import Store

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
BASE_FIXTURE = os.path.join(FIXTURES, "netsh_baseline.txt")
ATTACK_FIXTURE = os.path.join(FIXTURES, "netsh_attack.txt")


def an_event(rule_id="WIFI-001", bssid="02:11:22:33:44:55"):
    return Event(
        rule_id=rule_id, rule_name="test", severity="critical",
        technique="T1557.004", technique_name="Evil Twin",
        message="test", ssid="TrustedNet", bssid=bssid,
    )


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "t.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_and_observations_round_trip(self):
        with Store(self.db) as s:
            scan_id = s.record_scan([
                Observation("A", "70:bc:48:00:00:01", 6, 70, "WPA2-Personal", "CCMP")
            ])
            rows = s.observations_for_scan(scan_id)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["bssid"], "70:bc:48:00:00:01")
            self.assertEqual(rows[0]["signal_dbm"], -65)
            self.assertEqual(s.scan_count(), 1)

    def test_baseline_replace_is_atomic_not_additive(self):
        row = {
            "ssid": "A", "bssid": "70:bc:48:00:00:01", "vendor": "Cisco Meraki",
            "channels": [6], "authentication": "WPA2-Personal", "encryption": "CCMP",
            "min_signal_dbm": -65, "max_signal_dbm": -60, "sample_count": 2,
            "created_at": "2026-01-01T00:00:00Z",
        }
        with Store(self.db) as s:
            s.replace_baseline([row], {"created_at": "x"})
            s.replace_baseline([row], {"created_at": "y"})
            self.assertEqual(len(s.load_baseline()), 1)
            self.assertEqual(s.baseline_meta()["created_at"], "y")

    def test_baseline_channels_survive_json_round_trip(self):
        row = {
            "ssid": "A", "bssid": "70:bc:48:00:00:01", "vendor": "v",
            "channels": [6, 11, 44], "authentication": "WPA2-Personal",
            "encryption": "CCMP", "min_signal_dbm": -70, "max_signal_dbm": -50,
            "sample_count": 3, "created_at": "2026-01-01T00:00:00Z",
        }
        with Store(self.db) as s:
            s.replace_baseline([row], {})
            loaded = s.load_baseline()[("A", "70:bc:48:00:00:01")]
            self.assertEqual(loaded["channels"], [6, 11, 44])

    def test_first_alert_is_new_repeats_are_suppressed(self):
        with Store(self.db) as s:
            self.assertTrue(s.upsert_alert(an_event()))
            self.assertFalse(s.upsert_alert(an_event()))
            self.assertFalse(s.upsert_alert(an_event()))
            row = s.list_alerts()[0]
            self.assertEqual(row["hit_count"], 3)

    def test_different_ap_is_a_different_alert(self):
        with Store(self.db) as s:
            self.assertTrue(s.upsert_alert(an_event(bssid="02:00:00:00:00:01")))
            self.assertTrue(s.upsert_alert(an_event(bssid="02:00:00:00:00:02")))
            self.assertEqual(len(s.list_alerts()), 2)

    def test_clear_alerts(self):
        with Store(self.db) as s:
            s.upsert_alert(an_event())
            self.assertEqual(s.clear_alerts(), 1)
            self.assertEqual(s.list_alerts(), [])


class TestEmit(unittest.TestCase):
    def test_jsonl_is_one_parseable_object_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out", "events.jsonl")
            emit.write_jsonl([an_event("WIFI-001"), an_event("WIFI-002")], path)
            emit.write_jsonl([an_event("WIFI-003")], path)  # appends
            with open(path, encoding="utf-8") as fh:
                lines = [json.loads(line) for line in fh if line.strip()]
        self.assertEqual([d["rule_id"] for d in lines],
                         ["WIFI-001", "WIFI-002", "WIFI-003"])
        self.assertIn("dedupe_key", lines[0])
        self.assertEqual(lines[0]["source"], "wifi-sentry")

    def test_plain_text_output_has_no_escape_codes(self):
        text = emit.format_event(an_event(), color=False)
        self.assertNotIn("\033", text)
        self.assertIn("T1557.004", text)


class TestConfig(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            Config(ignore_ssids=["X"], signal_delta_db=20).save(path)
            loaded = Config.load(path)
        self.assertEqual(loaded.ignore_ssids, ["X"])
        self.assertEqual(loaded.signal_delta_db, 20)

    def test_missing_file_yields_defaults(self):
        self.assertEqual(Config.load("does-not-exist.json").signal_delta_db, 12)

    def test_unknown_keys_are_ignored_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"signal_delta_db": 5, "future_option": True}, fh)
            self.assertEqual(Config.load(path).signal_delta_db, 5)


class TestCliEndToEnd(unittest.TestCase):
    """Drives the real CLI through --replay, so no radio is needed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "t.db")
        self.cfg = os.path.join(self.tmp.name, "c.json")
        self.jsonl = os.path.join(self.tmp.name, "events.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(list(argv))
        return code, buf.getvalue()

    def base(self, *extra):
        return ("--db", self.db, "--config", self.cfg) + extra

    def test_scan_before_baseline_fails_cleanly(self):
        code, _ = self.run_cli(*self.base("--replay", BASE_FIXTURE, "scan"))
        self.assertEqual(code, 1)

    def test_full_flow_baseline_then_clean_then_attack(self):
        code, out = self.run_cli(*self.base("--replay", BASE_FIXTURE, "baseline"))
        self.assertEqual(code, 0)
        self.assertIn("Baseline saved", out)

        code, out = self.run_cli(*self.base("--replay", BASE_FIXTURE, "scan"))
        self.assertEqual(code, 0)
        self.assertIn("No deviations", out)

        code, out = self.run_cli(
            *self.base("--replay", ATTACK_FIXTURE, "scan", "--jsonl", self.jsonl))
        self.assertEqual(code, 2)  # non-zero so a scheduler can act on it
        self.assertIn("WIFI-001", out)

        with open(self.jsonl, encoding="utf-8") as fh:
            events = [json.loads(line) for line in fh if line.strip()]
        self.assertTrue(any(e["rule_id"] == "WIFI-001" for e in events))

    def test_repeat_attack_scan_suppresses_instead_of_repeating(self):
        self.run_cli(*self.base("--replay", BASE_FIXTURE, "baseline"))
        self.run_cli(*self.base("--replay", ATTACK_FIXTURE, "scan"))
        code, out = self.run_cli(*self.base("--replay", ATTACK_FIXTURE, "scan"))
        self.assertIn("suppressed", out)
        self.assertEqual(code, 2)

    def test_baseline_refuses_to_overwrite_without_force(self):
        self.run_cli(*self.base("--replay", BASE_FIXTURE, "baseline"))
        code, _ = self.run_cli(*self.base("--replay", BASE_FIXTURE, "baseline"))
        self.assertEqual(code, 1)
        code, _ = self.run_cli(*self.base("--replay", BASE_FIXTURE, "baseline", "--force"))
        self.assertEqual(code, 0)

    def test_alerts_listing_and_clear(self):
        self.run_cli(*self.base("--replay", BASE_FIXTURE, "baseline"))
        self.run_cli(*self.base("--replay", ATTACK_FIXTURE, "scan"))
        code, out = self.run_cli(*self.base("alerts"))
        self.assertEqual(code, 0)
        self.assertIn("WIFI-001", out)
        code, out = self.run_cli(*self.base("alerts", "--clear"))
        self.assertIn("Cleared", out)

    def test_rules_command_reports_attack_coverage(self):
        code, out = self.run_cli(*self.base("rules"))
        self.assertEqual(code, 0)
        self.assertIn("T1557.004", out)
        self.assertIn("ATT&CK techniques", out)

    def test_init_config_writes_then_refuses_to_clobber(self):
        code, _ = self.run_cli(*self.base("init-config"))
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(self.cfg))
        code, _ = self.run_cli(*self.base("init-config"))
        self.assertEqual(code, 1)

    def test_config_tuning_changes_scan_outcome(self):
        self.run_cli(*self.base("--replay", BASE_FIXTURE, "baseline"))
        Config(ignore_ssids=["TrustedNet", "Free_Airport_WiFi", "Starbucks"]).save(self.cfg)
        code, out = self.run_cli(*self.base("--replay", ATTACK_FIXTURE, "scan"))
        self.assertEqual(code, 0)
        self.assertIn("No deviations", out)


if __name__ == "__main__":
    unittest.main()
