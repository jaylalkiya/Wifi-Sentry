import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wifisentry import scanner
from wifisentry.models import signal_percent_to_dbm

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
BASELINE_FIXTURE = os.path.join(FIXTURES, "netsh_baseline.txt")


class TestMacNormalization(unittest.TestCase):
    def test_accepts_common_separators(self):
        for raw in ("70:BC:48:00:11:01", "70-bc-48-00-11-01", "70bc.4800.1101"):
            self.assertEqual(scanner.normalize_mac(raw), "70:bc:48:00:11:01")

    def test_rejects_wrong_length(self):
        self.assertEqual(scanner.normalize_mac("70:bc:48"), "")
        self.assertEqual(scanner.normalize_mac(""), "")


class TestParser(unittest.TestCase):
    def setUp(self):
        with open(BASELINE_FIXTURE, encoding="utf-8") as fh:
            self.text = fh.read()
        self.obs = scanner.parse_netsh_output(self.text)

    def test_one_observation_per_bssid_not_per_ssid(self):
        # TrustedNet has two radios; a per-SSID parser would collapse them and the
        # evil-twin rule would have nothing to compare against.
        self.assertEqual(len(self.obs), 5)

    def test_ssid_level_fields_apply_to_each_bssid(self):
        trustednet = [o for o in self.obs if o.ssid == "TrustedNet"]
        self.assertEqual(len(trustednet), 2)
        for o in trustednet:
            self.assertEqual(o.authentication, "WPA2-Personal")
            self.assertEqual(o.encryption, "CCMP")

    def test_bssid_level_fields_are_not_shared(self):
        by_bssid = {o.bssid: o for o in self.obs}
        self.assertEqual(by_bssid["70:bc:48:00:11:01"].channel, 44)
        self.assertEqual(by_bssid["70:bc:48:00:11:02"].channel, 6)
        self.assertEqual(by_bssid["70:bc:48:00:11:01"].signal_percent, 92)
        self.assertEqual(by_bssid["70:bc:48:00:11:02"].signal_percent, 78)

    def test_hidden_ssid_is_kept_with_empty_name(self):
        hidden = [o for o in self.obs if o.is_hidden]
        self.assertEqual(len(hidden), 1)
        self.assertEqual(hidden[0].bssid, "2c:30:33:aa:bb:cc")

    def test_open_network_detected(self):
        cafe = [o for o in self.obs if o.ssid == "Cafe-Guest"][0]
        self.assertTrue(cafe.is_open)

    def test_band_and_radio_type_parsed(self):
        o = [x for x in self.obs if x.bssid == "50:c7:bf:11:22:33"][0]
        self.assertEqual(o.band, "5 GHz")
        self.assertEqual(o.radio_type, "802.11ax")

    def test_interface_name(self):
        self.assertEqual(scanner.get_interface_name(self.text), "Wi-Fi")

    def test_empty_input_is_not_an_error(self):
        self.assertEqual(scanner.parse_netsh_output(""), [])

    def test_garbage_input_is_ignored(self):
        self.assertEqual(scanner.parse_netsh_output("hello\nworld: yes\n"), [])

    def test_scan_from_file(self):
        self.assertEqual(len(scanner.scan_from_file(BASELINE_FIXTURE)), 5)


class TestForcedSweep(unittest.TestCase):
    """WlanScan is what stops netsh handing back a stale cached list."""

    def test_request_scan_is_safe_to_call_anywhere(self):
        # Returns a count on Windows, 0 elsewhere; must never raise, because
        # a failed sweep request degrades to the cached list rather than
        # breaking the scan entirely.
        count = scanner.request_scan()
        self.assertIsInstance(count, int)
        self.assertGreaterEqual(count, 0)

    def test_scan_forces_a_sweep_by_default(self):
        calls = {"scan": 0, "slept": 0}
        real_request, real_sleep, real_netsh = (
            scanner.request_scan, scanner.time.sleep, scanner.run_netsh)
        scanner.request_scan = lambda: 1
        scanner.time.sleep = lambda s: calls.__setitem__("slept", s)
        scanner.run_netsh = lambda iface=None: ""
        try:
            scanner.scan()
            self.assertEqual(calls["slept"], scanner.SCAN_SETTLE_SECONDS)
            calls["slept"] = 0
            scanner.scan(force=False)
            self.assertEqual(calls["slept"], 0)
        finally:
            scanner.request_scan, scanner.time.sleep, scanner.run_netsh = (
                real_request, real_sleep, real_netsh)

    def test_no_settle_wait_when_no_interface_accepts_the_request(self):
        real_request, real_sleep, real_netsh = (
            scanner.request_scan, scanner.time.sleep, scanner.run_netsh)
        slept = []
        scanner.request_scan = lambda: 0       # e.g. radio off, or not Windows
        scanner.time.sleep = lambda s: slept.append(s)
        scanner.run_netsh = lambda iface=None: ""
        try:
            scanner.scan()
            self.assertEqual(slept, [])
        finally:
            scanner.request_scan, scanner.time.sleep, scanner.run_netsh = (
                real_request, real_sleep, real_netsh)


class TestSignalConversion(unittest.TestCase):
    def test_endpoints_and_monotonicity(self):
        self.assertEqual(signal_percent_to_dbm(100), -50)
        self.assertEqual(signal_percent_to_dbm(0), -100)
        self.assertLess(signal_percent_to_dbm(30), signal_percent_to_dbm(90))


if __name__ == "__main__":
    unittest.main()
