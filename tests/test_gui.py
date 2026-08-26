"""Smoke tests for the desktop UI.

The GUI is not where detection logic lives, so these do not re-test the rules.
They check the things a UI actually breaks on: constructing every widget,
rendering rows from real data, and formatting an alert detail pane.

Skipped automatically when Tk cannot open a display (headless CI).
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import tkinter as tk
    _probe = tk.Tk()
    _probe.destroy()
    # Tk keeps a module-level pointer to the destroyed probe; ttk's later
    # theme_use() then fires ThemeChanged at it and prints a Tcl warning.
    tk._default_root = None
    TK_AVAILABLE = True
except Exception:  # no display, or Tk not compiled in
    TK_AVAILABLE = False

from wifisentry import scanner
from wifisentry.baseline import build_rows
from wifisentry.models import Event, utcnow
from wifisentry.oui import OuiLookup
from wifisentry.store import Store

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def an_event(rule_id="WIFI-001", severity="critical"):
    return Event(
        rule_id=rule_id, rule_name="Evil twin: known SSID on an unknown BSSID",
        severity=severity, technique="T1557.004", technique_name="Evil Twin",
        message="test alert", ssid="TrustedNet", bssid="02:11:22:33:44:55",
        details={"vendor": "Locally-administered/randomized",
                 "locally_administered": True},
    )


@unittest.skipUnless(TK_AVAILABLE, "Tk display unavailable")
class TestGuiSmoke(unittest.TestCase):
    def setUp(self):
        from wifisentry.gui import WifiSentryApp

        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "t.db")
        self.cfg = os.path.join(self.tmp.name, "c.json")

        # A populated store, so the UI renders real rows rather than an empty
        # shell -- an empty Treeview would hide most formatting bugs.
        scan = scanner.scan_from_file(os.path.join(FIXTURES, "netsh_baseline.txt"))
        with Store(self.db) as store:
            store.record_scan(scan)
            store.replace_baseline(build_rows([scan], OuiLookup()),
                                   {"created_at": utcnow(), "sweeps": "1"})
            store.upsert_alert(an_event())
            store.upsert_alert(an_event("WIFI-004", "medium"))

        self.root = tk.Tk()
        self.root.withdraw()
        self.app = WifiSentryApp(self.root, self.db, self.cfg, None, None)
        self.root.update_idletasks()

    def tearDown(self):
        self.root.destroy()
        tk._default_root = None  # else ttk warns at the next theme_use()
        self.tmp.cleanup()

    def test_builds_all_three_tabs(self):
        self.assertEqual(len(self.app.tabs.tabs()), 6)

    def test_alerts_render_sorted_worst_first(self):
        items = self.app.alerts_tree.get_children()
        self.assertEqual(len(items), 2)
        first = self.app.alerts_tree.item(items[0])["values"]
        self.assertEqual(first[0], "CRITICAL")

    def test_alert_rows_carry_a_severity_tag_for_colouring(self):
        item = self.app.alerts_tree.get_children()[0]
        self.assertIn("critical", self.app.alerts_tree.item(item)["tags"])

    def test_baseline_status_is_shown_and_scan_enabled(self):
        self.assertIn("BASELINE", self.app.baseline_label.cget("text"))
        self.assertEqual(str(self.app.btn_scan.cget("state")), "normal")

    def test_networks_tab_marks_unbaselined_aps_as_new(self):
        obs = scanner.scan_from_file(os.path.join(FIXTURES, "netsh_attack.txt"))
        with Store(self.db) as store:
            baseline = store.load_baseline()
        self.app._populate_networks(obs, baseline)

        rows = [self.app.net_tree.item(i) for i in self.app.net_tree.get_children()]
        self.assertEqual(len(rows), 4)
        # Column 1 is the NEW marker; the evil twin is not in the baseline.
        new = [r for r in rows if r["values"][1] == "NEW"]
        self.assertTrue(new)
        # The open evil twin should sort to the top on risk and read CRITICAL.
        self.assertIn("CRITICAL", rows[0]["values"][0])

    def test_detail_pane_includes_evidence_and_false_positives(self):
        item = self.app.alerts_tree.get_children()[0]
        text = self.app._alert_details[item]
        self.assertIn("T1557.004", text)
        self.assertIn("locally_administered", text)
        self.assertIn("Known false positives", text)

    def test_rule_toggles_exist_for_every_rule(self):
        from wifisentry.detections import RULES
        self.assertEqual(set(self.app.rule_vars), set(RULES))

    def test_saving_rules_writes_disabled_list_to_config(self):
        from wifisentry.config import Config
        self.app.rule_vars["WIFI-005"].set(False)
        self.app.on_save_rules()
        self.assertEqual(Config.load(self.cfg).disabled_rules, ["WIFI-005"])

    def test_finishing_a_baseline_fills_the_networks_tab(self):
        # Regression: baseline used to leave Networks empty, so a first-time
        # user saw a blank screen and assumed nothing had happened.
        obs = scanner.scan_from_file(os.path.join(FIXTURES, "netsh_baseline.txt"))
        with Store(self.db) as store:
            baseline = store.load_baseline()

        self.app._handle({
            "kind": "baseline", "summary": "5 access points",
            "observations": obs, "baseline": baseline,
        })

        rows = [self.app.net_tree.item(i) for i in self.app.net_tree.get_children()]
        self.assertEqual(len(rows), 5)
        # Everything just baselined is trusted, so nothing reads NEW (col 1).
        self.assertEqual([r for r in rows if r["values"][1] == "NEW"], [])
        self.assertEqual(self.app.tabs.index("current"), 1)

    def test_simulation_clones_the_users_own_network_not_fake_ones(self):
        self.app.on_toggle_demo()
        try:
            self.assertTrue(self.app.demo)
            self.assertNotEqual(self.app.db, self.app.live_db)
            # Live scanning is locked out while the simulation is on screen.
            self.assertEqual(str(self.app.btn_scan.cget("state")), "disabled")
            severities = [self.app.alerts_tree.item(i)["values"][0]
                          for i in self.app.alerts_tree.get_children()]
            self.assertIn("CRITICAL", severities)
            self.assertIn("SIMULATION", self.app.baseline_label.cget("text"))
            # The evil twin must carry a REAL baselined SSID (TrustedNet), not an
            # invented one -- that is the whole point of this change.
            twin = [self.app.alerts_tree.item(i)["values"]
                    for i in self.app.alerts_tree.get_children()
                    if self.app.alerts_tree.item(i)["values"][3] == "02:00:5e:1d:0a:11"]
            self.assertTrue(twin)
            self.assertEqual(twin[0][2], "TrustedNet")  # the seeded baseline's SSID
            self.assertEqual(self.app.tabs.index("current"), 4)
        finally:
            self.app.on_toggle_demo()

    def test_exiting_demo_restores_the_live_database(self):
        self.app.on_toggle_demo()
        self.app.on_toggle_demo()
        self.assertFalse(self.app.demo)
        self.assertEqual(self.app.db, self.app.live_db)
        self.assertEqual(str(self.app.btn_scan.cget("state")), "normal")
        # The live alert set from setUp is back, not the demo's.
        self.assertEqual(len(self.app.alerts_tree.get_children()), 2)

    def test_dashboard_counts_reflect_the_store(self):
        # 5 devices baselined, 2 alerts seeded in setUp.
        self.assertEqual(self.app.stat_cards["networks"].cget("text"), "5")
        self.assertEqual(self.app.stat_cards["alerts"].cget("text"), "2")

    def test_history_tab_lists_every_device(self):
        rows = self.app.hist_tree.get_children()
        self.assertEqual(len(rows), 5)

    def test_capture_and_compare_flags_networks_unique_to_location_b(self):
        from wifisentry.oui import OuiLookup as _O
        oui = _O()
        def aps(fixture):
            obs = scanner.scan_from_file(os.path.join(FIXTURES, fixture))
            return [{"ssid": o.ssid, "bssid": o.bssid, "vendor": oui.vendor(o.bssid),
                     "channel": o.channel, "signal_dbm": o.signal_dbm,
                     "authentication": o.authentication} for o in obs]
        with Store(self.db) as store:
            store.save_snapshot("home", aps("netsh_baseline.txt"))
            store.save_snapshot("cafe", aps("netsh_attack.txt"))
        self.app._refresh_snapshot_lists()
        self.app.cmp_a.set("home")
        self.app.cmp_b.set("cafe")
        self.app.on_compare()
        rows = [self.app.cmp_tree.item(i)["values"] for i in self.app.cmp_tree.get_children()]
        only_b = [r for r in rows if str(r[0]).startswith("ONLY IN")]
        bssids = [r[2] for r in only_b]
        self.assertIn("02:11:22:33:44:55", bssids)  # the open evil twin

    def test_network_detail_pane_shows_risk_and_fingerprint(self):
        obs = scanner.scan_from_file(os.path.join(FIXTURES, "netsh_attack.txt"))
        with Store(self.db) as store:
            baseline = store.load_baseline()
        self.app._populate_networks(obs, baseline)
        item = self.app.net_tree.get_children()[0]
        text = self.app._net_details[item]
        self.assertIn("Risk score", text)
        self.assertIn("Device type", text)
        self.assertIn("Risk factors", text)

    def test_clearing_alerts_empties_the_tree(self):
        with Store(self.db) as store:
            store.clear_alerts()
        self.app._load_alerts_from_store()
        self.assertEqual(self.app.alerts_tree.get_children(), ())


@unittest.skipUnless(TK_AVAILABLE, "Tk display unavailable")
class TestGuiWithoutBaseline(unittest.TestCase):
    def test_scan_disabled_until_a_baseline_exists(self):
        from wifisentry.gui import WifiSentryApp

        with tempfile.TemporaryDirectory() as tmp:
            root = tk.Tk()
            root.withdraw()
            try:
                app = WifiSentryApp(root, os.path.join(tmp, "t.db"),
                                    os.path.join(tmp, "c.json"), None, None)
                self.assertEqual(str(app.btn_scan.cget("state")), "disabled")
                self.assertIn("NO BASELINE", app.baseline_label.cget("text"))
            finally:
                root.destroy()
                tk._default_root = None


if __name__ == "__main__":
    unittest.main()
