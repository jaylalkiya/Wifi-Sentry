"""Test the in-app 'Wipe all data' action.

Kept separate from test_gui so it can run without spinning the full app for
every case. Skipped when Tk has no display.
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
    tk._default_root = None
    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False

from wifisentry import scanner
from wifisentry.baseline import build_rows
from wifisentry.oui import OuiLookup
from wifisentry.models import utcnow
from wifisentry.store import Store

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


@unittest.skipUnless(TK_AVAILABLE, "Tk display unavailable")
class TestWipeData(unittest.TestCase):
    def setUp(self):
        from wifisentry.gui import WifiSentryApp

        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "t.db")
        scan = scanner.scan_from_file(os.path.join(FIXTURES, "netsh_baseline.txt"))
        with Store(self.db) as store:
            store.record_scan(scan)
            store.replace_baseline(build_rows([scan], OuiLookup()),
                                   {"created_at": utcnow(), "sweeps": "1"})
            store.save_snapshot("home", [{"bssid": "aa", "ssid": "Home"}])
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = WifiSentryApp(self.root, self.db, os.path.join(self.tmp.name, "c.json"),
                                 None, None)
        # Auto-confirm the destructive dialog for the test.
        import wifisentry.gui as guimod
        self._orig_yesno = guimod.messagebox.askyesno
        guimod.messagebox.askyesno = lambda *a, **k: True

    def tearDown(self):
        import wifisentry.gui as guimod
        guimod.messagebox.askyesno = self._orig_yesno
        self.root.destroy()
        tk._default_root = None
        self.tmp.cleanup()

    def test_wipe_removes_all_stored_data_but_keeps_app_working(self):
        self.app.on_wipe_data()

        # A fresh, empty database exists again -- app still functional.
        with Store(self.db) as store:
            self.assertFalse(store.has_baseline())
            self.assertEqual(store.device_history(), [])
            self.assertEqual(store.list_alerts(), [])
            self.assertEqual(store.list_snapshots(), [])

        # UI reflects the empty state: scanning is disabled until a new baseline.
        self.assertEqual(str(self.app.btn_scan.cget("state")), "disabled")
        self.assertIn("NO BASELINE", self.app.baseline_label.cget("text"))
        self.assertEqual(self.app.hist_tree.get_children(), ())

    def test_wipe_is_blocked_during_a_simulation(self):
        self.app.on_toggle_demo()   # enter simulation (throwaway db)
        try:
            self.app.on_wipe_data()  # should refuse, not touch live_db
            with Store(self.live_db_path()) as store:
                self.assertTrue(store.has_baseline())  # live data untouched
        finally:
            self.app.on_toggle_demo()

    def live_db_path(self):
        return self.app.live_db


if __name__ == "__main__":
    unittest.main()
