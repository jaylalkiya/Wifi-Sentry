"""Double-click entry point with no console window (pythonw runs .pyw files).

Kept tiny on purpose: it only fixes up the import path and hands off to the
package, so the real code stays in wifisentry/ where the tests can reach it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wifisentry.gui import launch  # noqa: E402

if __name__ == "__main__":
    launch(os.path.join(os.path.dirname(os.path.abspath(__file__)), "wifi-sentry.db"))
