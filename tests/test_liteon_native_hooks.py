"""Native peripheral effects and cache routing, with no device access."""
from pathlib import Path
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.


class NativeHooksTests(unittest.TestCase):
    def test_descrambling_survives_native_transfer_and_recovery(self):
        path = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not path.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned specimen and armips are required')
        from verify_native_hooks import verify_transfer_modes
        report = verify_transfer_modes(path.read_bytes())
        self.assertEqual(report['transfer_mode_cases'], 108)
        self.assertEqual(report['cd_leadout_gate_cases'], 8)

    def test_native_addressing_descrambling_and_read_boundaries(self):
        path = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not path.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned specimen and armips are required')
        from verify_native_hooks import verify_addressing_and_controls
        report = verify_addressing_and_controls(path.read_bytes())
        self.assertEqual(report['descrambling_cases'], 48)
        self.assertEqual(report['bd_psn_cases'], 24)
        self.assertEqual(report['native_read_check_cases'], 120)
        self.assertEqual(report['boundary_cases'], 18)

    def test_error_masks_and_cd_fua_follow_native_control_flow(self):
        path = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not path.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned specimen and armips are required')
        from verify_native_hooks import verify
        report = verify(path.read_bytes())
        self.assertEqual(report['error_mode_cases'], 480)
        self.assertEqual(len(report['cd_fua_cases']), 6)


if __name__ == '__main__':
    unittest.main()
