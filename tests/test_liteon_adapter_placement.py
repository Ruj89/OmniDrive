"""Execute real startup and hook code at the proposed physical addresses."""
from pathlib import Path
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.


class AdapterPlacementTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not path.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned specimen and armips are required')
        self.original = path.read_bytes()

    def test_physical_startup_preserves_native_ram_and_initializes_state(self):
        from verify_adapter_placement import verify
        candidate, report = verify(self.original)
        self.assertEqual(len(candidate), len(self.original))
        self.assertTrue(report['physical_startup_verified'])
        self.assertEqual(len(report['startup_cases']), 2)
        self.assertFalse(report['flash_ready'])
        self.assertFalse(report['full_omnidrive_port'])

    def test_adapter_abi_at_physical_addresses(self):
        from verify_native_adapter import verify
        report = verify(self.original)
        self.assertEqual(report['overlay_size'], 0x200000)
        self.assertEqual(report['placement'], 'production-profile')
        self.assertTrue(report['adapter_abi_verified'])
        self.assertEqual(len(report['native_dvd_layer_cases']), 6)
        self.assertEqual(len(report['native_dvd_psn_cases']), 72)
        self.assertFalse(report['flash_ready'])


if __name__ == '__main__':
    unittest.main()
