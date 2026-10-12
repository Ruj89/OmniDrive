"""Do not confuse a valid minimal image with a functioning OmniDrive port."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
import audit_integrity
import verify_port_baseline


class PortBaselineTests(unittest.TestCase):
    def test_unknown_images_cannot_be_certified(self):
        with self.assertRaisesRegex(ValueError, 'cannot certify a new port'):
            verify_port_baseline.verify(bytes(0x200000), bytes(0x200000))

    def test_generated_patch_still_lacks_c0_and_raw_mode_hooks(self):
        path = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not path.exists():
            self.skipTest('Local research specimen is not distributed')
        original = path.read_bytes()
        modified, _ = audit_integrity.build(original)
        report = verify_port_baseline.verify(original, modified)
        self.assertFalse(report['full_omnidrive_port'])
        self.assertEqual(report['changed_offsets'], [0x9cb76, 0x1cfffa])
        self.assertEqual(len(report['c0_dispatch']), 12)
        self.assertTrue(all(case['sense'] == [5, 0x20, 0] for case in report['c0_dispatch']))
        self.assertEqual(len(report['native_read_mode']), 36)
        for case in report['native_read_mode']:
            self.assertEqual(case['final_format'] & 255, 0x10)
            self.assertNotEqual(case['initial_format'], case['final_format'])


if __name__ == '__main__':
    unittest.main()
