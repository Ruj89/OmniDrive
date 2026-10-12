"""Execute native media hooks with explicit optical acquisition boundaries."""
from pathlib import Path
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.


class NativeMediaTests(unittest.TestCase):
    def test_native_read_timer_and_idle_speed(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not original.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned specimen and armips required')
        from verify_native_speed import verify
        report = verify(original.read_bytes())
        self.assertEqual(len(report['c0_idle_timer_cases']), 28)
        self.assertEqual(len(report['nonreading_timer_preserved']), 12)
        self.assertEqual(len(report['native_irq_ticks']), 6)
        self.assertFalse(report['physical_speed_verified'])

    def test_native_bd_di_acquisition_and_geometry(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not original.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned specimen and armips required')
        from verify_native_recognition import verify
        report = verify(original.read_bytes())
        self.assertEqual(len(report['bd_rom_di_cases']), 12)
        self.assertEqual(sum(c['accepted'] for c in report['bd_rom_di_cases']), 9)
        self.assertTrue(report['already_valid_di_preserved'])
        self.assertFalse(report['physical_recognition_verified'])

    def test_native_inquiry_template_and_host_identification(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not original.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned specimen and armips required')
        from verify_native_media import verify_identification
        report = verify_identification(original.read_bytes())
        self.assertEqual(len(report['inquiry_cases']), 7)
        self.assertEqual(report['host_signature_offset'], 74)

    def test_native_media_hooks(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not original.exists() or shutil.which('armips') is None:
            self.skipTest('Pinned specimen and armips required')
        from verify_native_media import verify
        report = verify(original.read_bytes())
        self.assertEqual(len(report['toc_cases']), 18)
        self.assertEqual(report['dvd_rom_psn_cases'], 16)
        self.assertEqual(len(report['pfi_cases']), 32)
        self.assertEqual(len(report['bd_identification_cases']), 4)
        self.assertEqual(len(report['control_data_cases']), 8)
        self.assertFalse(report['optical_acquisition_verified'])


if __name__ == '__main__':
    unittest.main()
