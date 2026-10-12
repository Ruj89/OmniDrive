"""MT1959 reference comparison: overlay unpacking and strongly matched sites."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.


class MT1959CompareTests(unittest.TestCase):
    def setUp(self):
        self.mt1959 = ROOT / 'dump/DE_ASUS_BW-16D1HT_3.02.bin'
        self.mt1939 = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        if not self.mt1959.exists() or not self.mt1939.exists():
            self.skipTest('Decoded BW-16D1HT 3.02 and BW-12B1LT 1.03 images required')

    def test_overlay_unpacks_to_veneer_targets(self):
        from compare_mt1959 import unpack_overlay, OVERLAY_BASE
        image = self.mt1959.read_bytes()
        overlay = unpack_overlay(image)
        self.assertEqual(len(overlay), struct.unpack_from('<I', image, 0x15c000)[0])
        # ReadDVDTOC veneer (main.asm label 0x14BFBC) enters a Thumb push.
        target = struct.unpack_from('<I', image, 0x14bfc0)[0] & ~1
        self.assertEqual(overlay[target - OVERLAY_BASE + 1], 0xb5)
        # The two runtime patch sites hold the instructions main.c rewrites.
        self.assertEqual(overlay[0x01f96daa - OVERLAY_BASE:][:2], bytes.fromhex('6ed1'))
        self.assertEqual(overlay[0x01f976c2 - OVERLAY_BASE:][:2], bytes.fromhex('0020'))

    def test_strong_matches_agree_with_reviewed_mapping(self):
        from compare_mt1959 import compare
        rows, _ = compare(self.mt1959.read_bytes(), self.mt1939.read_bytes())
        strong = [r for r in rows if r['candidates'][0][1] >= 40]
        self.assertGreaterEqual(len(strong), 6)
        for row in strong:
            self.assertIsNotNone(row['mt1939'], row['label'])
            self.assertLess(abs(row['candidates'][0][0] - row['mt1939']), 0x20, row['label'])


if __name__ == '__main__':
    unittest.main()
