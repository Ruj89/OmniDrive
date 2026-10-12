"""NOR semantics and native preservation/retry evidence; no device access."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/liteon'))
import liteon_paths  # noqa: F401  Puts every tool category on sys.path.
import verify_programmer as writer


class NorTests(unittest.TestCase):
    def test_unaligned_block_erase_covers_profile_and_preserves_neighbors(self):
        nor = writer.Nor(bytes(writer.FLASH_SIZE), 0xc22015)
        nor.transact(b'\x06', 0, 0)
        nor.transact(bytes.fromhex('d8 1d f0 00'), 0, 0)
        self.assertEqual(nor.data[0x1cffff], 0)
        self.assertEqual(nor.data[0x1d0000:0x1e0000], b'\xff' * 0x10000)
        self.assertEqual(nor.data[0x1e0000], 0)
        self.assertFalse(nor.wel)

    def test_program_cannot_restore_zero_bits_without_erase(self):
        nor = writer.Nor(bytes(writer.FLASH_SIZE), 0xc22015)
        nor.transact(b'\x06', 0, 0)
        nor.transact(bytes.fromhex('02 01 00 00 ff'), 0, 0)
        self.assertEqual(nor.transact(bytes.fromhex('0b 01 00 00 ff'), 1, 0), b'\x00')

    def test_write_enable_page_boundaries_and_unknown_commands(self):
        nor = writer.Nor(b'\xff' * writer.FLASH_SIZE, 0xc22015)
        with self.assertRaisesRegex(ValueError, 'WREN'):
            nor.transact(bytes.fromhex('d8 00 00 00'), 0, 0)
        nor.transact(b'\x06', 0, 0)
        with self.assertRaisesRegex(ValueError, 'page'):
            nor.transact(bytes.fromhex('02 00 00 ff 12 34'), 0, 0)
        with self.assertRaisesRegex(ValueError, 'outside'):
            nor.transact(bytes.fromhex('d8 20 00 00'), 0, 0)
        with self.assertRaisesRegex(ValueError, 'Unmodeled'):
            nor.transact(b'\xc7', 0, 0)


class NativeProgrammerTests(unittest.TestCase):
    def test_rejects_unknown_input(self):
        with self.assertRaisesRegex(ValueError, 'pinned original'):
            writer.verify(b'', b'', b'', b'')
        with self.assertRaisesRegex(ValueError, 'Unexpected imported programmer'):
            writer.run(b'', b'', b'', 0xc22015, 0x80)

    def test_original_patch_preservation_faults_and_interruption(self):
        original = ROOT / 'firmware/ASUS_BW-12B1LT_1.03.bin'
        inquiry = ROOT / 'dump/report.json'
        utility = Path(os.environ.get('LITEON_TEST_UTILITY', '/tmp/omnidrive-Flash_Utility.exe'))
        if not all(p.exists() for p in (original, inquiry, utility)):
            self.skipTest('Pinned local research inputs unavailable')
        if not all(importlib.util.find_spec(m) for m in ('unicorn', 'Crypto', 'pefile')):
            self.skipTest('Native-emulation dependencies unavailable')
        image = original.read_bytes()
        result = writer.verify(image, writer.build(image)[0], bytes.fromhex(
            json.loads(inquiry.read_text())['extended_inquiry_hex']), utility.read_bytes())
        self.assertEqual(len(result['cases']), 13)
        for case in result['cases'][:8]:
            self.assertTrue(case['native_return_reached'])
            self.assertTrue(case['final_array_matches_expected'])
            regions = {r['name']: r for r in case['regions']}
            self.assertEqual(regions['boot']['erase_touched_bytes'],
                             0 if case['control'] == 0x80 else 0x10000)
            for name in ('reserved_1', 'reserved_2'):
                self.assertEqual(regions[name]['erase_touched_bytes'], 0)
                self.assertEqual(regions[name]['program_touched_bytes'], 0)
        persistent = result['cases'][9]
        self.assertTrue(persistent['native_return_reached'])
        self.assertFalse(persistent['final_array_matches_expected'])
        self.assertGreater(persistent['changed_bytes_from_expected'], 0)
        self.assertEqual(persistent['native_readback_mismatches'], 4)
        for case in result['cases'][-2:]:
            self.assertTrue(case['interrupted'])
            self.assertFalse(case['regions'][2]['matches_original'])
        self.assertTrue(result['offline_programmer_audit_passed'])
        self.assertFalse(result['hardware_tested'])
        self.assertFalse(result['flash_ready'])


if __name__ == '__main__':
    unittest.main()
